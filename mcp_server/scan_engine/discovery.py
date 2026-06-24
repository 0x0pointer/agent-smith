"""
Active discovery enrichment for the spider scan path.

The container spider only scrapes ``<a href>`` / ``<form action>`` / turbo-frame
``src`` from the rendered DOM. It does NOT parse API specs, mine JS bundles for
routes, or read form fields — so the coverage matrix was left entirely dependent
on the model manually registering every endpoint with its params. A
less-disciplined model skips that: it registers a handful of stub endpoints with
empty params and dives straight into ad-hoc exploitation, so the matrix never
reflects the real attack surface (observed: 13 stub endpoints / 117 cells while a
39-operation OpenAPI spec and every tested API route went unregistered).

This module closes the gap host-side. After a spider run we:
  1. fetch + parse any OpenAPI 3.x / Swagger 2.0 spec → one endpoint per operation
     WITH its params (query/path/header/body), typed from the schema;
  2. mine linked JS bundles for ``fetch()`` / ``axios`` / API-route strings;
  3. read ``<form>`` fields into body params;
  4. AUTO-REGISTER the whole inventory into the coverage matrix.

The spider's job shifts from "here are some URLs, please register them" to "here
is a registered endpoint inventory to test." The pure parsers (``parse_openapi`` /
``extract_form_endpoints`` / ``extract_js_routes``) are I/O-free and unit-tested;
``discover_and_register`` does the bounded, concurrent fetching and calls
``core.coverage.add_endpoint`` (which dedups). Everything is fail-soft —
enrichment never breaks the spider result.
"""
from __future__ import annotations

import asyncio
import json
import re
from urllib.parse import urljoin, urlparse

# ── bounds (enrichment must stay cheap relative to the spider itself) ──────────
_MAX_OPS = 500          # cap operations expanded from one spec
_MAX_JS_FILES = 6       # JS bundles to mine
_MAX_HTML_PAGES = 15    # HTML pages to read forms from
_MAX_FETCH_BYTES = 5 * 1024 * 1024
_FETCH_TIMEOUT = 8      # per-fetch seconds

_STATIC_EXTS = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".pdf", ".zip",
}

# Common locations a spec lives at when it isn't linked from the DOM.
_SPEC_CANDIDATES = [
    "/openapi.json", "/swagger.json", "/swagger/v1/swagger.json",
    "/v3/api-docs", "/api-docs", "/api/openapi.json", "/static/openapi.json",
    "/api/swagger.json", "/docs/openapi.json", "/openapi/v1.json",
]

_HTTP_METHODS = {"get", "post", "put", "delete", "patch"}


# ── pure parsers ──────────────────────────────────────────────────────────────

def _hint(schema: dict | None) -> str:
    """Map a JSON-schema type to the coverage value_hint vocabulary."""
    t = (schema or {}).get("type", "") if isinstance(schema, dict) else ""
    return "integer" if t in ("integer", "number") else "string"


def _openapi3_params(operation: dict, path_level: list) -> list[dict]:
    params: list[dict] = []
    loc_map = {"query": "query", "path": "path", "header": "header", "cookie": "cookie"}
    for p in list(path_level) + list(operation.get("parameters") or []):
        if not isinstance(p, dict):
            continue
        name = p.get("name", "")
        ptype = loc_map.get(p.get("in", ""))
        if name and ptype:
            params.append({"name": name, "type": ptype, "value_hint": _hint(p.get("schema"))})
    body = operation.get("requestBody") or {}
    content = body.get("content") or {} if isinstance(body, dict) else {}
    for ctype, media in content.items():
        if not isinstance(media, dict):
            continue
        props = (media.get("schema") or {}).get("properties") or {}
        ptype = "body_form" if ("form" in ctype or "urlencoded" in ctype) else "body_json"
        for pname, pschema in props.items():
            params.append({"name": pname, "type": ptype, "value_hint": _hint(pschema)})
    return params


def _swagger2_params(operation: dict, path_level: list) -> list[dict]:
    params: list[dict] = []
    loc_map = {"query": "query", "path": "path", "header": "header", "formData": "body_form"}
    for p in list(path_level) + list(operation.get("parameters") or []):
        if not isinstance(p, dict):
            continue
        if p.get("in") == "body":
            props = (p.get("schema") or {}).get("properties") or {}
            for pname, pschema in props.items():
                params.append({"name": pname, "type": "body_json", "value_hint": _hint(pschema)})
            continue
        name = p.get("name", "")
        ptype = loc_map.get(p.get("in", ""))
        if name and ptype:
            params.append({"name": name, "type": ptype, "value_hint": _hint(p)})
    return params


def parse_openapi(spec: dict) -> list[dict]:
    """Expand an OpenAPI 3.x or Swagger 2.0 spec into endpoint dicts.

    Returns ``[{"path", "method", "params", "discovered_by": "openapi-spec"}]`` —
    one entry per operation, with params typed from the spec's ``parameters`` and
    ``requestBody`` (OpenAPI 3) / ``parameters[in=body|formData]`` (Swagger 2).
    """
    if not isinstance(spec, dict):
        return []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []
    is_v2 = str(spec.get("swagger", "")).startswith("2")
    base = (spec.get("basePath", "") or "").rstrip("/") if is_v2 else ""
    out: list[dict] = []
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        path_level = item.get("parameters") or []
        for method, op in item.items():
            if method.lower() not in _HTTP_METHODS or not isinstance(op, dict):
                continue
            params = _swagger2_params(op, path_level) if is_v2 else _openapi3_params(op, path_level)
            out.append({
                "path": (base + path) if base else path,
                "method": method.upper(),
                "params": params,
                "discovered_by": "openapi-spec",
            })
            if len(out) >= _MAX_OPS:
                return out
    return out


_FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
_INPUT_RE = re.compile(r"<(?:input|select|textarea)\b([^>]*)>", re.I)


def _attr(blob: str, name: str) -> str | None:
    m = re.search(rf"{name}\s*=\s*['\"]([^'\"]*)['\"]", blob, re.I)
    return m.group(1) if m else None


def extract_form_endpoints(html: str, page_url: str) -> list[dict]:
    """Parse ``<form>`` blocks into endpoints with their input fields as params."""
    out: list[dict] = []
    for attrs, inner in _FORM_RE.findall(html or ""):
        method = (_attr(attrs, "method") or "GET").upper()
        if method not in ("GET", "POST", "PUT", "DELETE", "PATCH"):
            method = "POST"
        action = _attr(attrs, "action") or page_url
        ptype = "query" if method == "GET" else "body_form"
        params, seen = [], set()
        for tag in _INPUT_RE.findall(inner):
            name = _attr(tag, "name")
            if not name or name in seen:
                continue
            itype = (_attr(tag, "type") or "text").lower()
            if itype in ("submit", "button", "reset", "image", "hidden"):
                continue
            seen.add(name)
            params.append({"name": name, "type": ptype,
                           "value_hint": "integer" if itype == "number" else "string"})
        try:
            path = urlparse(urljoin(page_url, action)).path or "/"
        except Exception:
            path = action or "/"
        out.append({"path": path, "method": method, "params": params, "discovered_by": "form"})
    return out


_JS_PATTERNS = [
    re.compile(r"""fetch\(\s*['"`]([^'"`]+)['"`]""", re.I),
    re.compile(r"""axios\s*\.\s*(?:get|post|put|delete|patch)\(\s*['"`]([^'"`]+)['"`]""", re.I),
    re.compile(r"""(?:\burl\b|\bendpoint\b|\bpath\b)\s*:\s*['"`](/[^'"`]+)['"`]""", re.I),
    re.compile(r"""['"`](/(?:api|v\d+|rest|graphql|internal|admin)/[^'"`?\s]+)['"`]""", re.I),
]


def extract_js_routes(js_text: str) -> list[str]:
    """Mine a JS bundle for API route strings (fetch/axios/url:/api-path literals)."""
    found: set[str] = set()
    for pat in _JS_PATTERNS:
        for raw in pat.findall(js_text or ""):
            route = raw.split("${", 1)[0].split("?", 1)[0].split("#", 1)[0].strip()
            if not route.startswith("/") or not (2 <= len(route) <= 200):
                continue
            last = route.rsplit("/", 1)[-1]
            ext = "." + last.rsplit(".", 1)[-1].lower() if "." in last else ""
            if ext in _STATIC_EXTS:
                continue
            found.add(route)
    return sorted(found)


# ── fetching + orchestration ──────────────────────────────────────────────────

def _is_static(url: str) -> bool:
    path = urlparse(url).path
    last = path.rsplit("/", 1)[-1]
    ext = "." + last.rsplit(".", 1)[-1].lower() if "." in last else ""
    return ext in _STATIC_EXTS


def _spider_endpoints(urls: list[str]) -> list[dict]:
    """Dynamic (non-asset) endpoints from raw spider URLs, with query/path params."""
    from urllib.parse import parse_qs
    seen: set[str] = set()
    out: list[dict] = []
    for url in urls:
        if _is_static(url):
            continue
        parsed = urlparse(url)
        path = parsed.path.rstrip("/") or "/"
        norm = re.sub(r"/\d+", "/{id}", path)
        if norm in seen:
            continue
        seen.add(norm)
        params = [{"name": n, "type": "query", "value_hint": "string"}
                  for n in parse_qs(parsed.query) if not n.startswith("__")]
        params += [{"name": f"id_{i}", "type": "path", "value_hint": "integer"}
                   for i, seg in enumerate(path.split("/")) if seg.isdigit()]
        out.append({"path": path, "method": "GET", "params": params, "discovered_by": "spider"})
    return out


async def _fetch(url: str) -> tuple[int, str]:
    import aiohttp
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=_FETCH_TIMEOUT),
                ssl=False, allow_redirects=True,
            ) as resp:
                body = await resp.content.read(_MAX_FETCH_BYTES)
                return resp.status, body.decode("utf-8", "replace")
    except Exception:
        return 0, ""


def _parse_spec_text(text: str) -> dict | None:
    """Return a spec dict if text is a valid OpenAPI/Swagger JSON document."""
    try:
        d = json.loads(text)
    except Exception:
        return None
    if isinstance(d, dict) and isinstance(d.get("paths"), dict) and (d.get("openapi") or d.get("swagger")):
        return d
    return None


async def discover_and_register(target: str, spider_urls: list[str], auth_context: str = "none") -> dict:
    """Enrich spider output with spec/JS/form discovery and auto-register everything.

    Returns ``{"registered", "cells", "by_source", "spec_found", "inventory"}``.
    Fail-soft: any fetch/parse error is swallowed; partial results still register.
    """
    from core.coverage import add_endpoint

    parsed_t = urlparse(target)
    base = f"{parsed_t.scheme}://{parsed_t.netloc}"
    inventory: list[dict] = list(_spider_endpoints(spider_urls))

    # 1. OpenAPI / Swagger spec — spider-found spec URLs first, then common probes.
    spec_urls, seen = [], set()
    for u in spider_urls:
        if re.search(r"(openapi|swagger|api-docs)", u, re.I) and u not in seen:
            seen.add(u); spec_urls.append(u)
    for c in _SPEC_CANDIDATES:
        cu = urljoin(base, c)
        if cu not in seen:
            seen.add(cu); spec_urls.append(cu)
    spec_found = False
    spec_results = await asyncio.gather(*(_fetch(u) for u in spec_urls[:16]), return_exceptions=True)
    for res in spec_results:
        if isinstance(res, tuple):
            spec = _parse_spec_text(res[1])
            if spec:
                inventory += parse_openapi(spec)
                spec_found = True
                break

    # 2. JS bundles → mined routes.
    js_urls = [u for u in spider_urls if u.lower().split("?", 1)[0].endswith(".js")][:_MAX_JS_FILES]
    for res in await asyncio.gather(*(_fetch(u) for u in js_urls), return_exceptions=True):
        if isinstance(res, tuple) and res[0] and res[1]:
            inventory += [{"path": r, "method": "GET", "params": [], "discovered_by": "js-bundle"}
                          for r in extract_js_routes(res[1])]

    # 3. HTML forms → body params.
    html_urls = [u for u in spider_urls if not _is_static(u)][:_MAX_HTML_PAGES]
    html_results = await asyncio.gather(*(_fetch(u) for u in html_urls), return_exceptions=True)
    for url, res in zip(html_urls, html_results):
        if isinstance(res, tuple) and res[0] and "<form" in res[1].lower():
            inventory += extract_form_endpoints(res[1], url)

    # 4. Register the whole inventory (add_endpoint dedups on normalized path+method).
    registered = cells = 0
    by_source: dict[str, int] = {}
    for ep in inventory:
        try:
            r = await add_endpoint(ep["path"], ep["method"], ep.get("params", []),
                                   ep.get("discovered_by", "spider"), auth_context)
        except Exception:
            continue
        if not r.get("dedup"):
            registered += 1
            cells += r.get("new_cells", 0)
            src = ep.get("discovered_by", "spider")
            by_source[src] = by_source.get(src, 0) + 1
    return {"registered": registered, "cells": cells, "by_source": by_source,
            "spec_found": spec_found, "inventory": len(inventory)}
