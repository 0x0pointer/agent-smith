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
import contextvars
import json
import re
from urllib.parse import urljoin, urlparse

# SP-1: auth for the discovery re-fetch. The spider crawls WITH the operator's
# session (cookies/token), but this layer's re-fetches (spec, JS, forms, live-
# probe) previously ran anonymous — so on an auth-gated app they hit login walls
# and the matrix collapsed to the public surface. discover_and_register() sets
# this for the duration of a run; _fetch() attaches it. A ContextVar keeps it
# async-safe (no signature churn across the 4 discovery helpers, no cross-run
# bleed between concurrent spiders).
_DISCOVERY_AUTH: contextvars.ContextVar = contextvars.ContextVar("discovery_auth", default=None)

# ── bounds (enrichment must stay cheap relative to the spider itself) ──────────
_MAX_OPS = 500          # cap operations expanded from one spec
_MAX_JS_FILES = 6       # JS bundles to mine
_MAX_HTML_PAGES = 15    # HTML pages to read forms from
_MAX_FETCH_BYTES = 5 * 1024 * 1024
_FETCH_TIMEOUT = 8      # per-fetch seconds
_MAX_VERIFY = 80        # cap liveness probes before registration

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


def _named_params(entries: list, loc_map: dict) -> list[dict]:
    """Map non-body OpenAPI/Swagger parameter entries to typed params.

    ``_hint`` reads the type from ``schema`` (OpenAPI 3) or the entry itself
    (Swagger 2 puts ``type`` on the parameter), so this serves both specs.
    """
    out: list[dict] = []
    for p in entries:
        if not isinstance(p, dict):
            continue
        name, ptype = p.get("name", ""), loc_map.get(p.get("in", ""))
        if name and ptype:
            out.append({"name": name, "type": ptype, "value_hint": _hint(p.get("schema") or p)})
    return out


def _schema_props_params(schema, ptype: str) -> list[dict]:
    """Map a schema's ``properties`` to params of the given type."""
    props = (schema or {}).get("properties") or {} if isinstance(schema, dict) else {}
    return [{"name": n, "type": ptype, "value_hint": _hint(s)} for n, s in props.items()]


def _openapi3_params(operation: dict, path_level: list) -> list[dict]:
    loc_map = {"query": "query", "path": "path", "header": "header", "cookie": "cookie"}
    params = _named_params(list(path_level) + list(operation.get("parameters") or []), loc_map)
    body = operation.get("requestBody") or {}
    content = body.get("content") or {} if isinstance(body, dict) else {}
    for ctype, media in content.items():
        if isinstance(media, dict):
            ptype = "body_form" if ("form" in ctype or "urlencoded" in ctype) else "body_json"
            params += _schema_props_params(media.get("schema"), ptype)
    return params


def _swagger2_params(operation: dict, path_level: list) -> list[dict]:
    loc_map = {"query": "query", "path": "path", "header": "header", "formData": "body_form"}
    entries = list(path_level) + list(operation.get("parameters") or [])
    params = _named_params([p for p in entries if isinstance(p, dict) and p.get("in") != "body"], loc_map)
    for p in entries:
        if isinstance(p, dict) and p.get("in") == "body":
            params += _schema_props_params(p.get("schema"), "body_json")
    return params


def _expand_path_item(path: str, item: dict, is_v2: bool, base: str) -> list[dict]:
    """Expand one spec path item into one endpoint dict per HTTP method."""
    path_level = item.get("parameters") or []
    out: list[dict] = []
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
    return out


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
        if isinstance(item, dict):
            out += _expand_path_item(path, item, is_v2, base)
        if len(out) >= _MAX_OPS:
            return out[:_MAX_OPS]
    return out


_FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
_INPUT_RE = re.compile(r"<(?:input|select|textarea)\b([^>]*)>", re.I)


def _attr(blob: str, name: str) -> str | None:
    m = re.search(rf"{name}\s*=\s*['\"]([^'\"]*)['\"]", blob, re.I)
    return m.group(1) if m else None


def _form_params(inner: str, ptype: str) -> list[dict]:
    """Extract named, testable input fields from a form body."""
    params, seen = [], set()
    for tag in _INPUT_RE.findall(inner):
        name = _attr(tag, "name")
        itype = (_attr(tag, "type") or "text").lower()
        if not name or name in seen or itype in ("submit", "button", "reset", "image", "hidden"):
            continue
        seen.add(name)
        params.append({"name": name, "type": ptype,
                       "value_hint": "integer" if itype == "number" else "string"})
    return params


def extract_form_endpoints(html: str, page_url: str) -> list[dict]:
    """Parse ``<form>`` blocks into endpoints with their input fields as params."""
    out: list[dict] = []
    for attrs, inner in _FORM_RE.findall(html or ""):
        method = (_attr(attrs, "method") or "GET").upper()
        if method not in ("GET", "POST", "PUT", "DELETE", "PATCH"):
            method = "POST"
        action = _attr(attrs, "action") or page_url
        params = _form_params(inner, "query" if method == "GET" else "body_form")
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


def _path_ext(path: str) -> str:
    last = path.rsplit("/", 1)[-1]
    return "." + last.rsplit(".", 1)[-1].lower() if "." in last else ""


def _clean_js_route(raw: str) -> str | None:
    """Normalize a mined string into a route path, or None if it isn't one."""
    route = raw.split("${", 1)[0].split("?", 1)[0].split("#", 1)[0].strip()
    if not route.startswith("/") or not (2 <= len(route) <= 200):
        return None
    return None if _path_ext(route) in _STATIC_EXTS else route


def extract_js_routes(js_text: str) -> list[str]:
    """Mine a JS bundle for API route strings (fetch/axios/url:/api-path literals)."""
    found: set[str] = set()
    for pat in _JS_PATTERNS:
        for raw in pat.findall(js_text or ""):
            route = _clean_js_route(raw)
            if route:
                found.add(route)
    return sorted(found)


# ── fetching + orchestration ──────────────────────────────────────────────────

def _is_static(url: str) -> bool:
    return _path_ext(urlparse(url).path) in _STATIC_EXTS


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
    # SP-1: attach the crawl's auth (Bearer token / session cookies) so spec,
    # JS, form and liveness fetches see the AUTHENTICATED surface, not a login wall.
    _auth = _DISCOVERY_AUTH.get() or {}
    _headers = _auth.get("headers") or None
    _cookies = _auth.get("cookies") or None
    try:
        # ssl=False is intentional: a pentest tool must reach targets that use
        # self-signed / invalid certs, so cert validation is deliberately off.
        timeout = aiohttp.ClientTimeout(total=_FETCH_TIMEOUT)
        connector = aiohttp.TCPConnector(ssl=False)  # NOSONAR — see comment above (S4830)
        async with aiohttp.ClientSession(connector=connector, headers=_headers, cookies=_cookies) as session:
            async with session.get(url, timeout=timeout, allow_redirects=True) as resp:
                # content.read(n) returns only the first available chunk, which
                # truncates a streamed/chunked body (a 50 KB spec arrived as a
                # 1 KB first chunk → JSON parse failed → spec silently skipped).
                # Accumulate full chunks up to the byte cap instead.
                buf = bytearray()
                async for chunk in resp.content.iter_chunked(65536):
                    buf.extend(chunk)
                    if len(buf) >= _MAX_FETCH_BYTES:
                        break
                return resp.status, bytes(buf).decode("utf-8", "replace")
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


def _spec_candidate_urls(base: str, spider_urls: list[str]) -> list[str]:
    """Spider-found spec URLs first, then common probe locations (deduped)."""
    urls, seen = [], set()
    for u in spider_urls:
        if re.search(r"(openapi|swagger|api-docs)", u, re.I) and u not in seen:
            seen.add(u); urls.append(u)
    for c in _SPEC_CANDIDATES:
        cu = urljoin(base, c)
        if cu not in seen:
            seen.add(cu); urls.append(cu)
    return urls


async def _discover_spec(base: str, spider_urls: list[str]) -> list[dict] | None:
    """Fetch + parse the first valid OpenAPI/Swagger spec; return its operations."""
    urls = _spec_candidate_urls(base, spider_urls)
    for res in await asyncio.gather(*(_fetch(u) for u in urls[:16]), return_exceptions=True):
        if isinstance(res, tuple):
            spec = _parse_spec_text(res[1])
            if spec:
                return parse_openapi(spec)
    return None


def _route_params(route: str) -> list[dict]:
    """SP-2: infer params from a JS-mined route so it generates injection cells,
    not just endpoint-level cells. Query params from ?a=b; path params from
    numeric segments AND templatized {id}/:id placeholders (integer hint → the
    IDOR/SQLi cells that matter on an object-reference route). A route with no
    inferable params yields [] (endpoint-level cells only) as before."""
    from urllib.parse import parse_qs, urlsplit
    parts = urlsplit(route)
    params = [{"name": n, "type": "query", "value_hint": "string"}
              for n in parse_qs(parts.query) if not n.startswith("__")]
    for i, seg in enumerate(parts.path.split("/")):
        if seg.isdigit() or re.fullmatch(r"[:{]\w+[}]?", seg):
            name = seg.strip(":{}") or f"id_{i}"
            params.append({"name": name, "type": "path", "value_hint": "integer"})
    return params


async def _discover_js(spider_urls: list[str]) -> list[dict]:
    """Mine linked JS bundles for routes."""
    js_urls = [u for u in spider_urls if u.lower().split("?", 1)[0].endswith(".js")][:_MAX_JS_FILES]
    eps: list[dict] = []
    for res in await asyncio.gather(*(_fetch(u) for u in js_urls), return_exceptions=True):
        if isinstance(res, tuple) and res[0] and res[1]:
            eps += [{"path": r, "method": "GET", "params": _route_params(r),
                     "discovered_by": "js-bundle"}
                    for r in extract_js_routes(res[1])]
    return eps


async def _discover_forms(spider_urls: list[str]) -> list[dict]:
    """Read forms on HTML pages into endpoints with body params."""
    html_urls = [u for u in spider_urls if not _is_static(u)][:_MAX_HTML_PAGES]
    results = await asyncio.gather(*(_fetch(u) for u in html_urls), return_exceptions=True)
    eps: list[dict] = []
    for url, res in zip(html_urls, results):
        if isinstance(res, tuple) and res[0] and "<form" in res[1].lower():
            eps += extract_form_endpoints(res[1], url)
    return eps


async def _verify_live(base: str, inventory: list[dict]) -> tuple[list[dict], int]:
    """Drop inventory entries whose CONCRETE path returns 404 — phantom spec ops.

    An OpenAPI spec is frequently aspirational: it documents routes that aren't
    actually wired (observed: a 54-operation spec where /api/v1/accounts,
    /api/v1/transfer, … all 404'd). Registering those fans ~15 dead coverage
    cells each, inflates the matrix, and sends the model chasing 404s. So before
    registration we probe each concrete path once (GET, concurrent, bounded) and
    drop the ones that 404 — a route that merely needs a different method/auth
    answers 405/401/403/5xx (not 404), so it survives.

    Templated paths ({id}/{version}) are KEPT — they can't be probed literally and
    need a value to test anyway. Fail-soft: a probe error/timeout keeps the entry
    (never drop on doubt). Returns ``(kept_inventory, dropped_count)``.
    """
    concrete: dict[str, str] = {}
    for ep in inventory:
        p = ep.get("path", "")
        if p and "{" not in p and "}" not in p:
            concrete.setdefault(p, urljoin(base, p))
    if not concrete:
        return inventory, 0
    paths = list(concrete)[:_MAX_VERIFY]
    results = await asyncio.gather(*(_fetch(concrete[p]) for p in paths), return_exceptions=True)
    dead = {
        p for p, res in zip(paths, results)
        if isinstance(res, tuple) and res[0] == 404
    }
    if not dead:
        return inventory, 0
    kept = [ep for ep in inventory if ep.get("path", "") not in dead]
    return kept, len(inventory) - len(kept)


async def _register_inventory(inventory: list[dict], auth_context: str) -> dict:
    """Register every endpoint (add_endpoint dedups); tally new registrations/cells."""
    from core.coverage import add_endpoint
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
    return {"registered": registered, "cells": cells, "by_source": by_source}


async def import_openapi(spec_url: str, auth: dict | None = None) -> dict:
    """SM-4: fetch an OpenAPI/Swagger spec by URL and register EVERY operation as
    coverage endpoints+cells in one call — vs the model hand-transcribing 50 ops
    into 50 report(coverage) calls (a clerical task small models fumble). Reuses
    the same parser + registration path as spider-driven discovery."""
    token = _DISCOVERY_AUTH.set(auth)
    try:
        _status, text = await _fetch(spec_url)
        spec = _parse_spec_text(text) if text else None
        if not spec:
            return {"registered": 0, "cells": 0,
                    "error": f"no valid OpenAPI/Swagger document at {spec_url}"}
        ops = parse_openapi(spec)
        result = await _register_inventory(ops, "jwt" if (auth or {}).get("headers", {}).get("Authorization") else "none")
        result["operations"] = len(ops)
        return result
    finally:
        _DISCOVERY_AUTH.reset(token)


_GRAPHQL_INTROSPECTION = (
    '{"query":"query{__schema{queryType{name fields{name args{name}}} '
    'mutationType{name fields{name args{name}}}}}"}'
)


async def import_graphql(url: str, auth: dict | None = None) -> dict:
    """SP-3: POST an introspection query and register the /graphql endpoint with
    every query/mutation field ARG as a body param — so the injectable surface
    (per-arg cells) is in the matrix and the graphql gate fires. GraphQL has one
    transport URL, so args (not per-field URLs) are the honest injection targets."""
    import aiohttp
    headers = {"Content-Type": "application/json"}
    headers.update((auth or {}).get("headers") or {})
    try:
        timeout = aiohttp.ClientTimeout(total=_FETCH_TIMEOUT)
        connector = aiohttp.TCPConnector(ssl=False)  # NOSONAR (S4830) — pentest target
        async with aiohttp.ClientSession(connector=connector, cookies=(auth or {}).get("cookies")) as s:
            async with s.post(url, data=_GRAPHQL_INTROSPECTION, headers=headers, timeout=timeout) as r:
                data = json.loads(await r.text())
    except Exception as exc:
        return {"registered": 0, "cells": 0, "error": f"introspection failed: {exc}"}
    schema = (data.get("data") or {}).get("__schema") or {}
    args: list[str] = []
    for root in ("queryType", "mutationType"):
        for field in ((schema.get(root) or {}).get("fields") or []):
            args += [a.get("name") for a in (field.get("args") or []) if a.get("name")]
    if not args:
        return {"registered": 0, "cells": 0, "error": "introspection returned no fields (may be disabled)"}
    params = [{"name": n, "type": "body_json", "value_hint": "string"} for n in dict.fromkeys(args)]
    from urllib.parse import urlparse
    result = await _register_inventory(
        [{"path": urlparse(url).path or "/graphql", "method": "POST", "params": params,
          "discovered_by": "graphql-introspection"}], "none")
    result["fields_args"] = len(params)
    return result


async def discover_and_register(target: str, spider_urls: list[str], auth_context: str = "none",
                                auth: dict | None = None) -> dict:
    """Enrich spider output with spec/JS/form discovery and auto-register everything.

    ``auth`` (SP-1): ``{"headers": {...}, "cookies": {...}}`` — the crawl's session,
    attached to every discovery re-fetch so auth-gated specs/routes/forms are seen.
    When present, ``auth_context`` is upgraded from ``none`` to the real form so the
    matrix cells aren't mislabeled unauthenticated.

    Returns ``{"registered", "cells", "by_source", "spec_found", "inventory"}``.
    Fail-soft: any fetch/parse error is swallowed; partial results still register.
    """
    parsed_t = urlparse(target)
    base = f"{parsed_t.scheme}://{parsed_t.netloc}"

    if auth and auth_context == "none":
        if (auth.get("headers") or {}).get("Authorization"):
            auth_context = "jwt"
        elif auth.get("cookies"):
            auth_context = "cookie"

    token = _DISCOVERY_AUTH.set(auth)
    try:
        inventory: list[dict] = list(_spider_endpoints(spider_urls))
        spec_ops = await _discover_spec(base, spider_urls)
        if spec_ops:
            inventory += spec_ops
        inventory += await _discover_js(spider_urls)
        inventory += await _discover_forms(spider_urls)

        inventory, dropped = await _verify_live(base, inventory)

        result = await _register_inventory(inventory, auth_context)
    finally:
        _DISCOVERY_AUTH.reset(token)
    result["spec_found"] = spec_ops is not None
    result["inventory"] = len(inventory)
    result["unverified_dropped"] = dropped
    return result
