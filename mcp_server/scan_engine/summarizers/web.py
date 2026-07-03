"""Web-surface summarizers — sqlmap, ffuf, spider."""
from __future__ import annotations

import json
import re
from typing import Any

from ._common import SummaryResult


# ---------------------------------------------------------------------------
# kali_sqlmap summarizer
# ---------------------------------------------------------------------------

def _process_sqlmap_line(stripped: str, state: dict) -> bool:
    """Update state with data from one stripped sqlmap output line.

    Returns True when the 'not injectable' signal is found (caller should stop).
    """
    if "all tested parameters do not appear to be injectable" in stripped.lower():
        return True
    m = re.match(r"Parameter:\s+(\S+)\s+\((\w+)\)", stripped)
    if m:
        state["injectable_params"].append(f"{m.group(1)} ({m.group(2)})")
    if "is vulnerable" in stripped.lower():
        state["is_vulnerable"] = True
    m = re.match(r"back-end DBMS:\s+(.+)", stripped, re.I)
    if m:
        state["db_type"] = m.group(1).strip()
    if re.match(r"\[\*\]\s+\w+", stripped):
        db_name = stripped.lstrip("[*] ").strip()
        if db_name and db_name not in state["databases"]:
            state["databases"].append(db_name)
    m = re.match(r"\|\s+(\w+)\s+\|", stripped)
    if m:
        state["tables"].append(m.group(1))
    return False


def _parse_sqlmap_lines(lines: list[str]) -> dict | None:
    """Parse sqlmap output lines. Returns None if 'not injectable' is detected."""
    state: dict = {
        "injectable_params": [], "db_type": "", "databases": [], "tables": [], "is_vulnerable": False,
    }
    for line in lines:
        if _process_sqlmap_line(line.strip(), state):
            return None
    return {
        "injectable_params": state["injectable_params"],
        "db_type": state["db_type"],
        "databases": state["databases"],
        "tables": state["tables"],
        "is_vulnerable": state["is_vulnerable"] or bool(state["injectable_params"]),
    }


def _build_sqlmap_vulnerable_result(result: SummaryResult, parsed: dict) -> None:
    """Populate result fields when sqlmap found injectable parameters."""
    injectable_params = parsed["injectable_params"]
    db_type = parsed["db_type"]
    params_str = ", ".join(injectable_params) if injectable_params else "unknown"
    result.summary = f"SQLi CONFIRMED on parameter(s): {params_str}"
    if db_type:
        result.summary += f" (DBMS: {db_type})"
    result.facts.append(f"Injectable: {params_str}")
    if db_type:
        result.facts.append(f"DBMS: {db_type}")
    if parsed["databases"]:
        result.facts.append(f"Databases: {', '.join(parsed['databases'][:10])}")
    if parsed["tables"]:
        result.facts.append(f"Tables: {', '.join(parsed['tables'][:20])}")
    result.recommended.append("Dump credentials: kali(command='sqlmap ... --dump -T users')")
    result.recommended.append("Try OS shell: kali(command='sqlmap ... --os-shell')")


def _summarize_kali_sqlmap(raw: str, _ctx: dict) -> SummaryResult:
    """Parse sqlmap output for injection results."""
    result = SummaryResult()
    lines = raw.strip().splitlines()

    parsed = _parse_sqlmap_lines(lines)
    if parsed is None:
        result.summary = "sqlmap: no injection found"
        result.facts.append("All tested parameters not injectable")
        return result

    if parsed["is_vulnerable"]:
        _build_sqlmap_vulnerable_result(result, parsed)
    else:
        result.summary = "sqlmap scan completed — check artifact for details"

    result.evidence = {
        "injectable_params": parsed["injectable_params"],
        "dbms": parsed["db_type"],
        "databases": parsed["databases"][:10],
        "tables": parsed["tables"][:20],
        "vulnerable": parsed["is_vulnerable"],
    }

    return result


# ---------------------------------------------------------------------------
# ffuf summarizer
# ---------------------------------------------------------------------------

def _parse_ffuf_json(raw: str) -> list[dict] | None:
    """Parse ffuf JSON output (-of json). Returns list of path dicts or None on parse error."""
    try:
        data = json.loads(raw)
        return [
            {"url": r.get("url", "?"), "status": r.get("status", 0), "length": r.get("length", 0)}
            for r in data.get("results", [])
        ]
    except (json.JSONDecodeError, TypeError):
        return None


def _parse_ffuf_text(raw: str) -> list[dict]:
    """Parse ffuf text output. Returns list of path dicts."""
    paths: list[dict] = []
    for line in raw.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("["):
            continue
        m = re.match(r'(\d{3})\s+\S+\s+\S+\s+(.*)', line)
        if m:
            paths.append({"url": m.group(2).strip(), "status": int(m.group(1)), "length": 0})
        elif line.startswith("http"):
            paths.append({"url": line, "status": 0, "length": 0})
    return paths


def _summarize_ffuf(raw: str, _ctx: dict) -> SummaryResult:
    """Parse ffuf output for discovered paths."""
    result = SummaryResult()
    paths = _parse_ffuf_json(raw)
    if paths is None:
        paths = _parse_ffuf_text(raw)

    if paths:
        result.summary = f"ffuf found {len(paths)} path(s)"
        for p in paths[:25]:
            status_str = f" [{p['status']}]" if p["status"] else ""
            result.facts.append(f"{p['url']}{status_str}")
        result.evidence = {"paths": paths[:50], "total": len(paths)}
    else:
        result.summary = "ffuf: no paths discovered"
        result.evidence = {"paths": [], "total": 0}

    return result


# ---------------------------------------------------------------------------
# spider summarizer
# ---------------------------------------------------------------------------

_STATIC_EXTENSIONS = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map",
}


def _extract_url_params(parsed_url: Any) -> list[dict]:
    """Extract query and path parameters from a parsed URL object."""
    from urllib.parse import parse_qs
    params: list[dict] = []
    path = parsed_url.path
    for name in parse_qs(parsed_url.query):
        if not name.startswith("__"):
            params.append({"name": name, "type": "query", "value_hint": "string"})
    for i, seg in enumerate(path.split("/")):
        if seg.isdigit():
            params.append({"name": f"id_{i}", "type": "path", "value_hint": "integer"})
    return params


def _extract_dynamic_endpoints(urls: list[str]) -> list[dict]:
    """Filter static assets and deduplicate URL paths into unique dynamic endpoints."""
    from urllib.parse import urlparse
    seen_paths: set[str] = set()
    endpoints: list[dict] = []
    for url in urls:
        parsed = urlparse(url)
        path = parsed.path.rstrip("/") or "/"
        ext = "." + path.rsplit(".", 1)[-1].lower() if "." in path.split("/")[-1] else ""
        if ext in _STATIC_EXTENSIONS:
            continue
        norm = re.sub(r'/\d+', '/{id}', path)
        if norm in seen_paths:
            continue
        seen_paths.add(norm)
        endpoints.append({"path": norm, "method": "GET", "params": _extract_url_params(parsed)})
    return endpoints


def _summarize_spider(raw: str, _ctx: dict) -> SummaryResult:
    """Parse katana/spider output — one URL per line. Extract endpoints for registration."""
    result = SummaryResult()
    urls = [l.strip() for l in raw.strip().splitlines() if l.strip() and l.strip().startswith("http")]

    if not urls:
        result.summary = "Spider: no URLs discovered"
        result.evidence = {"urls": [], "count": 0}
        return result

    endpoints = _extract_dynamic_endpoints(urls)

    result.summary = f"Spider crawled {len(urls)} URL(s), {len(endpoints)} unique endpoint(s)"
    result.facts = [f"{ep['path']}" + (f" params={[p['name'] for p in ep['params']]}" if ep['params'] else "") for ep in endpoints[:20]]
    result.evidence = {"endpoints": endpoints[:30], "all_urls_count": len(urls)}

    for ep in endpoints[:10]:
        params_json = json.dumps(ep["params"]) if ep["params"] else "[]"
        result.required.append(
            f"report(action='coverage', data={{\"type\":\"endpoint\", \"path\":\"{ep['path']}\", "
            f"\"method\":\"{ep['method']}\", \"params\":{params_json}, \"discovered_by\":\"spider\"}})"
        )

    return result
