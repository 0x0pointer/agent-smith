"""
Consolidated HTTP tool — replaces http_request and save_poc from exploitation.py
"""
import asyncio
import json
import os
from typing import Any

from core import cost as cost_tracker
from core import logger as log
from mcp_server._app import mcp, _ensure_dict

# Inline response body shown in the result/cost/log (the envelope itself only
# surfaces a 500-char preview of this). Kept small so big responses don't bloat
# context or the cost estimate.
_INLINE_BODY_CHARS = 8_000
# Full response body kept as the on-disk artifact when it exceeds the inline cap,
# so the model can grep/page a large OpenAPI spec or JS bundle via
# session(action='artifact'). ~1 MB bound guards against pathological downloads.
_MAX_ARTIFACT_BODY = 1_000_000


def _write_text(path: str, content: str) -> None:
    with open(path, "w") as fh:
        fh.write(content)


@mcp.tool()
async def http(
    action:  str,
    url:     str,
    method:  str = "GET",
    headers: dict | str | None = None,
    body:    Any = None,
    options: dict | str | None = None,
) -> str:
    """Raw HTTP request or PoC saving.

    action  : request | save_poc
    url     : target URL
    method  : HTTP method (default GET)
    headers : request headers dict
    body    : request body string
    options : action-specific settings

    request options:
      poc=false        — set true to route through Burp proxy
      burp_proxy=http://127.0.0.1:8080

    save_poc options:
      title=poc        — filename label
      notes=           — description written as comment in the .http file
      finding_id=      — finding UUID to auto-link this PoC (adds filepath to finding.poc_files)
    """
    if isinstance(body, dict):
        body = json.dumps(body)
    headers = _ensure_dict(headers)
    opts = _ensure_dict(options) or {}

    if action == "request":
        return await _do_request(url, method, headers, body, opts)
    elif action == "save_poc":
        return await _do_save_poc(url, method, headers, body, opts)
    else:
        return f"Unknown action '{action}'. Use: request, save_poc"


async def _do_request(url, method, headers, body, opts):
    import aiohttp

    poc = opts.get("poc", False)
    burp_proxy = opts.get("burp_proxy", "http://127.0.0.1:8080")
    proxy = burp_proxy if poc else None

    log.tool_call("http_request", {"url": url, "method": method, "poc": poc})
    call_id = cost_tracker.start("http_request")
    artifact_raw = None
    try:
        async with aiohttp.ClientSession() as session:
            async with session.request(
                method, url,
                headers=headers or {},
                data=body,
                timeout=aiohttp.ClientTimeout(total=30),
                ssl=False,
                proxy=proxy,
            ) as resp:
                text = await resp.text()
                base = {
                    "status": resp.status,
                    "headers": dict(resp.headers),
                    "burp": f"request sent through {burp_proxy}" if poc else "not routed through Burp",
                }
                # Inline result drives the 500-char preview, cost, and logging —
                # keep it bounded.
                result = json.dumps({**base, "body": text[:_INLINE_BODY_CHARS]}, indent=2)
                # When the body is larger, ALSO keep the full body (up to a sane
                # cap) as the on-disk artifact so the model can grep/page a big
                # OpenAPI spec or JS bundle via session(action='artifact'). It's
                # never sent inline, so it inflates neither context nor cost.
                if len(text) > _INLINE_BODY_CHARS:
                    artifact_raw = json.dumps({**base, "body": text[:_MAX_ARTIFACT_BODY]}, indent=2)
    except Exception as exc:
        result = json.dumps({
            "error": str(exc),
            "hint": f"If poc=true, make sure Burp Suite is open with proxy on {burp_proxy}",
        })
    cost_tracker.finish(call_id, result)
    log.tool_result("http_request", result)

    from mcp_server.scan_engine import wrap
    # Pass body + headers so the envelope can detect credential-validation
    # attempts (password/secret/api_key fields). Without these the QA daemon
    # cannot exclude legitimate login traffic from its session-expiry check
    # and fires false-positive HIR_AUTH_FAILURE on every login attempt.
    return wrap("http_request", result, {
        "url":     url,
        "method":  method,
        "body":    body or "",
        "headers": headers or {},
    }, artifact_raw=artifact_raw)


async def _do_save_poc(url, method, headers, body, opts):
    import datetime as dt
    from urllib.parse import urlparse

    title      = opts.get("title", "poc")
    notes      = opts.get("notes", "")
    finding_id = opts.get("finding_id", "")

    parsed = urlparse(url)
    host = parsed.netloc
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    lines = [f"{method.upper()} {path} HTTP/1.1", f"Host: {host}"]
    for k, v in (headers or {}).items():
        lines.append(f"{k}: {v}")
    if body:
        lines.append(f"Content-Length: {len(body.encode())}")
    lines.append("")
    if body:
        lines.append(body)
    raw = "\r\n".join(lines)

    pocs_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "pocs")
    os.makedirs(pocs_dir, exist_ok=True)
    safe_title = "".join(c if c.isalnum() or c in "-_" else "_" for c in title)
    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(pocs_dir, f"{timestamp}_{safe_title}.http")

    poc_content = (f"# {notes}\n\n" if notes else "") + raw
    await asyncio.to_thread(_write_text, filepath, poc_content)

    linked = False
    if finding_id:
        from core import findings as findings_store
        linked = await findings_store.link_poc(finding_id, filepath)

    result = json.dumps({
        "saved":      filepath,
        "linked_to":  finding_id if linked else None,
        "hint":       "Open Burp Repeater and paste this file to load the request",
    })
    log.tool_result("save_poc", result)
    return result
