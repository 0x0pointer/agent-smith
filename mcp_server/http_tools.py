"""
Consolidated HTTP tool — replaces http_request and save_poc from exploitation.py
"""
import json
import os
from typing import Any

from core import cost as cost_tracker
from core import logger as log
from mcp_server._app import mcp


@mcp.tool()
async def http(
    action:  str,
    url:     str,
    method:  str = "GET",
    headers: dict | None = None,
    body:    Any = None,
    options: dict | None = None,
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
    """
    if isinstance(body, dict):
        body = json.dumps(body)
    opts = options or {}

    if action == "request":
        return await _do_request(url, method, headers, body, opts)
    elif action == "save_poc":
        return _do_save_poc(url, method, headers, body, opts)
    else:
        return f"Unknown action '{action}'. Use: request, save_poc"


async def _do_request(url, method, headers, body, opts):
    import aiohttp

    poc = opts.get("poc", False)
    burp_proxy = opts.get("burp_proxy", "http://127.0.0.1:8080")
    proxy = burp_proxy if poc else None

    log.tool_call("http_request", {"url": url, "method": method, "poc": poc})
    call_id = cost_tracker.start("http_request")
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
                result = json.dumps({
                    "status": resp.status,
                    "headers": dict(resp.headers),
                    "body": text[:8_000],
                    "burp": f"request sent through {burp_proxy}" if poc else "not routed through Burp",
                }, indent=2)
    except Exception as exc:
        result = json.dumps({
            "error": str(exc),
            "hint": f"If poc=true, make sure Burp Suite is open with proxy on {burp_proxy}",
        })
    cost_tracker.finish(call_id, result)
    log.tool_result("http_request", result)
    return result


def _do_save_poc(url, method, headers, body, opts):
    import datetime as dt
    from urllib.parse import urlparse

    title = opts.get("title", "poc")
    notes = opts.get("notes", "")

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

    with open(filepath, "w") as f:
        if notes:
            f.write(f"# {notes}\n\n")
        f.write(raw)

    result = json.dumps({
        "saved": filepath,
        "hint": "Open Burp Repeater and paste this file to load the request",
    })
    log.tool_result("save_poc", result)
    return result
