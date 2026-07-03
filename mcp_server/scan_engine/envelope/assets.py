"""
Tool-invocation recording (P1) and known-asset extraction (P2).
"""
from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# P1 — Tool invocation recording
# ---------------------------------------------------------------------------

def _record_invocation(tool: str, ctx: dict, summary: str) -> bool:
    """Record tool invocation with summary for dedup and recovery.

    Returns True if this invocation was a duplicate (same tool+target+options already seen).
    """
    import hashlib
    from core import session as scan_session
    target = ctx.get("url", ctx.get("host", ctx.get("domain", ctx.get("path", ""))))
    hash_input = f"{tool}:{target}:{sorted(ctx.items())}"
    options_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:8]
    current = scan_session.get() or {}
    invocations = current.get("tool_invocations", [])
    is_duplicate = bool(options_hash and any(i.get("options_hash") == options_hash for i in invocations))
    scan_session.add_tool_invocation(tool, target, summary, options_hash)
    return is_duplicate


# ---------------------------------------------------------------------------
# P2 — Known assets extraction
# ---------------------------------------------------------------------------

def _persist_httpx_assets(scan_session: Any, evidence: dict) -> None:
    """Persist tech stack and server assets from httpx evidence."""
    tech = evidence.get("tech", [])
    if tech:
        scan_session.update_known_assets(
            "technologies", tech if isinstance(tech, list) else [tech])
    server = evidence.get("server")
    if server:
        scan_session.update_known_assets("technologies", [server])


def _persist_port_scan_assets(scan_session: Any, evidence: dict, ctx: dict) -> None:
    """Persist ports and hosts from naabu/nmap evidence."""
    ports = evidence.get("ports", [])
    hosts = evidence.get("hosts", [])
    host = hosts[0] if hosts else ctx.get("host", "")
    if ports:
        scan_session.update_known_assets(
            "ports", [{"host": host, "port": p} for p in ports])
    if hosts:
        scan_session.update_known_assets("domains", hosts)


_JWT_RE = __import__("re").compile(r"eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]+")
_AUTH_PATH_HINTS = ("login", "signin", "auth", "token", "session")


def _update_jwt_tokens(scan_session: Any, req_headers: dict, body_prev: str, url: str) -> None:
    """Scan response body + auth-y request headers for JWT strings and persist any found."""
    from datetime import datetime, timezone
    haystack = body_prev
    for k, v in req_headers.items():
        if isinstance(v, str) and "auth" in k.lower():
            haystack += " " + v
    tokens = [
        {"type": "jwt", "value": m,
         "obtained_at": datetime.now(timezone.utc).isoformat(), "source_url": url}
        for m in _JWT_RE.findall(haystack)
    ]
    if tokens:
        scan_session.update_known_assets("auth_tokens", tokens)


def _update_credentials(
    scan_session: Any, url: str, method: str, status: int, req_body: str
) -> None:
    """Persist credentials and auth endpoint when a POST login succeeds."""
    import json
    if not (method == "POST" and 200 <= status < 300
            and any(h in url.lower() for h in _AUTH_PATH_HINTS) and req_body):
        return
    try:
        req_data = json.loads(req_body) if req_body.lstrip().startswith("{") else None
    except Exception:
        req_data = None
    if not isinstance(req_data, dict):
        return
    uname = req_data.get("username") or req_data.get("user") or req_data.get("email")
    pword = req_data.get("password") or req_data.get("pass") or req_data.get("pwd")
    if uname and pword:
        scan_session.update_known_assets("credentials", [{
            "username": str(uname), "password": str(pword),
            "source": f"login_success {url}",
        }])
        scan_session.update_known_assets("auth_endpoints", [{
            "path": url, "method": method,
            "body_template": {"username": "$USERNAME", "password": "$PASSWORD"},
        }])


def _persist_http_auth_assets(scan_session: Any, evidence: dict, ctx: dict) -> None:
    """Extract JWTs, credentials, and auth endpoints from an http_request.

    Triggers:
      - Any JWT-looking string in the response body or Authorization headers
        is added to known_assets.auth_tokens.
      - A 2xx response to POST to an auth-looking path whose request body
        contained username/password adds the credentials to known_assets.credentials
        AND registers the auth endpoint in known_assets.auth_endpoints.
    """
    status      = evidence.get("status", 0)
    body_prev   = evidence.get("body_preview", "")
    url         = ctx.get("url", "")
    method      = (ctx.get("method") or "GET").upper()
    req_body    = ctx.get("body", "") or ""
    req_headers = ctx.get("headers") or {}

    _update_jwt_tokens(scan_session, req_headers, body_prev, url)
    _update_credentials(scan_session, url, method, status, req_body)


def _extract_and_persist_assets(tool: str, result: Any, ctx: dict) -> None:
    """Extract discovered assets from summarizer result and persist to session."""
    from core import session as scan_session
    evidence = result.evidence

    if tool == "httpx":
        _persist_httpx_assets(scan_session, evidence)
    elif tool in ("naabu", "nmap"):
        _persist_port_scan_assets(scan_session, evidence, ctx)
    elif tool == "subfinder":
        subs = evidence.get("subdomains", [])
        if subs:
            scan_session.update_known_assets("domains", subs[:50])
    elif tool == "spider":
        endpoints = evidence.get("endpoints", [])
        if endpoints:
            scan_session.update_known_assets(
                "endpoints",
                [ep.get("path", "") for ep in endpoints if ep.get("path")])
    elif tool in ("fuzzyai", "garak", "pyrit", "promptfoo"):
        # AI scans pass the URL straight to the tool (no spider), so without this
        # the AI endpoint never lands in known_assets — leaving recovery and the
        # deepen gate blind to the AI surface. Persist the target path.
        target = ctx.get("target", "")
        if target:
            from urllib.parse import urlparse
            path = urlparse(target).path or target
            scan_session.update_known_assets("endpoints", [path])
    elif tool == "http_request":
        _persist_http_auth_assets(scan_session, evidence, ctx)
