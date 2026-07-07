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


def _update_jwt_tokens(scan_session: Any, req_headers: dict, body_prev: str, url: str,
                       body_jwts: list | None = None) -> None:
    """Scan response body + auth-y request headers for JWT strings and persist any found.

    ``body_jwts`` (pre-extracted from the FULL response body by the summarizer) is
    preferred over the truncated body_prev so a token deeper than 500 chars is still
    captured — otherwise the sweep's auth self-heal has no token to replay."""
    from datetime import datetime, timezone
    haystack = body_prev
    for k, v in req_headers.items():
        if isinstance(v, str) and "auth" in k.lower():
            haystack += " " + v
    found = list(body_jwts or []) + _JWT_RE.findall(haystack)
    seen: set = set()
    uniq = [m for m in found if not (m in seen or seen.add(m))]
    tokens = [
        {"type": "jwt", "value": m,
         "obtained_at": datetime.now(timezone.utc).isoformat(), "source_url": url}
        for m in uniq
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
        # Form-urlencoded login (username=x&password=y) — the classic HTML-form case
        # the JSON-only path was silently dropping, so form-auth apps captured no creds.
        if "=" in req_body:
            from urllib.parse import parse_qs
            try:
                req_data = {k: v[0] for k, v in
                            parse_qs(req_body, keep_blank_values=True).items() if v}
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


# CH-2: session-cookie names worth capturing for auth reuse. A framework session
# cookie (not a tracking/analytics one) authenticates subsequent requests, so it
# belongs in known_assets alongside JWTs — the AUTH_MISSING retry and the SP-1
# discovery re-fetch both consume it.
_SESSION_COOKIE_HINTS = (
    "session", "sess", "sid", "phpsessid", "jsessionid", "asp.net_sessionid",
    "connect.sid", "auth", "token", "_session", "csrf", "xsrf", "remember",
)


def _update_session_cookies(scan_session: Any, evidence: dict, url: str) -> None:
    """Persist session-ish Set-Cookie pairs into known_assets.session_cookies."""
    raw = evidence.get("set_cookie") or ""
    if not raw:
        return
    from datetime import datetime, timezone
    seen: list[dict] = []
    # A dict(resp.headers) collapses multiple Set-Cookie into one comma-joined
    # value; split conservatively on ", " boundaries that precede a `name=`.
    import re as _re
    for part in _re.split(r",(?=\s*[A-Za-z0-9!#$%&'*+.^_`|~-]+=)", raw):
        pair = part.strip().split(";", 1)[0]
        if "=" not in pair:
            continue
        name, _, value = pair.partition("=")
        name, value = name.strip(), value.strip()
        if not name or not value:
            continue
        if any(h in name.lower() for h in _SESSION_COOKIE_HINTS):
            seen.append({"name": name, "value": value,
                         "source_url": url,
                         "obtained_at": datetime.now(timezone.utc).isoformat()})
    if seen:
        scan_session.update_known_assets("session_cookies", seen)


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

    _update_jwt_tokens(scan_session, req_headers, body_prev, url,
                       body_jwts=evidence.get("jwt_hits"))
    _update_credentials(scan_session, url, method, status, req_body)
    _update_session_cookies(scan_session, evidence, url)
    _update_rate_limits(scan_session, evidence, url)


def _update_rate_limits(scan_session: Any, evidence: dict, url: str) -> None:
    """CH-8: record throttle state (429 / Retry-After / X-RateLimit-*) in
    known_assets so the agent stays throttle-aware (respects request caps) and
    can flag endpoints that DON'T rate-limit."""
    status = evidence.get("status", 0)
    rl = evidence.get("rate_limit") or {}
    if status == 429 or rl:
        hdr = " ".join(f"{k}={v}" for k, v in rl.items())
        scan_session.update_known_assets(
            "rate_limits", [f"{url}: HTTP {status}{(' ' + hdr) if hdr else ''}".strip()])


def _trigger_body_signal_gates(scan_session: Any, result: Any, ctx: dict) -> None:
    """CH-4: a response body signal that was previously a dead-end anomaly now
    opens a follow-up gate — the deterministic 'the tool already saw the bug'
    push a small model won't chain on its own. An interactive Werkzeug debugger
    is a near-certain RCE console; a reflected SQL error points at an injectable
    param. Both → a mandatory web-exploit gate to weaponize before completing."""
    anomalies = " ".join(getattr(result, "anomalies", []) or []).lower()
    url = ctx.get("url", "")
    if "werkzeug debugger" in anomalies:
        scan_session.trigger_gate(
            "web_exploit_debugger",
            f"Interactive debugger exposed at {url} — likely RCE",
            ["web-exploit"])
    elif "sql error" in anomalies:
        scan_session.trigger_gate(
            "web_exploit_sqli",
            f"SQL error reflected from {url} — likely injectable",
            ["web-exploit"])


def _persist_subfinder_assets(scan_session, evidence) -> None:
    subs = evidence.get("subdomains", [])
    if subs:
        scan_session.update_known_assets("domains", subs[:50])


def _persist_spider_assets(scan_session, evidence) -> None:
    endpoints = evidence.get("endpoints", [])
    if endpoints:
        scan_session.update_known_assets(
            "endpoints",
            [ep.get("path", "") for ep in endpoints if ep.get("path")])


def _persist_ai_target_asset(scan_session, ctx) -> None:
    """AI scans pass the URL straight to the tool (no spider), so without this the
    AI endpoint never lands in known_assets — leaving recovery and the deepen gate
    blind to the AI surface. Persist the target path."""
    target = ctx.get("target", "")
    if target:
        from urllib.parse import urlparse
        path = urlparse(target).path or target
        scan_session.update_known_assets("endpoints", [path])


def _persist_sqlmap_gate(scan_session, evidence, ctx) -> None:
    # CH-11: drive the gate from the TOOL's own verdict, not the model's wording —
    # sqlmap confirming injectability opens the web-exploit gate to weaponize.
    if evidence.get("vulnerable"):
        scan_session.trigger_gate(
            "web_exploit_sqli",
            f"sqlmap confirmed injectable: {ctx.get('target', '')}",
            ["web-exploit"])


def _persist_nuclei_gate(scan_session, evidence) -> None:
    # CH-11 + CH-3: a critical/high nuclei hit — especially a CVE — opens the
    # exploit-validation chain deterministically.
    findings = evidence.get("findings", []) or []
    if any(f.get("severity") in ("critical", "high") for f in findings):
        scan_session.trigger_gate(
            "analyze_cve", "nuclei reported a critical/high finding", ["analyze-cve"])


def _extract_and_persist_assets(tool: str, result: Any, ctx: dict) -> None:
    """Extract discovered assets from summarizer result and persist to session."""
    from core import session as scan_session
    evidence = result.evidence

    if tool == "httpx":
        _persist_httpx_assets(scan_session, evidence)
    elif tool in ("naabu", "nmap"):
        _persist_port_scan_assets(scan_session, evidence, ctx)
    elif tool == "subfinder":
        _persist_subfinder_assets(scan_session, evidence)
    elif tool == "spider":
        _persist_spider_assets(scan_session, evidence)
    elif tool in ("fuzzyai", "garak", "pyrit", "promptfoo"):
        _persist_ai_target_asset(scan_session, ctx)
    elif tool == "http_request":
        _persist_http_auth_assets(scan_session, evidence, ctx)
        _trigger_body_signal_gates(scan_session, result, ctx)
    elif tool == "kali_sqlmap":
        _persist_sqlmap_gate(scan_session, evidence, ctx)
    elif tool == "nuclei":
        _persist_nuclei_gate(scan_session, evidence)
