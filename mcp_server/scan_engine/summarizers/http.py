"""httpx + http_request summarizers."""
from __future__ import annotations

import json
import re
from typing import Any

from ._common import SummaryResult


# ---------------------------------------------------------------------------
# httpx summarizer
# ---------------------------------------------------------------------------

def _parse_httpx_json_line(line: str, url: str) -> dict | None:
    """Parse a single httpx JSON line. Returns parsed fields dict or None on failure."""
    try:
        data = json.loads(line)
        return {
            "status": data.get("status_code") or data.get("status-code"),
            "tech": data.get("tech", []),
            "title": data.get("title", ""),
            "content_type": data.get("content_type", data.get("content-type", "")),
            "server": data.get("webserver", data.get("server", "")),
            "cdn_or_waf": data.get("cdn", "") or data.get("waf", ""),
            "url": data.get("url", url),
        }
    except json.JSONDecodeError:
        return None


def _parse_httpx_text_line(line: str, url: str) -> dict | None:
    """Parse a single httpx text-mode line. Returns parsed fields dict or None on no match."""
    m = re.match(r'(https?://\S+)\s+\[(\d+)\]', line)
    if not m:
        return None
    brackets = re.findall(r'\[([^\]]+)\]', line)
    return {
        "status": int(m.group(2)),
        "url": m.group(1),
        "server": brackets[1] if len(brackets) > 1 else "",
        "content_type": brackets[2] if len(brackets) > 2 else "",
        "title": brackets[3] if len(brackets) > 3 else "",
        "tech": [],
        "cdn_or_waf": "",
    }


def _build_httpx_facts(result: SummaryResult, status: Any, server: str, content_type: str, title: str, tech: Any, cdn_or_waf: str) -> None:
    """Append extracted fields to result.facts."""
    if status:
        result.facts.append(f"Status: {status}")
    if server:
        result.facts.append(f"Server: {server}")
    if content_type:
        result.facts.append(f"Content-Type: {content_type}")
    if title:
        result.facts.append(f"Title: {title}")
    if tech:
        result.facts.append(f"Tech: {', '.join(tech) if isinstance(tech, list) else tech}")
    if cdn_or_waf:
        result.facts.append(f"CDN/WAF: {cdn_or_waf}")


def _find_parsed_httpx_line(lines: list[str], url: str) -> dict | None:
    """Return the first successfully parsed line from httpx output, or None."""
    for line in lines:
        line = line.strip()
        parsed = (
            _parse_httpx_json_line(line, url)
            if line.startswith("{")
            else _parse_httpx_text_line(line, url)
        )
        if parsed:
            return parsed
    return None


def _build_httpx_summary(result: "SummaryResult", url: str, status: object, server: str) -> None:
    """Populate result.summary and anomalies based on parsed httpx status."""
    if status:
        result.summary = f"{url} is live (HTTP {status})"
        if server:
            result.summary += f", server: {server}"
    else:
        result.summary = f"httpx scan of {url} — could not parse status"
        result.anomalies.append("Could not parse httpx output format")


def _summarize_httpx(raw: str, ctx: dict) -> SummaryResult:
    """Parse httpx output to extract tech stack, status, WAF, headers."""
    result = SummaryResult()
    url = ctx.get("url", "")
    parsed = _find_parsed_httpx_line(raw.strip().splitlines(), url)

    if parsed:
        status       = parsed["status"]
        url          = parsed["url"]
        server       = parsed["server"]
        tech         = parsed["tech"]
        content_type = parsed["content_type"]
        title        = parsed["title"]
        cdn_or_waf   = parsed["cdn_or_waf"]
    else:
        status = None
        server = tech = content_type = title = cdn_or_waf = ""

    _build_httpx_summary(result, url, status, server)
    _build_httpx_facts(result, status, server, content_type, title, tech, cdn_or_waf)

    result.evidence = {
        "url": url,
        "status": status,
        "server": server,
        "tech": tech,
    }

    result.recommended.append("Run scan(tool='spider') to crawl endpoints")
    if not cdn_or_waf:
        result.recommended.append("No WAF detected — direct testing likely viable")

    return result


# ---------------------------------------------------------------------------
# http_request summarizer
# ---------------------------------------------------------------------------

def _summarize_http_request(raw: str, ctx: dict) -> SummaryResult:
    """Parse HTTP response from http(action='request')."""
    result = SummaryResult()
    url = ctx.get("url", "")
    method = ctx.get("method", "GET")

    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        result.summary = f"{method} {url} — raw response (not JSON)"
        result.facts.append(f"Raw length: {len(raw)} chars")
        result.evidence = {"raw_length": len(raw)}
        return result

    if "error" in data:
        result.summary = f"{method} {url} — ERROR: {data['error']}"
        result.anomalies.append(data["error"])
        if "hint" in data:
            result.facts.append(data["hint"])
        result.evidence = {"error": data["error"]}
        return result

    status = data.get("status", 0)
    headers = data.get("headers", {})
    body = data.get("body", "")

    result.summary = f"{method} {url} returned HTTP {status}"

    result.facts.append(f"Status: {status}")
    if headers.get("Content-Type"):
        result.facts.append(f"Content-Type: {headers['Content-Type']}")
    if headers.get("Server"):
        result.facts.append(f"Server: {headers['Server']}")
    result.facts.append(f"Body length: {len(body)} chars")

    # Extract interesting patterns from body
    _extract_body_signals(body, result)

    result.evidence = {
        "status": status,
        "content_type": headers.get("Content-Type", ""),
        "body_preview": body[:500],
        # Capture JWTs from the FULL body, not just the 500-char preview — a real
        # login response often carries the token deeper than 500 chars, and the auth
        # asset capture (envelope/assets.py) would otherwise miss it, starving the
        # sweep's auth self-heal of a token to replay.
        "jwt_hits": __import__("re").findall(
            r"eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]+", body)[:5],
        # CH-2: surface Set-Cookie so the envelope can capture a session cookie
        # into known_assets for reuse (the majority of classic web apps are
        # cookie-session, not JWT).
        "set_cookie": headers.get("Set-Cookie", "") or headers.get("set-cookie", ""),
        # CH-8: surface rate-limit signals (429 / Retry-After / X-RateLimit-*) so
        # the envelope can record throttle state — the agent must respect it
        # (e.g. the SMS-token request cap) and a MISSING limit is itself a finding.
        "rate_limit": {k: v for k, v in headers.items()
                       if k.lower() == "retry-after" or k.lower().startswith("x-ratelimit")},
    }

    # Security-relevant headers
    security_headers = ["X-Frame-Options", "Content-Security-Policy",
                        "Strict-Transport-Security", "X-Content-Type-Options"]
    missing = [h for h in security_headers if h.lower() not in {k.lower() for k in headers}]
    if missing:
        result.facts.append(f"Missing security headers: {', '.join(missing)}")

    return result


def _extract_body_signals(body: str, result: SummaryResult) -> None:
    """Detect interesting patterns in response body."""
    lower = body.lower()

    if "werkzeug" in lower and "debugger" in lower:
        result.anomalies.append("Werkzeug debugger detected — potential RCE")
    if "traceback" in lower or "stack trace" in lower:
        result.anomalies.append("Stack trace in response — information disclosure")
    if "sql" in lower and ("syntax" in lower or "error" in lower):
        result.anomalies.append("Possible SQL error in response")
    if any(kw in lower for kw in ("password", "secret", "api_key", "apikey", "token")):
        result.anomalies.append("Sensitive keyword detected in response body")
