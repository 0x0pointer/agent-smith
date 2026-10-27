"""Auth-header sourcing + a live cookie jar for the AI red-team transports.

Issue #247: cookie-session and token targets had to be re-pasted as a giant
`headers` dict into every `redteam()` / `scan(tool="garak")` call, nothing was
reused from `known_assets`, and a rotating (sliding-expiry) session cookie went
stale the moment the server rotated it.

This module gives both transports one place to:
  * resolve_headers(options, base) — merge base headers (Content-Type) with auth
    pulled from known_assets when options ask for it (headers_from / auth_profile),
    under any explicit options["headers"] (explicit always wins so the agent can
    override a stale asset).
  * CookieJar — seed from an initial Cookie header / known_assets, apply on each
    request, and refresh from the response's Set-Cookie so a per-response rotating
    cookie keeps working across an attack loop; session-ish cookies are written
    back to known_assets so the next call (and compaction recovery) see the latest.

Pure-stdlib, fail-soft: with no running scan every lookup degrades to empty and
behaviour is exactly the old static-headers path.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

# Session-cookie names worth persisting back to known_assets (mirrors the http
# tool's envelope capture in scan_engine/envelope/assets.py).
_SESSION_COOKIE_HINTS = (
    "session", "sess", "sid", "phpsessid", "jsessionid", "asp.net_sessionid",
    "connect.sid", "auth", "token", "_session", "csrf", "xsrf", "remember",
)

# Values of headers_from / auth_profile that mean "the current known_assets vault".
_ASSET_PROFILE_NAMES = {"known_assets", "known-assets", "assets", "session", "auto"}


def _known_assets() -> dict:
    try:
        from core import session as _sess
        return (_sess.get() or {}).get("known_assets", {}) or {}
    except Exception:
        return {}


def _jar_from_cookie_list(cookies: list) -> dict:
    """Collapse a known_assets.session_cookies list into {name: value} (last wins)."""
    jar: dict[str, str] = {}
    for c in cookies or []:
        if isinstance(c, dict) and c.get("name") and c.get("value") is not None:
            jar[str(c["name"])] = str(c["value"])
    return jar


def cookie_header_from_assets(ka: dict | None = None) -> str:
    jar = _jar_from_cookie_list((ka if ka is not None else _known_assets()).get("session_cookies", []))
    return format_jar(jar)


def auth_headers_from_assets(ka: dict | None = None) -> dict:
    """Authorization (newest JWT), Cookie (session cookies), and any stored custom
    auth headers, built from known_assets."""
    ka = ka if ka is not None else _known_assets()
    out: dict[str, str] = {}
    tokens = [t for t in ka.get("auth_tokens", []) if isinstance(t, dict) and t.get("value")]
    if tokens:
        out["Authorization"] = f"Bearer {tokens[-1]['value']}"
    cookie = cookie_header_from_assets(ka)
    if cookie:
        out["Cookie"] = cookie
    for h in ka.get("auth_headers", []) or []:      # optional: stored X-Api-Key etc.
        if isinstance(h, dict) and h.get("name") and h.get("value") is not None:
            out[str(h["name"])] = str(h["value"])
    return out


def _profile_headers(name: str, ka: dict | None = None) -> dict:
    """Resolve a named auth profile. 'known_assets' (and aliases) → the live vault;
    any other name → known_assets.auth_profiles[name] if present, else {}."""
    key = (name or "").strip().lower()
    ka = ka if ka is not None else _known_assets()
    if key in _ASSET_PROFILE_NAMES:
        return auth_headers_from_assets(ka)
    prof = (ka.get("auth_profiles") or {}).get(name) or (ka.get("auth_profiles") or {}).get(key)
    if isinstance(prof, dict):
        return {str(k): str(v) for k, v in prof.items()}
    return {}


def wants_assets(options: dict) -> bool:
    return bool(options.get("headers_from") or options.get("auth_profile"))


def resolve_headers(options: dict, base: dict | None = None) -> dict:
    """Merge (low→high precedence): base < known_assets/profile auth < explicit headers.

    Explicit options["headers"] always wins so the agent can override one stale
    field while still sourcing the rest from known_assets.
    """
    hdrs = dict(base or {})
    profile = options.get("headers_from") or options.get("auth_profile")
    if profile:
        hdrs.update(_profile_headers(str(profile)))
    extra = options.get("headers") or {}
    if isinstance(extra, dict):
        hdrs.update({str(k): str(v) for k, v in extra.items()})
    return hdrs


# ── cookie jar ──────────────────────────────────────────────────────────────────

def parse_cookie_header(value: str) -> dict:
    """'a=1; b=2' → {'a': '1', 'b': '2'}."""
    jar: dict[str, str] = {}
    for part in (value or "").split(";"):
        name, sep, val = part.strip().partition("=")
        if sep and name:
            jar[name.strip()] = val.strip()
    return jar


def format_jar(jar: dict) -> str:
    return "; ".join(f"{n}={v}" for n, v in jar.items() if n)


def parse_set_cookie(lines) -> list[tuple[str, str]]:
    """Each Set-Cookie line → (name, value) from its first `name=value` pair.

    Accepts a list of header lines (http.client gives these via get_all) or a
    single comma-joined string (split conservatively before a `name=`).
    """
    if isinstance(lines, str):
        lines = re.split(r",(?=\s*[A-Za-z0-9!#$%&'*+.^_`|~-]+=)", lines)
    out: list[tuple[str, str]] = []
    for line in lines or []:
        pair = str(line).strip().split(";", 1)[0]
        name, sep, val = pair.partition("=")
        if sep and name.strip():
            out.append((name.strip(), val.strip()))
    return out


class CookieJar:
    """A per-send cookie jar: seed, apply, refresh from Set-Cookie, persist back.

    Seeded from (in precedence order) the initial Cookie header the caller built
    and, when the caller asked for known_assets, the stored session cookies.
    `apply(headers)` stamps the current jar onto an outgoing request;
    `update_from_response(set_cookie_lines)` refreshes it from the reply and writes
    session-ish cookies back to known_assets so a rotating cookie never goes stale.
    """

    def __init__(self, initial: dict | None = None, source_url: str = ""):
        self.jar: dict[str, str] = dict(initial or {})
        self.source_url = source_url

    @classmethod
    def from_headers(cls, headers: dict, source_url: str = "") -> "CookieJar":
        cookie = ""
        for k, v in (headers or {}).items():
            if k.lower() == "cookie":
                cookie = v
                break
        return cls(parse_cookie_header(cookie), source_url)

    def apply(self, headers: dict) -> dict:
        if self.jar:
            headers["Cookie"] = format_jar(self.jar)
        return headers

    def update_from_response(self, set_cookie_lines, persist: bool = True) -> list[str]:
        """Merge the response's Set-Cookie pairs; return the names that changed."""
        changed: list[str] = []
        persist_rows: list[dict] = []
        for name, value in parse_set_cookie(set_cookie_lines):
            if not value:                       # a deletion (value cleared) — drop it
                if self.jar.pop(name, None) is not None:
                    changed.append(name)
                continue
            if self.jar.get(name) != value:
                self.jar[name] = value
                changed.append(name)
            if any(h in name.lower() for h in _SESSION_COOKIE_HINTS):
                persist_rows.append({"name": name, "value": value,
                                     "source_url": self.source_url,
                                     "obtained_at": datetime.now(timezone.utc).isoformat()})
        if persist and persist_rows:
            try:
                from core import session as _sess
                _sess.update_known_assets("session_cookies", persist_rows)
            except Exception:
                pass
        return changed
