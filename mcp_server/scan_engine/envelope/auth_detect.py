"""
Shared HTTP-request auth-signal detectors used by the auth-missing warning
and the quick-log enrichment.
"""
from __future__ import annotations

from typing import Any

# Field names that mark a request body / form / query as a credential-
# validation attempt. Matched generically — no endpoint-name allowlist.
_AUTH_PAYLOAD_FIELDS = (
    "password", "passwd", "pwd", "pass",
    "secret", "client_secret",
    "api_key", "apikey", "access_token", "refresh_token", "id_token",
    "credential", "credentials",
    "otp", "totp", "mfa_code", "code",
)
_AUTH_FIELD_RE = __import__("re").compile(
    r'["\']?(' + "|".join(_AUTH_PAYLOAD_FIELDS) + r')["\']?\s*[:=]',
    __import__("re").IGNORECASE,
)


def _is_zero_status(raw: Any) -> bool:
    """Return True if `raw` represents HTTP status 0 — i.e. no response was
    received (aiohttp/requests exception path).

    Accepts both numeric 0 and the string "0" so we don't silently miss a
    status that was serialized through a JSON round-trip. Anything else
    (including None, malformed strings, real status codes) returns False.
    """
    if raw == 0:
        return True
    if isinstance(raw, str) and raw.strip() == "0":
        return True
    return False


def _is_auth_attempt(ctx: dict) -> bool:
    """True if this http_request looks like a credential validation attempt.

    Generic signals — no URL allowlist, works for any app's naming:
      1. The request body / form / query contains a field name from
         _AUTH_PAYLOAD_FIELDS (password, secret, api_key, otp, ...).
      2. The request URL exactly matches a known auth endpoint discovered
         earlier in the scan (known_assets.auth_endpoints).
    """
    body  = (ctx.get("body") or "")
    query = (ctx.get("query") or "")
    haystack = body + " " + query
    # Auth-bearing request headers should NOT trigger this (we're sending auth, not testing it)
    if _AUTH_FIELD_RE.search(haystack):
        return True
    try:
        from core import session as _sess
        ka = (_sess.get() or {}).get("known_assets", {})
        url = ctx.get("url", "")
        for ep in ka.get("auth_endpoints", []):
            if isinstance(ep, dict) and ep.get("path") and ep["path"] in url:
                return True
    except Exception:
        pass
    return False
