"""
Missing-Authorization warning — injected when an http_request returns 401/403
with no auth attached but valid tokens/credentials exist in known_assets.
"""
from __future__ import annotations

from mcp_server.scan_engine.envelope._common import Envelope
from mcp_server.scan_engine.envelope.auth_detect import _is_auth_attempt


# Headers commonly used by web apps to carry authentication. Authorization
# (JWT bearer / basic / digest), Cookie (session), and any X-*-Token /
# X-*-Auth / X-Api-Key / X-Access-Key variant most APIs adopt.
_AUTH_HEADER_NAMES_LOWER = ("authorization", "cookie", "x-csrf-token")
_AUTH_HEADER_PATTERNS = (
    "auth", "token", "api-key", "apikey", "access-key",
    "session", "credential", "bearer",
)
# Query-string params Smith may have used to embed a token.
_AUTH_QUERY_PATTERNS = ("token", "access_token", "api_key", "apikey", "auth", "session")


def _request_carries_auth(ctx: dict) -> bool:
    """True if the request sent SOME form of authentication.

    Generic across auth styles: JWT bearer, basic, cookies, custom X-* headers,
    or query-string tokens. If none of these are present the 401/403 is most
    likely caused by Smith forgetting auth entirely (vs sending an invalid one).
    """
    headers = ctx.get("headers") or {}
    for k in headers.keys():
        kl = k.lower()
        if kl in _AUTH_HEADER_NAMES_LOWER:
            return True
        if any(p in kl for p in _AUTH_HEADER_PATTERNS):
            return True
    # Query-string auth (e.g. ?token=..., ?access_token=...)
    url = ctx.get("url", "")
    if "?" in url:
        qs = url.split("?", 1)[1].lower()
        if any(f"{p}=" in qs for p in _AUTH_QUERY_PATTERNS):
            return True
    return False


def _inject_missing_auth_warning(env: Envelope, ctx: dict) -> None:
    """When an http_request gets 401/403 and Smith sent NO auth at all but
    valid JWTs/credentials exist in known_assets, prepend an actionable warning
    so Smith retries with the token on the next call.

    Skipped when:
      - response was not 401/403 (auth presumably worked or unrelated error)
      - the request carried any auth form (header, cookie, query token) —
        the token is invalid, not missing
      - this was a credential-validation attempt (login flow)
      - no JWT is yet available in known_assets
    """
    status = env.evidence.get("status", 0) if env.evidence else 0
    if status not in (401, 403):
        return
    if _request_carries_auth(ctx):
        return  # some auth WAS sent; the issue is the value, not absence
    if _is_auth_attempt(ctx):
        return  # legitimate login attempt — 401 is the test signal
    try:
        from core import session as _sess
        sess_data    = _sess.get() or {}
        known_assets = sess_data.get("known_assets", {})
        tokens       = known_assets.get("auth_tokens", [])
        valid_tokens = [t for t in tokens if isinstance(t, dict) and t.get("value")]
        if not valid_tokens:
            return
        url    = ctx.get("url", "")
        method = (ctx.get("method", "GET") or "GET").upper()

        # Smaller models (the user hit this with Qwen3.6-35B-A3B) treat
        # short "try header X" warnings as background noise and burn 7+
        # tool calls retrying naked requests against the same endpoint.
        # The fix is the same shape we used for the envelope budget
        # truncation: embed the EXACT next tool call inline with the
        # full token-reference path. The model can pattern-match on
        # `EXECUTE NOW: http(...)` far more reliably than on a discursive
        # "you should try X, or maybe Y" paragraph.
        #
        # The token reference is `known_assets.auth_tokens[-1].value`
        # (not a truncated literal) because:
        #   1. Models that DO read warnings can resolve the path from
        #      session state directly without us inlining a 700-char JWT
        #      that would blow the envelope budget.
        #   2. The truncated form `eyJ0eXAiOiJK...` previously shown
        #      reads like a complete token to less-careful models, which
        #      then sent the truncated value verbatim and got 401 again.
        creds = known_assets.get("credentials", [])
        auth_endpoints = known_assets.get("auth_endpoints", [])
        cred_hint = ""
        if creds and auth_endpoints:
            ep = auth_endpoints[0]
            cred_hint = (
                f" If the stored token has expired (still 401 after the "
                f"retry above), mint a fresh one: "
                f"http(action='request', method='{ep.get('method','POST')}', "
                f"url='{ep.get('path','')}', "
                f"body={{'username':'{creds[0].get('username','')}', "
                f"'password':'{creds[0].get('password','')}'}}). "
                f"Extract the new JWT from the response and retry."
            )
        message = (
            f"AUTH_MISSING: {method} {url} returned HTTP {status} with NO auth "
            f"attached (no Authorization / Cookie / X-Api-Key / X-Auth-* / "
            f"?token= query). 401/403 with no auth is NOT a test result — "
            f"the server never evaluated your payload. "
            f"EXECUTE NOW: retry the same request with the JWT attached: "
            f"http(action='request', method='{method}', url='{url}', "
            f"headers={{'Authorization': 'Bearer ' + "
            f"known_assets.auth_tokens[-1].value}}). "
            f"({len(valid_tokens)} valid token(s) available; "
            f"newest source: {valid_tokens[-1].get('source_url','unknown')}). "
            f"If 401 persists, the app may use Cookie auth (re-login + reuse "
            f"Set-Cookie) or a custom header like X-Api-Key/X-Auth-Token — try "
            f"those header names with the same JWT value."
            f"{cred_hint}"
            f" DO NOT retry the naked request — every naked retry will return "
            f"401 and burns budget without producing a test result."
        )
        env.warnings.append(message)
        env.summary = f"⚠ {message}\n\n" + env.summary
    except Exception:
        pass  # never break tool dispatch
