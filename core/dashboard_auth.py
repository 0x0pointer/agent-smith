"""
Per-session dashboard bearer token
===================================
The dashboard (FastAPI on :7777) is a control plane: whoever can call its
mutating routes can steer, complete, or wipe a scan — and ``/api/steer`` feeds
an autonomous, permission-skipping agent. Binding to loopback removes the remote
network reach, but a browser-driven CSRF / DNS-rebind attacker can still reach
``127.0.0.1`` through the operator's own browser. A per-session bearer token
closes that gap: the token lives in the browser's origin-scoped ``sessionStorage``
(a cross-origin or rebound page can neither read it nor set the ``Authorization``
header without a CORS preflight that has no allow), and it is required on every
``/api/*`` call.

Model (matches "new session == new dashboard == new key"):
  - ``mint_token()`` is called when a scan session starts — it generates a fresh
    random token and writes it ``0600`` to ``logs/dashboard.token`` (under the
    already-gitignored ``logs/`` dir; never ``session.json``, which the dashboard
    serves). A new session overwrites it, invalidating the previous dashboard.
  - The dashboard URL is printed with the token in the URL *fragment*
    (``…/#k=<token>``) — a fragment is never sent to the server, so it stays out
    of access logs.
  - The FastAPI middleware validates ``Authorization: Bearer <token>`` per request
    with a constant-time compare.

This is an opaque capability token, not a JWT: a single local server with
per-session state gains nothing from stateless signature validation, and an
opaque token is fewer moving parts (no signing key, no verify library).

NOTE: this is the network / CSRF / rebind boundary. It does NOT stop a
*same-origin* XSS (injected JS in the dashboard origin holds the token) — that is
handled separately by output escaping + sanitization in the dashboard JS.
"""
from __future__ import annotations

import hmac
import os

from core import paths as _paths


def mint_token() -> str:
    """Generate a fresh session token, persist it 0600, and return it.

    Overwrites any previous token so a new scan session invalidates the old
    dashboard. Best-effort: never raises into the caller's start path.
    """
    import secrets

    token = secrets.token_urlsafe(32)
    path = _paths.DASHBOARD_TOKEN_FILE
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Create with 0600 from the start (don't briefly expose the token).
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, token.encode("utf-8"))
        finally:
            os.close(fd)
        try:
            os.chmod(str(path), 0o600)  # tighten if the file pre-existed
        except OSError:
            pass
    except OSError:
        # Filesystem trouble — return the token anyway so the URL still carries
        # it; validation will simply have nothing to compare against (open).
        pass
    return token


def read_token() -> str | None:
    """Return the current session token, or None if none has been minted."""
    try:
        t = _paths.DASHBOARD_TOKEN_FILE.read_text().strip()
        return t or None
    except (OSError, ValueError):
        return None


def verify(supplied: str | None) -> bool:
    """Constant-time compare of a supplied bearer token against the current one."""
    token = read_token()
    if not token or not supplied:
        return False
    return hmac.compare_digest(supplied, token)


def clear() -> None:
    """Remove the token file (e.g. on scan clear)."""
    try:
        _paths.DASHBOARD_TOKEN_FILE.unlink(missing_ok=True)
    except OSError:
        pass
