"""
Shared plumbing for the dashboard routes package.

All route handlers register on the single :data:`router` here (included onto
the FastAPI ``app`` by ``core.api_server`` at import time). Handlers reach
shared state, helpers, and the Smith-supervision functions through the
package (the ``_api`` alias) so the dashboard's tests can patch any of them.

``_wake_smith_if_idle`` lives here (not in a route module) because two route
groups call it and the tests patch it as ``core.api_server.routes._wake_smith_if_idle``
— callers therefore reference it via the package namespace at call time.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter

import core.api_server as _api

_log = logging.getLogger(__name__)

router = APIRouter()


async def _wake_smith_if_idle() -> bool:
    """Spawn a fresh Smith run iff no live Smith process exists.

    A queued steering directive is inert: it reaches Smith only by riding the
    envelope on Smith's *next* tool call. When the operator triggers triage,
    Smith has usually gone quiet — its non-interactive `claude -p` /
    `opencode run` turn has exited — so no tool call ever consumes the directive
    and the pass never starts. The watchdog won't help promptly either (it keeps
    Smith "alive" for the full _SMITH_IDLE_SECONDS quick_log grace before
    respawning).

    So if no live Smith *process* exists we spawn one now; its recovery prompt
    appends steering_queue.get_active(), delivering the directive verbatim
    (client-agnostic via _detect_active_client). We gate on process liveness,
    NOT quick_log freshness — a just-exited `-p` turn leaves a <grace quick_log
    yet has no process to consume the directive. When a live process IS present
    we abstain: a looping Smith picks the directive up on its next call, and a
    second `-p` Smith alongside a live one would dual-write state.
    """
    try:
        smith_alive = (
            _api._signal_pid_file_alive()
            or _api._signal_process_scan_finds_client()
        )
        if smith_alive:
            return False
        client = _api._detect_active_client()
        if _api._client_installed(client):
            ok, _result = await _api._spawn_smith(client, source="api")
            return bool(ok)
    except Exception:
        # Never fail the request on a spawn error — the directive is still
        # queued and the watchdog remains a fallback.
        _log.exception("triage wake-spawn failed")
    return False
