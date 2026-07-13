"""
Smith process supervision.

Detects whether a Smith (claude / opencode / codex) is alive, distinguishes a
hung process from a stopped one, resolves which client to (re)spawn, performs
the spawn, and runs the auto-restart watchdog.

These functions call each other — and read the watchdog state/config globals
— through ``core.api_server`` (the ``_api`` alias) or the package object
(``core.api_server.smith``) rather than as locals, so the dashboard's tests can
patch any one of them (e.g. ``_smith_running``, ``_spawn_smith``) and have the
patch observed by every caller.

Split into a package for the <300-lines-per-file convention. This facade keeps
the public import surface identical: ``import core.api_server.smith`` and every
name previously importable from the module resolve here unchanged. The mutable
watchdog counters live here as module globals so external writers and
unittest patches on ``core.api_server.smith.<name>`` target the same object the
submodule functions read/write via ``_smith.``.
"""
from __future__ import annotations

# ── Mutable module-global watchdog state ─────────────────────────────────────
# Kept on the facade (not a submodule) so unittest.mock.patch on
# ``core.api_server.smith.<name>`` and the parent re-export observe the same
# object the submodules mutate via ``_smith.<name>``.
_watchdog_last_progress: tuple | None = None
_watchdog_no_progress_count = 0
# Cumulative per-scan auto-respawn accounting (enforces _WATCHDOG_MAX_PER_SCAN). Keyed
# on the session id so a new scan resets it; stops the operator-terminated-thorough
# runaway where the rolling per-hour cap alone let the watchdog respawn forever.
_watchdog_scan_key: str = ""
_watchdog_scan_restarts = 0
# Progress snapshot (findings, addressed cells) observed at the last watchdog respawn-flow pass.
# The per-scan cap resets whenever the scan ADVANCED since this mark, so the cap counts only
# CONSECUTIVE futile respawns — a healthy long scan that legitimately respawns many times and
# keeps finding things is never suppressed (fixes the "deep scan stalls at 8 respawns" regression).
_watchdog_last_respawn_progress: tuple = ()
# Last respawn-failure reason (the child's own exit line, e.g. an out-of-usage /
# credit / auth message) so the no-progress HIR can report the REAL cause instead
# of the generic "agent keeps exiting without testing". Cleared on a live respawn.
_last_spawn_failure: str = ""
# Restart throttle for the MCP SSE self-heal — reset by tests on this facade.
_mcp_sse_last_restart_ts: float = 0.0

# ── Re-exports (public import surface preserved) ─────────────────────────────
from core.client_patterns import looks_like_smith  # noqa: E402,F401
from ._common import (  # noqa: E402,F401
    _log,
    _SMITH_IDLE_SECONDS,
    _SMITH_STALL_SECONDS,
    _WATCHDOG_MAX_NO_PROGRESS,
    _WATCHDOG_COLD_START_AFTER,
    _WATCHDOG_MAX_PER_SCAN,
    _KNOWN_CLIENTS,
    _SPAWN_SOURCE_TAGS,
    _MCP_SSE_RESTART_MIN_GAP_SECONDS,
    _MCP_LAUNCHD_LABEL,
)
from .signals import (  # noqa: E402,F401
    _signal_pid_file_alive,
    _signal_quick_log_fresh,
    _signal_session_recently_started,
    _signal_process_scan_finds_client,
    _process_matches_smith,
    _smith_running,
    _live_pid_from_pid_file,
    _live_pid_from_process_scan,
    _quick_log_age_seconds,
    _is_loopback,
)
from .health import (  # noqa: E402,F401
    _smith_hung_pid,
    _kill_hung_smith,
    _smith_generating,
    _scan_has_pending_cells,
    _smith_stalled_pid,
    _smith_exited,
)
from .clients import (  # noqa: E402,F401
    _client_installed,
    _client_process_running,
    _resolve_client_from_session,
    _resolve_client_from_smith_client_file,
    _resolve_client_from_running_process,
    _detect_active_client,
)
from .progress import (  # noqa: E402,F401
    _scan_progress_snapshot,
    _watchdog_should_escalate_no_progress,
    _escalate_no_progress_hir,
)
from .spawn import (  # noqa: E402,F401
    _spawn_source_tag,
    _latest_opencode_session,
    _recorded_claude_session,
    _cold_recovery_prompt,
    _resume_prompt,
    _spawn_smith,
)
from .mcp_sse import (  # noqa: E402,F401
    _mcp_sse_alive,
    _launchd_supervises_mcp,
    _ensure_mcp_sse_alive,
)
from .watchdog import (  # noqa: E402,F401
    _watchdog_notify,
    _watchdog_respawn_flow,
    _watchdog_tick,
    _smith_watchdog_loop,
)
