"""
The watchdog state machine: detect a dead/hung/stalled Smith mid-scan and
respawn it (or escalate) under a guard gauntlet.

``_watchdog_tick`` routes the detectors and the respawn hand-off through the
parent (``_api.<name>``) so the dashboard's tests can patch any one of them;
sibling notify/respawn helpers and the no-progress counter go through the
package object (``_smith.<name>``). Tuning constants are imported directly.
"""
from __future__ import annotations

import asyncio

import core.api_server as _api
import core.api_server.smith as _smith

from ._common import _log, _SMITH_IDLE_SECONDS, _SMITH_STALL_SECONDS


def _watchdog_notify(title: str, body: str, code: str) -> None:
    """Best-effort out-of-band notification — never breaks the watchdog loop."""
    try:
        from core import notifiers as _nfr
        _nfr.notify(title=title, body=body, urgency="high", code=code)
    except Exception:
        pass


async def _watchdog_respawn_flow(now: float) -> None:
    """Respawn Smith (or escalate) after it stopped while the scan is running.

    Runs the guard gauntlet — MCP alive, min-gap, per-hour cap, no-progress
    backoff — then spawns a fresh client. Each guard that blocks notifies the
    operator and returns. Extracted from _watchdog_tick to keep both readable.
    """
    _smith._watchdog_notify(
        "Smith stopped while scan running",
        "Watchdog detected Smith exited with the scan still marked running. Auto-restart will "
        "fire if MCP is alive and the per-hour cap allows. Check the dashboard if it stays stuck.",
        "WATCHDOG_SMITH_STOPPED",
    )
    if not _api._mcp_sse_alive():
        _log.warning("watchdog suppressed: MCP SSE server unreachable on 127.0.0.1:7778")
        _smith._watchdog_notify(
            "MCP SSE server unreachable",
            "Watchdog can't restart Smith because the MCP server on 127.0.0.1:7778 isn't "
            "responding. Restart it with `./installers/start-mcp-server.sh start`.",
            "WATCHDOG_MCP_DOWN",
        )
        return
    if now - _api._watchdog_last_restart_ts < _api._WATCHDOG_MIN_GAP_SECONDS:
        return
    _api._watchdog_restart_count_window[:] = [
        t for t in _api._watchdog_restart_count_window if now - t < 3600
    ]
    if len(_api._watchdog_restart_count_window) >= _api._WATCHDOG_MAX_PER_HOUR:
        _log.warning("watchdog suppressed: %d restarts in last hour exceeds cap %d",
                     len(_api._watchdog_restart_count_window), _api._WATCHDOG_MAX_PER_HOUR)
        _smith._watchdog_notify(
            "Smith respawn cap reached",
            f"Watchdog gave up after {len(_api._watchdog_restart_count_window)} restarts in the "
            f"last hour (cap {_api._WATCHDOG_MAX_PER_HOUR}). Scan is stuck — intervene from the dashboard.",
            "WATCHDOG_RESPAWN_CAP",
        )
        return
    # No-progress backoff — escalate to a human instead of respawning into the
    # same dead end (the recovery→list→exit loop that burned the model every 2 min).
    if _api._watchdog_should_escalate_no_progress():
        _log.warning("watchdog: %d respawns with no progress — pausing for human (HIR_NO_PROGRESS)",
                     _smith._watchdog_no_progress_count)
        _api._escalate_no_progress_hir()
        return
    client = _api._detect_active_client()
    _log.info("watchdog: smith stopped while scan running — auto-restart")
    ok, result = await _api._spawn_smith(client, source="watchdog")
    if ok:
        _api._watchdog_last_restart_ts = now
        _api._watchdog_restart_count_window.append(now)
        _smith._last_spawn_failure = ""   # live respawn — clear any prior failure reason
        _log.info("watchdog: spawned pid=%d", int(result) if isinstance(result, int) else 0)
    else:
        # Record the child's own exit reason so the no-progress HIR can report the
        # REAL cause (out-of-usage / credit / auth) instead of the generic
        # "agent keeps exiting without testing".
        _smith._last_spawn_failure = str(result)
        # The child died on launch (bad/empty auth, "Credit balance is too low",
        # missing binary). Count it against the min-gap so we don't hot-loop, and
        # surface the child's REAL exit reason to the operator — otherwise the
        # no-progress fingerprint would relabel a billing/auth failure as a coverage
        # dead-end (HIR_NO_PROGRESS) and hide the actual fix.
        _api._watchdog_last_restart_ts = now
        _log.warning("watchdog: respawn failed to stay alive — %s", result)
        _smith._watchdog_notify(
            "Smith respawn failed to start",
            f"Watchdog relaunched {client} but it exited immediately: {result}. "
            "If this says 'Credit balance is too low', the headless respawn is billing an "
            "API key (from .env) instead of your Claude subscription — unset ANTHROPIC_API_KEY "
            "for the server, add API credit, or set SMITH_SPAWN_USE_API_KEY=1 intentionally.",
            "WATCHDOG_RESPAWN_FAILED",
        )


def _kill_stalled_or_hung(hung_pid, stalled_pid) -> None:
    """Notify + kill a hung/stalled Smith process; the caller then falls through to
    the respawn flow. `hung_pid is None` distinguishes a stall (loop exited mid-scan)
    from a hang (process alive but no MCP heartbeat) for the log/notification wording
    and dedup key."""
    kill_pid = hung_pid or stalled_pid
    is_stall = hung_pid is None
    idle_desc = (
        f"agent loop exited mid-scan (idle > {_SMITH_STALL_SECONDS // 60} min, "
        "not generating, cells still pending)"
        if is_stall else
        f"no MCP heartbeat in {_SMITH_IDLE_SECONDS // 60} min"
    )
    _log.warning(
        "watchdog: %s Smith pid=%d — killing + respawning (%s)",
        "stalled" if is_stall else "hung", kill_pid, idle_desc,
    )
    _smith._watchdog_notify(
        ("Smith stalled — agent loop exited mid-scan" if is_stall
         else "Smith hung — process alive but no progress"),
        f"Watchdog detected pid {kill_pid}: {idle_desc}. Killing it and respawning to "
        "resume the scan. Check the dashboard if it stays stuck.",
        ("WATCHDOG_SMITH_STALLED" if is_stall else "WATCHDOG_SMITH_HUNG"),
    )
    _api._kill_hung_smith(kill_pid)


async def _watchdog_tick(now: float) -> None:
    """Single watchdog tick: restart Smith if all guard conditions pass.

    Fires out-of-band notifications (Telegram/Slack/Discord) at three
    decision points so the operator sees stuck-scan states even when
    they're not watching the dashboard. Each notification has its own
    dedup code so the 30-min BaseNotifier cooldown prevents spam — one
    alert per condition per window, not one per watchdog tick.
    """
    session_data = _api._read_json(_api._SESSION_FILE)
    if session_data.get("status") != "running":
        return
    if (session_data.get("intervention") or {}).get("code"):
        return

    # Hung-process detection runs BEFORE the _smith_running() early-return.
    # A hung opencode/claude keeps _signal_pid_file_alive() and
    # _signal_process_scan_finds_client() returning True (process exists)
    # while quick_log goes stale (no MCP activity). _smith_running() OR's
    # all four signals, so it stays True for a hung process and the old
    # `if _smith_running(): return` masked the hang indefinitely. By
    # checking hang FIRST, we kill the zombie + let the rest of the tick
    # respawn via the normal _spawn_smith() path.
    hung_pid = _api._smith_hung_pid()
    # When not hung (within the 30-min window), also catch a loop that has
    # EXITED mid-scan: alive but idle > _SMITH_STALL_SECONDS, NOT generating, and
    # cells still pending. This respawns in minutes instead of waiting out the
    # blunt 30-min timer, without false-killing a slow generation.
    stalled_pid = _api._smith_stalled_pid() if hung_pid is None else None
    if hung_pid is not None or stalled_pid is not None:
        _kill_stalled_or_hung(hung_pid, stalled_pid)
        # Fall through into the spawn flow — do NOT return early.
    elif _api._smith_exited():
        # Cleanly EXITED mid-scan: process gone, no pid to kill. This branch MUST
        # precede the _smith_running() early-return, because in the 5-30 min window
        # after a clean exit _signal_quick_log_fresh() still reports "alive" off the
        # stale heartbeat — _smith_running() would return True and mask the gone
        # process for the full 30-min idle timer. Logged (the absence of any
        # watchdog log is what made this hard to diagnose) then fall through to the
        # respawn flow, which fires WATCHDOG_SMITH_STOPPED. No kill needed.
        _log.warning(
            "watchdog: Smith cleanly exited mid-scan (process gone, idle > %d min, "
            "cells pending) — respawning instead of waiting out the 30-min idle timer",
            _SMITH_STALL_SECONDS // 60,
        )
    elif _api._smith_running():
        return
    # Smith is stopped (or just killed) while the scan is still running — hand
    # off to the respawn flow (notify → MCP/gap/cap/no-progress guards →
    # spawn-or-escalate). Extracted from this tick so each stays readable and
    # under the cognitive-complexity budget; the WATCHDOG_SMITH_STOPPED dedup
    # key is distinct from the HUNG/STALLED key fired above, so both alerts
    # land for a hang event (operator sees "hung, killing" then "restarting").
    await _smith._watchdog_respawn_flow(now)


async def _smith_watchdog_loop() -> None:
    """Background task: auto-restart Smith when it dies mid-scan.

    Conditions for an auto-restart:
      - session.status == "running"
      - no active intervention (HIR_*) — human still needs to resolve
      - Smith process is not alive (per _smith_running)
      - at least _WATCHDOG_MIN_GAP_SECONDS since the last auto-restart
      - fewer than _WATCHDOG_MAX_PER_HOUR restarts in the trailing hour

    Idle when status != "running" or session is gone. Runs forever as long
    as the dashboard process lives. Safety cap prevents storms when Smith
    dies immediately on startup repeatedly (e.g. config error).
    """
    import time as _time
    while True:
        try:
            await asyncio.sleep(_api._WATCHDOG_POLL_SECONDS)
            # Keep the MCP SSE daemon alive FIRST, every tick, regardless of
            # scan status — _watchdog_tick early-returns when no scan is running,
            # but the operator still needs MCP up to start the next one.
            await _api._ensure_mcp_sse_alive(_time.time())
            await _api._watchdog_tick(_time.time())
        except asyncio.CancelledError:
            raise
        except Exception:
            _log.exception("watchdog loop error (continuing)")
