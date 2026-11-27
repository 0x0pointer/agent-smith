"""Smith lifecycle + watchdog diagnostic routes."""
from __future__ import annotations

import logging

from fastapi import Request
from fastapi.responses import JSONResponse

import core.api_server as _api
from core.api_server.smith import idle as _idle

from ._common import router

_log = logging.getLogger(__name__)


# ── Smith lifecycle ─────────────────────────────────────────────────────────

def _run_agent_status(run_id: str) -> dict:
    """Agent status for a dashboard-started run (its own worker process)."""
    from control_plane import orchestrator

    state = orchestrator.run_agent_state(run_id)
    return {
        "running": state["alive"],
        "adjudicating": False,
        "heartbeat_age_s": None,
        "idle": state["idle"],
        "agent_idle": ({"since": state.get("idle_since") or "", "reason": "exited",
                        "detail": "Smith ended its turn and exited."} if state["idle"] else None),
        "auto_resume": False,
        "work": _run_work(run_id),
    }


def _run_work(run_id: str) -> dict:
    try:
        from control_plane import work_queue

        w = work_queue.summary(run_id)
        return {"queued": w["queued"], "running": w["running"]}
    except Exception:
        return {"queued": 0, "running": None}


@router.get("/api/smith-status")
async def api_smith_status(request: Request) -> JSONResponse:
    """Smith liveness + activity heartbeat.

    `running` is true if any Smith process exists (incl. an idle interactive one
    sitting at a prompt). `heartbeat_age_s` is how long since the last MCP
    tool-call (quick_log mtime) — the true *activity* signal — and `idle` flags
    when that exceeds the heartbeat window. A live-but-idle Smith (running=true,
    idle=true) is one that has stopped working and is likely awaiting input.
    """
    run_id = getattr(request.state, "run_id", None)
    if run_id:
        try:
            return JSONResponse(_run_agent_status(run_id))
        except Exception:
            return JSONResponse({"running": None, "idle": False, "agent_idle": None})
    import time
    heartbeat_age = None
    try:
        if _api._QUICK_LOG_FILE.exists():
            heartbeat_age = int(time.time() - _api._QUICK_LOG_FILE.stat().st_mtime)
    except OSError:
        pass
    # Soft "stopped working" threshold — deliberately shorter than the watchdog's
    # _SMITH_IDLE_SECONDS respawn grace so the UI can warn before a respawn.
    _HEARTBEAT_IDLE_S = 120
    idle = heartbeat_age is not None and heartbeat_age >= _HEARTBEAT_IDLE_S
    running = _api._smith_running()
    # `adjudicating` lets the UI label a post-complete triage relaunch as
    # "adjudicating" instead of a plain "running" — so a Smith spun back up to
    # re-verify findings isn't mistaken for a hung/stuck scan.
    adjudicating = False
    if running:
        try:
            from core import session as scan_session
            scan_session.load_from_disk(force=True)
            adjudicating = bool((scan_session.get() or {}).get("triage_requested"))
        except Exception:
            pass
    return JSONResponse({
        "running": running,
        "adjudicating": adjudicating,
        "heartbeat_age_s": heartbeat_age,
        "idle": idle,
        # The scan is idle: Smith stopped on its own and nothing was respawned.
        # {since, reason, detail} or null. See core/api_server/smith/idle.py.
        "agent_idle": _idle.read_idle(),
        "auto_resume": _idle.auto_resume_enabled(),
    })


@router.get("/api/smith-clients")
async def api_smith_clients() -> JSONResponse:
    """Return available clients and the auto-detected active one."""
    return JSONResponse({
        "claude":   _api._client_installed("claude"),
        "opencode": _api._client_installed("opencode"),
        "codex":    _api._client_installed("codex"),
        "active":   _api._detect_active_client(),
    })


@router.get("/api/watchdog")
async def api_watchdog_status() -> JSONResponse:
    """Diagnostic: report watchdog state — last restart, count in last hour."""
    import time as _time
    now = _time.time()
    recent = [t for t in _api._watchdog_restart_count_window if now - t < 3600]
    return JSONResponse({
        "enabled": _api._watchdog_task is not None and not (_api._watchdog_task and _api._watchdog_task.done()),
        "last_restart_ago_s": int(now - _api._watchdog_last_restart_ts) if _api._watchdog_last_restart_ts else None,
        "restarts_in_last_hour": len(recent),
        "max_per_hour": _api._WATCHDOG_MAX_PER_HOUR,
        "poll_seconds": _api._WATCHDOG_POLL_SECONDS,
        "min_gap_seconds": _api._WATCHDOG_MIN_GAP_SECONDS,
    })


@router.post("/api/restart-smith")
async def api_restart_smith(request: Request) -> JSONResponse:
    """Spawn a new Smith process (claude or opencode) to continue the active scan.

    Body: {"client": "claude" | "opencode", "force": bool}

    Builds a recovery prompt that includes any pending HUMAN_STEER directives
    so Smith acts on them immediately after recovering its position.
    Blocked when Smith is already running to prevent duplicate sessions.
    """
    try:
        body = await request.json() if request.headers.get("content-length") else {}
    except Exception:
        body = {}
    force = bool(body.get("force", False))
    run_id = getattr(request.state, "run_id", None)
    if run_id:
        # A dashboard-started run has its own worker process: resume THAT.
        try:
            from control_plane import orchestrator
            from .runs_routes import _public_resume_result
            return JSONResponse({"ok": True, **_public_resume_result(orchestrator.resume_run(run_id))})
        except (KeyError, ValueError):
            return JSONResponse({"ok": False, "error": "run not found"}, status_code=404)
        except Exception:
            _log.exception("api_restart_smith: could not resume run")
            return JSONResponse({"ok": False, "error": "could not resume the scan"}, status_code=500)
    if not force and _api._smith_running():
        return JSONResponse({"ok": False, "error": "Smith is already running. Pass force=true to override."}, status_code=409)
    client = (body.get("client") or _api._detect_active_client()).lower()
    if client not in _api._KNOWN_CLIENTS:
        return JSONResponse({"ok": False, "error": f"Unknown client: {client}"}, status_code=400)
    if not _api._client_installed(client):
        return JSONResponse(
            {"ok": False, "error": f"{client} is not installed on this host"},
            status_code=400,
        )

    ok, result = await _api._spawn_smith(client, source="api")
    if ok:
        return JSONResponse({"ok": True, "pid": result, "client": client})
    return JSONResponse({"ok": False, "error": str(result)}, status_code=500)
