"""Scan completion + triage lifecycle routes."""
from __future__ import annotations

import logging

from fastapi import Request
from fastapi.responses import JSONResponse

import core.api_server as _api
import core.api_server.routes as _routes  # for _wake_smith_if_idle (patch-transparent)

from ._common import router

_log = logging.getLogger(__name__)


@router.post("/api/complete")
async def api_complete(request: Request) -> JSONResponse:
    """Human-triggered scan completion.

    Only this endpoint (called from the dashboard) can mark a scan complete.
    Smith cannot complete a scan autonomously — session(action='complete') is blocked.
    Body: {"notes": "optional completion notes"}

    Completion is unconditional — it does NOT run the adjudication pass. Triaging
    findings is a separate, operator-chosen step via POST /api/triage (the
    "Triage findings" button). This keeps the two decisions independent: review
    findings when you want, finish the scan when you want.

    Side-effect cleanup mirrors Clear All but narrower: scan-tied operational
    pointers (smith.pid, smith.client, quick_log heartbeat) are wiped so the
    dashboard immediately reflects "smith stopped" instead of waiting 5 min
    for the activity signal to age out. Deliverables (findings.json,
    coverage_matrix.json, session.json, artifacts/, pocs/, pentest.log) are
    intentionally preserved — they're the report you'll export from."""
    try:
        from core import session as scan_session
        # Force-reload so we mutate against the freshest disk state, not a
        # cached _current snapshot.
        scan_session.load_from_disk(force=True)
        body  = await request.json()
        notes = str(body.get("notes", "")).strip()

        cfg    = scan_session.complete(notes)
        status = cfg.get("status", "complete")

        # Clean up operational pointers now that the scan is terminal.
        # The watchdog gates on `session.status == "running"`, so flipping
        # to "complete" first (above) means it won't fire a "smith stopped"
        # alert from these deletions.
        for path in (_api._SMITH_PID_FILE, _api._SMITH_CLIENT_FILE, _api._QUICK_LOG_FILE):
            _api._safe_unlink(path)

        return JSONResponse({"ok": True, "status": status})
    except Exception:
        _log.exception("api_complete failed")
        return JSONResponse({"ok": False, "error": _api._ERR_REQUEST_FAILED}, status_code=500)


@router.post("/api/triage")
async def api_triage(request: Request) -> JSONResponse:
    """Operator-triggered adjudication (triage) pass — does NOT complete the scan.

    Injects the senior-review directive for every un-adjudicated in-scope
    finding and wakes Smith if it has gone idle. Smith records a verdict per
    finding, then resumes normal testing — the scan stays open. Completion is a
    separate decision (POST /api/complete).
    """
    try:
        from core import session as scan_session
        scan_session.load_from_disk(force=True)

        try:
            from core.findings import _load as _load_findings
            from core.adjunction import pending_findings
            pending = pending_findings(_load_findings())
        except Exception:
            pending = []

        if not pending:
            return JSONResponse({"ok": True, "status": "nothing_to_triage", "pending_adjudication": 0})
        sess = scan_session.get() or {}
        if not sess.get("target"):
            return JSONResponse({"ok": False, "error": "no scan to triage"}, status_code=409)

        # Triage is now a POST-scan step: it runs against a STOPPED scan and
        # (re)spawns Smith to adjudicate. A running scan is also tolerated (the
        # legacy mid-scan path), but the dashboard only surfaces the button once
        # the scan has stopped. The directive wording branches on that so a
        # terminal-scan triage tells Smith to stop afterwards, not resume.
        terminal = sess.get("status") in (
            "complete", "incomplete_with_unresolved_blockers", "limit_reached",
        )

        scan_session.set_triage_requested(True)

        from core.adjunction.directive import build_adjudication_directive
        from core.steering import steering_queue, RESUME_REQUIRED
        if terminal:
            closing_note = (
                "\n\nNOTE: This is a post-scan TRIAGE pass requested by the human "
                "operator on a STOPPED scan. After you have adjudicated ALL findings "
                "above, STOP — do NOT resume testing and do NOT call "
                "session(action='start'). The scan stays complete."
            )
        else:
            closing_note = (
                "\n\nNOTE: This is a standalone TRIAGE pass requested by the human "
                "operator. After you have adjudicated ALL findings above, DO NOT "
                "complete the scan — resume normal testing where you left off. The "
                "scan stays open."
            )
        directive_body = build_adjudication_directive(pending) + closing_note
        steering_queue.add_directive(
            code=RESUME_REQUIRED,
            message=directive_body,
            priority="high",
            skill=None,
            trigger="TRIAGE_ADJUDICATION",
            force=True,
        )
        try:
            from core.adjunction.log import log_directive
            log_directive(pending)
        except Exception:
            pass

        smith_spawned = await _routes._wake_smith_if_idle()
        return JSONResponse({
            "ok": True,
            "status": "triaging",
            "pending_adjudication": len(pending),
            "smith_spawned": smith_spawned,
        })
    except Exception:
        _log.exception("api_triage failed")
        return JSONResponse({"ok": False, "error": _api._ERR_REQUEST_FAILED}, status_code=500)


@router.post("/api/triage-cancel")
async def api_triage_cancel() -> JSONResponse:
    """Clear an in-flight triage pass — operator escape hatch for the banner.

    Drops the triage_requested flag and removes any un-consumed
    TRIAGE_ADJUDICATION steering directives so the banner disappears and Smith
    won't pick up a stale review directive. Does NOT touch findings or verdicts
    already recorded.
    """
    try:
        from core import session as scan_session
        scan_session.load_from_disk(force=True)
        scan_session.set_triage_requested(False)
        removed = 0
        try:
            from core.steering import steering_queue
            removed = steering_queue.cancel_by_trigger(
                "TRIAGE_ADJUDICATION", "triage cancelled by operator"
            )
            # Also clear legacy force-complete directives, which otherwise have
            # no cleanup path at all and would replay into the next run.
            removed += steering_queue.cancel_by_trigger(
                "FORCE_COMPLETE_ADJUDICATION", "triage cancelled by operator"
            )
        except Exception:
            _log.exception("api_triage_cancel: directive cleanup failed")
        return JSONResponse({"ok": True, "removed_directives": removed})
    except Exception:
        _log.exception("api_triage_cancel failed")
        return JSONResponse({"ok": False, "error": _api._ERR_REQUEST_FAILED}, status_code=500)


@router.post("/api/force-stop")
async def api_force_stop() -> JSONResponse:
    """Hard stop — the "just stop it now" control.

    Unlike /api/complete (which finalizes the session but leaves a
    mid-adjudication Smith still running) and /api/triage-cancel (which only
    drops the triage flag), this flips the session terminal, cancels any triage
    pass, AND kills the running Smith process so it can neither keep working nor
    be respawned by the watchdog. Deliverables (findings, coverage, PoCs) are
    preserved — only the live process + operational pointers are torn down."""
    _reason = "force-stopped by operator"
    try:
        from core import session as scan_session
        scan_session.load_from_disk(force=True)
        # Capture a live Smith PID BEFORE the kill + pointer-wipe below.
        pid = _api._live_pid_from_pid_file() or _api._live_pid_from_process_scan()
        # Force-stop is the operator override — it must finalize from ANY non-terminal
        # state. complete() only transitions from 'running', so a scan wedged in
        # intervention_required (an open HIR — exactly when you most need to kill it)
        # couldn't be stopped at all. Clear the HIR first so complete() flips it terminal.
        if (scan_session.get() or {}).get("status") == "intervention_required":
            scan_session.resolve_intervention("FORCE_STOP", _reason)
        # Terminal status first so the watchdog won't respawn after the kill.
        cfg = scan_session.complete(_reason)
        scan_session.set_triage_requested(False)
        removed = 0
        try:
            from core.steering import steering_queue
            removed = steering_queue.cancel_by_trigger("TRIAGE_ADJUDICATION", _reason)
            removed += steering_queue.cancel_by_trigger("FORCE_COMPLETE_ADJUDICATION", _reason)
        except Exception:
            _log.exception("api_force_stop: directive cleanup failed")
        killed = bool(pid) and _api._kill_hung_smith(pid)
        # _kill_hung_smith clears smith.pid/client on success; wipe the rest too.
        for path in (_api._SMITH_PID_FILE, _api._SMITH_CLIENT_FILE, _api._QUICK_LOG_FILE):
            _api._safe_unlink(path)
        return JSONResponse({
            "ok": True,
            "status": cfg.get("status", "complete"),
            "killed": killed,
            "pid": pid,
            "removed_directives": removed,
        })
    except Exception:
        _log.exception("api_force_stop failed")
        return JSONResponse({"ok": False, "error": _api._ERR_REQUEST_FAILED}, status_code=500)
