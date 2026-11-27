"""Scan completion + triage lifecycle routes."""
from __future__ import annotations

import logging

from fastapi import Request
from fastapi.responses import JSONResponse

import core.api_server as _api
import core.api_server.routes as _routes  # for _wake_smith_if_idle (patch-transparent)

from ._common import router

_log = logging.getLogger(__name__)
_ERR_DB_UNAVAILABLE = "database unavailable"
_TERMINAL_STATUSES = ("complete", "incomplete_with_unresolved_blockers", "limit_reached")
_TRIAGE_CANCELLED_REASON = "triage cancelled by operator"


def _save_run_session(run_id: str, session_doc: dict) -> None:
    from core import db as _db
    repo = _db.get_repository()
    if repo is None:
        raise RuntimeError(_ERR_DB_UNAVAILABLE)
    repo.upsert_run(run_id, session_doc, session_doc.get("workdir", ""))
    repo.save_snapshot(run_id, "session", session_doc)


def _terminal_scan(sess: dict) -> bool:
    return sess.get("status") in _TERMINAL_STATUSES


def _triage_closing_note(terminal: bool) -> str:
    if terminal:
        return (
            "\n\nNOTE: This is a post-scan TRIAGE pass requested by the human "
            "operator on a STOPPED scan. After you have adjudicated ALL findings "
            "above, STOP — do NOT resume testing and do NOT call "
            "session(action='start'). The scan stays complete."
        )
    return (
        "\n\nNOTE: This is a standalone TRIAGE pass requested by the human "
        "operator. After you have adjudicated ALL findings above, DO NOT "
        "complete the scan — resume normal testing where you left off. The "
        "scan stays open."
    )


def _pending_triage_findings(findings_data: dict) -> list[dict]:
    try:
        from core.adjunction import pending_findings

        return pending_findings(findings_data)
    except Exception:
        return []


def _enqueue_triage_directive(pending: list[dict], *, terminal: bool, run_id: str | None = None) -> None:
    from core.adjunction.directive import build_adjudication_directive
    from core.steering import RESUME_REQUIRED, steering_queue

    directive_body = build_adjudication_directive(pending) + _triage_closing_note(terminal)
    steering_queue.add_directive(
        code=RESUME_REQUIRED,
        message=directive_body,
        priority="high",
        skill=None,
        trigger="TRIAGE_ADJUDICATION",
        force=True,
        run_id=run_id,
    )
    try:
        from core.adjunction.log import log_directive

        log_directive(pending)
    except Exception:
        pass


def _cancel_triage_directives(run_id: str | None = None) -> int:
    from core.steering import steering_queue

    removed = steering_queue.cancel_by_trigger(
        "TRIAGE_ADJUDICATION", _TRIAGE_CANCELLED_REASON, run_id=run_id
    )
    return removed + steering_queue.cancel_by_trigger(
        "FORCE_COMPLETE_ADJUDICATION", _TRIAGE_CANCELLED_REASON, run_id=run_id
    )


def _run_scoped_triage(run_id: str) -> JSONResponse:
    from core import db as _db

    repo = _db.get_repository()
    if repo is None:
        return JSONResponse({"ok": False, "error": _ERR_DB_UNAVAILABLE}, status_code=503)
    sess = repo.load_snapshot(run_id, "session") or {}
    pending = _pending_triage_findings(repo.load_snapshot(run_id, "findings") or {"findings": []})
    if not pending:
        return JSONResponse({"ok": True, "status": "nothing_to_triage", "pending_adjudication": 0})
    if not sess.get("target"):
        return JSONResponse({"ok": False, "error": "no scan to triage"}, status_code=409)
    sess["triage_requested"] = True
    _save_run_session(run_id, sess)
    _enqueue_triage_directive(pending, terminal=_terminal_scan(sess), run_id=run_id)
    return JSONResponse({
        "ok": True,
        "status": "triaging",
        "pending_adjudication": len(pending),
        "smith_spawned": False,
    })


async def _single_run_triage() -> JSONResponse:
    from core.findings import _load as _load_findings
    from core import session as scan_session

    scan_session.load_from_disk(force=True)
    pending = _pending_triage_findings(_load_findings())
    if not pending:
        return JSONResponse({"ok": True, "status": "nothing_to_triage", "pending_adjudication": 0})
    sess = scan_session.get() or {}
    if not sess.get("target"):
        return JSONResponse({"ok": False, "error": "no scan to triage"}, status_code=409)
    scan_session.set_triage_requested(True)
    _enqueue_triage_directive(pending, terminal=_terminal_scan(sess))
    smith_spawned = await _routes._wake_smith_if_idle()
    return JSONResponse({
        "ok": True,
        "status": "triaging",
        "pending_adjudication": len(pending),
        "smith_spawned": smith_spawned,
    })


def _run_scoped_triage_cancel(run_id: str) -> JSONResponse:
    from core import db as _db

    repo = _db.get_repository()
    if repo is None:
        return JSONResponse({"ok": False, "error": _ERR_DB_UNAVAILABLE}, status_code=503)
    sess = repo.load_snapshot(run_id, "session") or {"run_id": run_id}
    sess["triage_requested"] = False
    _save_run_session(run_id, sess)
    removed = 0
    try:
        removed = _cancel_triage_directives(run_id)
    except Exception:
        _log.exception("api_triage_cancel: directive cleanup failed")
    return JSONResponse({"ok": True, "removed_directives": removed})


def _single_run_triage_cancel() -> JSONResponse:
    from core import session as scan_session

    scan_session.load_from_disk(force=True)
    scan_session.set_triage_requested(False)
    removed = 0
    try:
        removed = _cancel_triage_directives()
    except Exception:
        _log.exception("api_triage_cancel: directive cleanup failed")
    return JSONResponse({"ok": True, "removed_directives": removed})


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
        run_id = getattr(request.state, "run_id", None) or None
        if run_id:
            return _run_scoped_triage(run_id)
        return await _single_run_triage()
    except Exception:
        _log.exception("api_triage failed")
        return JSONResponse({"ok": False, "error": _api._ERR_REQUEST_FAILED}, status_code=500)


@router.post("/api/triage-cancel")
async def api_triage_cancel(request: Request) -> JSONResponse:
    """Clear an in-flight triage pass — operator escape hatch for the banner.

    Drops the triage_requested flag and removes any un-consumed
    TRIAGE_ADJUDICATION steering directives so the banner disappears and Smith
    won't pick up a stale review directive. Does NOT touch findings or verdicts
    already recorded.
    """
    try:
        run_id = getattr(request.state, "run_id", None) or None
        if run_id:
            return _run_scoped_triage_cancel(run_id)
        return _single_run_triage_cancel()
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
