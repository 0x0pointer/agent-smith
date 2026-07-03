"""Scan-state mutation routes: clear, tunnels, intervention, steering."""
from __future__ import annotations

import logging

from fastapi import Request
from fastapi.responses import JSONResponse

import core.api_server as _api

from ._common import router

_log = logging.getLogger(__name__)


# ── Scan-state mutation ─────────────────────────────────────────────────────

@router.delete("/api/clear")
async def api_clear() -> JSONResponse:
    """Wipe all scan state — findings, session, coverage, logs, quick_log, qa_state."""
    from core.findings import _save

    # findings.json
    _save({"meta": {"created": "", "target": ""}, "findings": [], "diagrams": []})

    # coverage_matrix.json — reset to empty (keep the file so /api/coverage returns valid JSON)
    try:
        from core.coverage import reset as _reset_coverage
        await _reset_coverage()
    except Exception:
        pass

    _RECOVERY_SNAP = _api._REPO_ROOT / "recovery_latest.json"
    _METRICS_FILE  = _api._REPO_ROOT / "pentest_metrics.jsonl"
    # _COVERAGE_FILE is intentionally omitted — reset() above already wrote the empty state.
    # Deleting it would cause /api/coverage to return {} instead of an empty-but-valid matrix.
    # _SMITH_PID_FILE + _SMITH_CLIENT_FILE are scan-tied pointers — a stale
    # PID from the previous scan biases _detect_active_client() toward the old
    # client and clutters smith-status diagnostics for the next scan.
    for path in (_api._SESSION_FILE, _api._QUICK_LOG_FILE, _api._QA_STATE_FILE,
                 _api._COST_FILE, _api._STEERING_FILE, _RECOVERY_SNAP, _METRICS_FILE,
                 _api._SMITH_PID_FILE, _api._SMITH_CLIENT_FILE):
        _api._safe_unlink(path)

    # log files in logs/
    try:
        from core.logger import _LOG_DIR
        _api._clear_log_files(_LOG_DIR)
    except Exception:
        pass

    # pocs/ — clear .http files so PoC count doesn't bleed between sessions
    try:
        pocs_dir = _api._REPO_ROOT / "pocs"
        if pocs_dir.exists():
            for poc_file in pocs_dir.glob("*.http"):
                _api._safe_unlink(poc_file)
    except Exception:
        pass

    # artifacts/ — raw scanner output files
    _api._clear_dir_files(_api._REPO_ROOT / "artifacts")

    # threat-model/ — generated HTML/MD reports
    _api._clear_dir_files(_api._REPO_ROOT / "threat-model")

    # gh-issues.md — exported GitHub issue blocks
    _api._safe_unlink(_api._REPO_ROOT / "gh-issues.md")

    await _api._cleanup_tunnels()
    return JSONResponse({"ok": True})


@router.delete("/api/tunnels")
async def api_cleanup_tunnels() -> JSONResponse:
    """Kill chisel tunnels in Kali. Remote clients disconnect automatically."""
    result = await _api._cleanup_tunnels()
    return JSONResponse({"ok": True, "message": result})


@router.get("/api/intervention")
async def api_intervention() -> JSONResponse:
    """Return current HIR state if the scan is paused, else {active: false}.

    Force-reloads from disk: the MCP process (separate from this dashboard
    uvicorn process) writes session.json on every tool call, so our cached
    _current would otherwise stay stuck on the snapshot taken at startup.
    """
    try:
        from core import session as scan_session
        scan_session.load_from_disk(force=True)
        iv = scan_session.get_intervention()
        if iv:
            return JSONResponse({"active": True, **iv})
    except Exception:
        pass
    return JSONResponse({"active": False})


@router.post("/api/intervention/respond")
async def api_intervention_respond(request: Request) -> JSONResponse:
    """Human responds to an HIR event from the dashboard.

    Body: {"choice": "ACCEPT_PARTIAL", "message": "optional free text"}
    Transitions scan back to running and injects a steering directive for Smith.
    """
    try:
        body   = await request.json()
        choice  = str(body.get("choice", "")).strip()
        message = str(body.get("message", "")).strip()
        if not choice and not message:
            return JSONResponse({"ok": False, "error": "choice or message required"}, status_code=400)
        from core import session as scan_session
        from core.steering import steering_queue, RESUME_REQUIRED
        # Force-reload before mutating — see api_intervention docstring for why.
        scan_session.load_from_disk(force=True)
        scan_session.resolve_intervention(choice, message)
        human_instruction = f"Human resolved HIR — choice='{choice}'" + (f": {message}" if message else "")
        steering_queue.add_directive(
            code=RESUME_REQUIRED,
            message=(
                f"HUMAN RESPONSE: {human_instruction}. "
                "Act on this instruction now, then continue the scan."
            ),
            priority="high",
            skill=None,
            trigger="HIR_RESOLVED",
        )
        return JSONResponse({"ok": True, "resumed": True, "instruction": human_instruction})
    except Exception:
        _log.exception("api_intervention_respond failed")
        return JSONResponse({"ok": False, "error": _api._ERR_REQUEST_FAILED}, status_code=500)


@router.post("/api/steer")
async def api_steer(request: Request) -> JSONResponse:
    """Human sends a free-form steering instruction outside of an HIR event.

    Creates a high-priority steering directive so Smith sees it on the next tool call.
    Body: {"message": "..."}
    """
    try:
        body    = await request.json()
        message = str(body.get("message", "")).strip()
        if not message:
            return JSONResponse({"ok": False, "error": "message required"}, status_code=400)
        from core.steering import steering_queue, RESUME_REQUIRED
        steering_queue.add_directive(
            code=RESUME_REQUIRED,
            message=f"HUMAN INSTRUCTION: {message}",
            priority="high",
            skill=None,
            trigger="HUMAN_STEER",
            force=True,  # human instructions always go through — never deduped
        )
        return JSONResponse({"ok": True})
    except Exception:
        _log.exception("api_steer failed")
        return JSONResponse({"ok": False, "error": _api._ERR_REQUEST_FAILED}, status_code=500)
