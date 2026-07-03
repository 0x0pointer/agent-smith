"""Manual-setup gate routes: elect + recheck."""
from __future__ import annotations

import logging

from fastapi import Request
from fastapi.responses import JSONResponse

import core.api_server as _api
import core.api_server.routes as _routes  # for _wake_smith_if_idle (patch-transparent)

from ._common import router

_log = logging.getLogger(__name__)


@router.post("/api/setup-gates/{gate_id}/elect")
async def api_setup_gate_elect(gate_id: str, request: Request) -> JSONResponse:
    """Operator elects a manual-setup gate: now | defer | skip.

    Body: {"choice": "now|defer|skip"}. Non-blocking — election just records the
    operator's decision; it never completes or blocks the scan.
    """
    try:
        body = await request.json()
        choice = str(body.get("choice", "")).strip()
        if choice not in ("now", "defer", "skip"):
            return JSONResponse({"ok": False, "error": "choice must be now|defer|skip"}, status_code=400)
        from core import session as scan_session
        scan_session.load_from_disk(force=True)
        gate = scan_session.record_election(gate_id, choice)
        if not gate:
            return JSONResponse({"ok": False, "error": "gate not found"}, status_code=404)
        return JSONResponse({"ok": True, "gate": gate})
    except Exception:
        _log.exception("api_setup_gate_elect failed")
        return JSONResponse({"ok": False, "error": _api._ERR_REQUEST_FAILED}, status_code=500)


@router.post("/api/setup-gates/{gate_id}/recheck")
async def api_setup_gate_recheck(gate_id: str) -> JSONResponse:
    """Operator re-runs a gate's readiness probe (the "I've set it up — verify" button).

    On a pass that clears a DEFERRED gate, wake Smith so it resumes the gated
    work — this is the headless re-check actuator (closes PLAN_REVIEW_GAPS G08).
    Smith's own subsequent MCP `check` produces the audit artifact; this operator
    path just flips state and nudges.
    """
    try:
        from core import session as scan_session, probe_runner
        scan_session.load_from_disk(force=True)
        gate = scan_session.setup_gate_by_id(gate_id)
        if not gate:
            return JSONResponse({"ok": False, "error": "gate not found"}, status_code=404)
        was_deferred = gate.get("election") == "defer"
        out = await probe_runner.check_gate(gate_id)  # artifact_store=None in the dashboard process
        woke = False
        if out["status"] == "ok" and was_deferred:
            woke = await _routes._wake_smith_if_idle()

        # Do not expose raw probe execution output/error details to remote clients.
        probe_result = out.get("result")
        safe_probe = None
        if isinstance(probe_result, dict):
            safe_probe = dict(probe_result)
            safe_probe["stdout"] = ""
            safe_probe["stderr"] = ""
            if safe_probe.get("error"):
                safe_probe["error"] = _api._ERR_REQUEST_FAILED

        return JSONResponse({
            "ok": True, "status": out["status"], "gate": out["gate"],
            "probe": safe_probe, "smith_woken": woke,
        })
    except Exception:
        _log.exception("api_setup_gate_recheck failed")
        return JSONResponse({"ok": False, "error": _api._ERR_REQUEST_FAILED}, status_code=500)
