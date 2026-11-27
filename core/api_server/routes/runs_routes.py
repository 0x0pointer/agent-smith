from __future__ import annotations

import json
import logging

from fastapi import Request
from fastapi.responses import JSONResponse

from control_plane import orchestrator

from ._common import router

_LOG = logging.getLogger(__name__)


def _is_operator(request: Request) -> bool:
    return getattr(request.state, "role", "") == "operator"


def _service_unavailable(action: str, exc: RuntimeError) -> JSONResponse:
    _LOG.warning("runs route %s failed: %s", action, exc)
    return JSONResponse({"error": "service unavailable"}, status_code=503)


@router.get("/api/control-plane")
async def api_control_plane(request: Request) -> JSONResponse:
    """Tell the dashboard which mode it is in.

    ``enabled`` is true when the control-plane database is reachable (multi-run
    platform mode); ``role`` / ``run_id`` describe the caller's token. The UI
    uses this to decide whether to gate the tabs behind selecting a scan — in
    classic single-run mode (no database) nothing is gated.
    """
    from core import db as _db

    return JSONResponse({
        "enabled": _db.get_repository() is not None,
        "role": getattr(request.state, "role", "") or "",
        "run_id": getattr(request.state, "run_id", "") or "",
    })


@router.get("/api/sources")
async def api_sources() -> JSONResponse:
    """Sources (local knowledge bases) a new scan can be bound to.

    Names and localhost URLs from the Source registry (``sources.yaml`` or
    ``SOURCE_REGISTRY``). Read-only; an unreadable registry yields an empty list.
    """
    try:
        from core.sources import list_sources

        sources = [{"name": name, "url": str((meta or {}).get("url") or "")}
                   for name, meta in sorted(list_sources().items())]
    except Exception:
        _LOG.exception("api_sources failed")
        sources = []
    return JSONResponse({"sources": sources})


@router.get("/api/runs")
async def api_runs(request: Request) -> JSONResponse:
    if not _is_operator(request):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    return JSONResponse(orchestrator.list_runs())


@router.post("/api/runs")
async def api_create_run(request: Request) -> JSONResponse:
    if not _is_operator(request):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    try:
        body = await request.json()
        return JSONResponse(orchestrator.create_run(body))
    except json.JSONDecodeError:
        return JSONResponse({"error": "malformed json"}, status_code=400)
    except orchestrator.RunIdCollisionError:
        return JSONResponse({"error": "could not allocate a unique run id, try again"}, status_code=409)
    except ValueError as exc:
        # A fixed message per validation rule — never the exception text itself.
        return JSONResponse({"error": orchestrator.public_validation_error(exc)}, status_code=400)
    except RuntimeError as exc:
        return _service_unavailable("create", exc)


@router.post("/api/runs/{run_id}/token")
async def api_mint_run_token(run_id: str, request: Request) -> JSONResponse:
    if not _is_operator(request):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    try:
        return JSONResponse(orchestrator.mint_existing_run_token(run_id))
    except KeyError:
        return JSONResponse({"error": "run not found"}, status_code=404)
    except RuntimeError as exc:
        return _service_unavailable("mint_token", exc)


@router.post("/api/runs/{run_id}/resume")
async def api_resume_run(run_id: str, request: Request) -> JSONResponse:
    """Start an idle run's agent again (operator, or that run's own token)."""
    role = getattr(request.state, "role", "")
    token_run_id = getattr(request.state, "run_id", "")
    if role != "operator" and token_run_id != run_id:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    try:
        return JSONResponse(_public_resume_result(orchestrator.resume_run(run_id)))
    except KeyError:
        return JSONResponse({"error": "run not found"}, status_code=404)
    except orchestrator.UnsafeRunPath:
        return JSONResponse({"error": "run not found"}, status_code=404)
    except RuntimeError as exc:
        return _service_unavailable("resume", exc)


def _public_resume_result(result: dict) -> dict:
    """The fields of a resume result that are safe and useful to a client."""
    body = {"run_id": str(result.get("run_id") or ""), "resumed": bool(result.get("resumed"))}
    if result.get("pid"):
        body["pid"] = int(result["pid"])
    if not body["resumed"]:
        body["reason"] = "already running" if result.get("reason") == "already running" else "run is not active"
    return body


def _may_access_run(request: Request, run_id: str) -> bool:
    return getattr(request.state, "role", "") == "operator" or getattr(request.state, "run_id", "") == run_id


@router.get("/api/runs/{run_id}/work")
async def api_run_work(run_id: str, request: Request) -> JSONResponse:
    """The run's work queue: items waiting, the one in progress, and history."""
    if not _may_access_run(request, run_id):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    from control_plane import work_queue

    return JSONResponse(work_queue.summary(run_id))


@router.post("/api/runs/{run_id}/work")
async def api_enqueue_run_work(run_id: str, request: Request) -> JSONResponse:
    """Queue a work item for the run. Body: {"title": "...", "text": "..."}.

    Operator only. This is also the push entry point for an integration (e.g. a
    PR scanner) that wants Smith to test something specific: the item waits in
    the queue and is handed to the run when it is idle.
    """
    if not _is_operator(request):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    from control_plane import work_queue

    try:
        body = await request.json()
        if not isinstance(body, dict) or not str(body.get("text") or body.get("title") or "").strip():
            return JSONResponse({"error": "title or text required"}, status_code=400)
        item_id = work_queue.enqueue_manual(run_id, body.get("title", ""), body.get("text", ""))
    except json.JSONDecodeError:
        return JSONResponse({"error": "malformed json"}, status_code=400)
    except KeyError:
        return JSONResponse({"error": "run not found"}, status_code=404)
    except RuntimeError as exc:
        return _service_unavailable("enqueue_work", exc)
    # Start it right away if the run is idle.
    try:
        work_queue.tick()
    except Exception:
        _LOG.exception("work tick after enqueue failed")
    return JSONResponse({"queued": item_id is not None, "id": item_id})


@router.post("/api/runs/{run_id}/stop")
async def api_stop_run(run_id: str, request: Request) -> JSONResponse:
    role = getattr(request.state, "role", "")
    token_run_id = getattr(request.state, "run_id", "")
    if role != "operator" and token_run_id != run_id:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    try:
        result = orchestrator.stop_run(run_id)
    except RuntimeError as exc:
        return _service_unavailable("stop", exc)
    # Cleanup failures carry process/docker error text: report only that cleanup
    # was incomplete (the details are in the server log).
    body = {"run_id": str(result.get("run_id") or ""), "status": "stopped"}
    if result.get("cleanup_errors"):
        body["cleanup_incomplete"] = True
    return JSONResponse(body)
