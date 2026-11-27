from __future__ import annotations

import json

from fastapi import Request
from fastapi.responses import JSONResponse

from control_plane import orchestrator

from ._common import router


def _is_operator(request: Request) -> bool:
    return getattr(request.state, "role", "") == "operator"


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
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except orchestrator.RunIdCollisionError as exc:
        return JSONResponse({"error": str(exc)}, status_code=409)
    except RuntimeError as exc:
        return JSONResponse({"error": str(exc)}, status_code=503)


@router.post("/api/runs/{run_id}/stop")
async def api_stop_run(run_id: str, request: Request) -> JSONResponse:
    role = getattr(request.state, "role", "")
    token_run_id = getattr(request.state, "run_id", "")
    if role != "operator" and token_run_id != run_id:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    try:
        return JSONResponse(orchestrator.stop_run(run_id))
    except RuntimeError as exc:
        return JSONResponse({"error": str(exc)}, status_code=503)
