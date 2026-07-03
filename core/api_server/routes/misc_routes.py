"""QA / steering / metrics / logs read routes."""
from __future__ import annotations

import json
import logging

from fastapi.responses import JSONResponse

import core.api_server as _api

from ._common import router

_log = logging.getLogger(__name__)


# ── QA / steering / metrics / logs ──────────────────────────────────────────

@router.get("/api/qa")
async def api_qa() -> JSONResponse:
    return JSONResponse(_api._read_json(_api._QA_STATE_FILE))


@router.get("/api/steering")
async def api_steering() -> JSONResponse:
    return JSONResponse(_api._read_json(_api._STEERING_FILE))


@router.get("/api/adjudication-log")
async def api_adjudication_log() -> JSONResponse:
    try:
        from core.adjunction.log import read_all
        return JSONResponse(read_all())
    except Exception:
        return JSONResponse([])


@router.get("/api/metrics")
async def api_metrics() -> JSONResponse:
    import core.metrics as metrics_mod
    return JSONResponse(metrics_mod.load_all())


@router.get("/api/quicklog")
async def api_quicklog() -> JSONResponse:
    if not _api._QUICK_LOG_FILE.exists():
        return JSONResponse([])
    entries: list[dict] = []
    for line in _api._QUICK_LOG_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                entries.append(json.loads(line))
            except Exception:
                pass
    return JSONResponse(entries)


@router.get("/api/logs")
async def api_logs(file: str = "") -> JSONResponse:
    from core.logger import log_path, _LOG_DIR
    try:
        log_paths = sorted(_LOG_DIR.glob("*.log"), key=lambda p: p.name, reverse=True)
        all_files = [p.name for p in log_paths]
        # Resolve target from trusted glob results — never construct a path
        # from the user-supplied `file` string directly.
        if file:
            target = next((p for p in log_paths if p.name == file), None)
            if target is None:
                return JSONResponse({"lines": [], "files": all_files, "error": "invalid path"})
        else:
            target = log_path
        lines = target.read_text(encoding="utf-8").splitlines() if target.exists() else []
        return JSONResponse({"lines": lines, "file": target.name, "files": all_files})
    except Exception:
        _log.exception("api_logs failed")
        return JSONResponse({"lines": [], "files": [], "error": "failed to read log"})
