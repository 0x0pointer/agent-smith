"""QA / steering / metrics / logs read routes."""
from __future__ import annotations

import json
import logging
from pathlib import Path

from fastapi import Request
from fastapi.responses import JSONResponse

import core.api_server as _api

from ._common import router

_log = logging.getLogger(__name__)


# ── QA / steering / metrics / logs ──────────────────────────────────────────

@router.get("/api/qa")
async def api_qa(request: Request) -> JSONResponse:
    run_id = getattr(request.state, "run_id", None)
    if run_id:
        from core import db as _db
        data = _db.load_snapshot("qa", run_id=run_id)
        return JSONResponse(data if isinstance(data, dict) else {"alerts": [], "history": []})
    return JSONResponse(_api._read_json(_api._QA_STATE_FILE))


@router.get("/api/steering")
async def api_steering(request: Request) -> JSONResponse:
    run_id = getattr(request.state, "run_id", None)
    if run_id:
        from core import db as _db
        data = _db.load_snapshot("steering", run_id=run_id)
        return JSONResponse(data if isinstance(data, dict) else {"directives": []})
    return JSONResponse(_api._read_json(_api._STEERING_FILE))


def _run_root(request: Request) -> Path | None:
    """Workdir of the scan this request is scoped to.

    ``None`` means "not run-scoped" (classic single-run mode, or an operator
    token): the caller falls back to the process-wide files. A run-scoped token
    whose run has no workdir on record resolves to a path that does not exist,
    so the caller serves nothing rather than leaking another scan's logs.
    """
    run_id = getattr(request.state, "run_id", None)
    if not run_id:
        return None
    from core import db as _db

    row = _db.get_run(run_id)
    workdir = (row or {}).get("workdir")
    return Path(workdir) if workdir else Path("/nonexistent") / str(run_id)


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    entries: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                entries.append(json.loads(line))
            except Exception:
                pass
    return entries


@router.get("/api/adjudication-log")
async def api_adjudication_log(request: Request) -> JSONResponse:
    try:
        root = _run_root(request)
        if root is not None:
            return JSONResponse(_read_jsonl(root / _api._paths.ADJUDICATION_LOG_FILE.name))
        from core.adjunction.log import read_all
        return JSONResponse(read_all())
    except Exception:
        return JSONResponse([])


@router.get("/api/metrics")
async def api_metrics() -> JSONResponse:
    import core.metrics as metrics_mod
    return JSONResponse(metrics_mod.load_all())


@router.get("/api/quicklog")
async def api_quicklog(request: Request) -> JSONResponse:
    root = _run_root(request)
    path = (root / _api._QUICK_LOG_FILE.name) if root is not None else _api._QUICK_LOG_FILE
    return JSONResponse(_read_jsonl(path))


def _artifacts_dir(request: Request) -> Path:
    root = _run_root(request)
    return (root / _api._paths.ARTIFACTS_DIR.name) if root is not None else _api._paths.ARTIFACTS_DIR


@router.get("/api/tool-results")
async def api_tool_results(request: Request) -> JSONResponse:
    """What each tool found in this scan: parsed, de-duplicated results per tool."""
    try:
        from core import tool_results
        from .findings_routes import _scoped_data

        root = _run_root(request)
        quick_path = (root / _api._QUICK_LOG_FILE.name) if root is not None else _api._QUICK_LOG_FILE
        session = _scoped_data(request, "session", _api._SESSION_FILE)
        known = session.get("known_assets") if isinstance(session, dict) else None
        return JSONResponse(tool_results.summarize(_artifacts_dir(request), _read_jsonl(quick_path), known))
    except Exception:
        _log.exception("api_tool_results failed")
        return JSONResponse({"overview": {}, "tools": [], "total_runs": 0, "error": "failed to read tool results"})


@router.get("/api/tool-results/raw")
async def api_tool_result_raw(request: Request, id: str = "") -> JSONResponse:
    """Raw (secret-redacted, bounded) output of one tool run."""
    try:
        from core import tool_results

        doc = tool_results.read_artifact(_artifacts_dir(request), id)
    except Exception:
        _log.exception("api_tool_result_raw failed")
        doc = None
    if doc is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse(doc)


@router.get("/api/logs")
async def api_logs(request: Request, file: str = "") -> JSONResponse:
    from core.logger import log_path, _LOG_DIR
    try:
        # A run-scoped token reads that run's own logs directory.
        root = _run_root(request)
        if root is not None:
            _LOG_DIR = root / "logs"
            log_path = _LOG_DIR / "pentest.log"
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
