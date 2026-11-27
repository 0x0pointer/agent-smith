from __future__ import annotations

import os
import shutil
import subprocess
import uuid
from pathlib import Path

from core import dashboard_auth
from core import db as _db
from core import paths as _paths

_DEPTHS = {"recon", "standard", "thorough", "danger"}


def _dashboard_base_url() -> str:
    return "http://127.0.0.1:7777"


def _new_run_id() -> str:
    return f"run-{uuid.uuid4().hex[:8]}"


def _validate(payload: dict) -> tuple[str, str]:
    target = str(payload.get("target") or "").strip()
    depth = str(payload.get("depth") or "standard").strip() or "standard"
    if not target:
        raise ValueError("target required")
    if depth not in _DEPTHS:
        raise ValueError("invalid depth")
    return target, depth


def _workdir_for(run_id: str) -> Path:
    path = Path(_paths.RUNTIME_ROOT) / "runs" / run_id
    path.mkdir(parents=True, exist_ok=True)
    return path


def _spawn_worker(run_id: str, workdir: Path) -> int:
    env = os.environ.copy()
    env["SMITH_RUN_ID"] = run_id
    env["SMITH_WORKDIR"] = str(workdir)
    proc = subprocess.Popen(["python", "-m", "mcp_server"], env=env)
    return int(getattr(proc, "pid", 0) or 0)


def create_run(payload: dict) -> dict:
    target, depth = _validate(payload)
    run_id = _new_run_id()
    workdir = _workdir_for(run_id)
    token = dashboard_auth.mint_run_token(run_id)
    session_doc = {
        "run_id": run_id,
        "target": target,
        "depth": depth,
        "status": "running",
        "workdir": str(workdir),
    }
    repo = _db.get_repository()
    if repo is None:
        raise RuntimeError("database unavailable")
    repo.upsert_run(run_id, session_doc, str(workdir))
    repo.save_snapshot(run_id, "session", session_doc)
    try:
        _spawn_worker(run_id, workdir)
    except Exception:
        session_doc["status"] = "failed"
        repo.upsert_run(run_id, session_doc, str(workdir))
        repo.save_snapshot(run_id, "session", session_doc)
        shutil.rmtree(workdir, ignore_errors=True)
        raise
    return {
        "run_id": run_id,
        "status": "running",
        "dashboard_url": f"{_dashboard_base_url()}/#k={token}",
        "token": token,
    }


def list_runs() -> list[dict]:
    rows = _db.list_runs()
    return [
        {
            "run_id": row.get("run_id"),
            "target": row.get("target"),
            "status": row.get("status"),
            "depth": row.get("depth"),
            "workdir": row.get("workdir"),
        }
        for row in rows
    ]


def stop_run(run_id: str) -> dict:
    repo = _db.get_repository()
    if repo is None:
        raise RuntimeError("database unavailable")
    session_doc = repo.load_snapshot(run_id, "session") or {"run_id": run_id}
    session_doc["status"] = "stopped"
    repo.upsert_run(run_id, session_doc, session_doc.get("workdir", ""))
    repo.save_snapshot(run_id, "session", session_doc)
    return {"run_id": run_id, "status": "stopped"}


def start_control_plane() -> dict:
    return {"status": "started", "database": bool(_db.get_repository()), "dashboard_url": _dashboard_base_url()}


def stop_control_plane() -> dict:
    return {"status": "stopped"}


def control_plane_status() -> dict:
    return {
        "database": "healthy" if _db.get_repository() else "unavailable",
        "dashboard": "running",
        "orchestrator": "running",
    }
