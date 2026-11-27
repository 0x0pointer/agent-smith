"""Sessions index read API — feeds the dashboard's Sessions panel (issue #187).

Lists every scan session, whatever started it (operator start, watchdog respawn,
implicit auto-create), from the per-session smith-events streams. Those are one
file per session and therefore immune to the session.json single-current clobber
that makes concurrent/auto-spawned sessions invisible today. Each row carries
target, start time, ORIGIN (operator|watchdog), status, and findings count, so an
operator sees auto-started sessions at a glance without grepping logs.

Read-only. References the events dir via core.paths (a core module must not import
mcp_server at import time).
"""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import Request
from fastapi.responses import JSONResponse

from core import paths as _paths

from ._common import router

_FINDING_SCAN_CAP = 20_000   # lines scanned to count findings when no snapshot exists


def _run_paths(request: Request) -> tuple[Path, Path] | None:
    run_id = getattr(request.state, "run_id", None)
    if not run_id:
        return _paths.SMITH_EVENTS_DIR, _paths.SESSION_FILE
    from core import db as _db

    row = _db.get_run(run_id)
    workdir = (row or {}).get("workdir")
    if not workdir:
        return None
    root = Path(workdir)
    return root / "logs" / "smith-events", root / "session.json"


def _read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _current_session(session_file: Path) -> dict:
    """The live session.json {id, status} — the ONE session the clobber-prone
    current pointer names; every other session's status is inferred from its bundle."""
    data = _read_json(session_file) or {}
    return {"id": data.get("id"), "status": data.get("status")}


def _findings_count(stem: str, events_dir: Path) -> int:
    """Prefer the durable per-session snapshot (cheap, authoritative); else count
    `finding` events in the stream, bounded so a huge log can't stall the request."""
    doc = _read_json(events_dir / stem / "findings.json")
    if isinstance(doc, dict):
        return len(doc.get("findings") or [])
    jl = events_dir / f"{stem}.jsonl"
    n = 0
    try:
        with jl.open(encoding="utf-8") as f:
            for i, line in enumerate(f):
                if i >= _FINDING_SCAN_CAP:
                    break
                if '"event_type": "finding"' in line or '"event_type":"finding"' in line:
                    n += 1
    except OSError:
        pass
    return n


def _session_row(stem: str, current: dict, events_dir: Path) -> dict:
    meta = _read_json(events_dir / stem / "meta.json") or {}
    jl = events_dir / f"{stem}.jsonl"
    try:
        last_activity = jl.stat().st_mtime if jl.exists() else None
    except OSError:
        last_activity = None
    # status: the live pointer wins for the current session; a terminal findings
    # snapshot marks a finished one; otherwise it's a past/backgrounded session.
    if stem == current.get("id"):
        status = current.get("status") or "running"
    elif (events_dir / stem / "findings.json").exists():
        status = "complete"
    else:
        status = "inactive"
    origin = (meta.get("origin") or "operator").strip() or "operator"
    return {
        "id": stem,
        "target": meta.get("target"),
        "started": meta.get("started"),
        "origin": origin,
        "auto_started": origin != "operator",
        "status": status,
        "findings": _findings_count(stem, events_dir),
        "scan_phase": meta.get("scan_phase"),
        "last_activity": last_activity,
    }


@router.get("/api/sessions")
async def api_sessions(request: Request) -> JSONResponse:
    """List every scan session newest-first, with origin/status/findings so the
    dashboard can badge auto-started ones and switch between concurrent sessions."""
    scoped_paths = _run_paths(request)
    if scoped_paths is None:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    events_dir, session_file = scoped_paths
    try:
        streams = sorted(
            events_dir.glob("*.jsonl"),   # *.jsonl only — the dir also holds per-session bundle subdirs
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        ) if events_dir.exists() else []
    except OSError:
        streams = []
    current = _current_session(session_file)
    rows = [_session_row(p.stem, current, events_dir) for p in streams]
    return JSONResponse({"sessions": rows, "current": current.get("id"), "count": len(rows)})
