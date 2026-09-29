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

from fastapi.responses import JSONResponse

from core import paths as _paths

from ._common import router

_FINDING_SCAN_CAP = 20_000   # lines scanned to count findings when no snapshot exists


def _read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _current_session() -> dict:
    """The live session.json {id, status} — the ONE session the clobber-prone
    current pointer names; every other session's status is inferred from its bundle."""
    data = _read_json(_paths.SESSION_FILE) or {}
    return {"id": data.get("id"), "status": data.get("status")}


def _findings_count(stem: str) -> int:
    """Prefer the durable per-session snapshot (cheap, authoritative); else count
    `finding` events in the stream, bounded so a huge log can't stall the request."""
    doc = _read_json(_paths.SMITH_EVENTS_DIR / stem / "findings.json")
    if isinstance(doc, dict):
        return len(doc.get("findings") or [])
    jl = _paths.SMITH_EVENTS_DIR / f"{stem}.jsonl"
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


def _session_row(stem: str, current: dict) -> dict:
    meta = _read_json(_paths.SMITH_EVENTS_DIR / stem / "meta.json") or {}
    jl = _paths.SMITH_EVENTS_DIR / f"{stem}.jsonl"
    try:
        last_activity = jl.stat().st_mtime if jl.exists() else None
    except OSError:
        last_activity = None
    # status: the live pointer wins for the current session; a terminal findings
    # snapshot marks a finished one; otherwise it's a past/backgrounded session.
    if stem == current.get("id"):
        status = current.get("status") or "running"
    elif (_paths.SMITH_EVENTS_DIR / stem / "findings.json").exists():
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
        "findings": _findings_count(stem),
        "scan_phase": meta.get("scan_phase"),
        "last_activity": last_activity,
    }


@router.get("/api/sessions")
async def api_sessions() -> JSONResponse:
    """List every scan session newest-first, with origin/status/findings so the
    dashboard can badge auto-started ones and switch between concurrent sessions."""
    events_dir = _paths.SMITH_EVENTS_DIR
    try:
        streams = sorted(
            events_dir.glob("*.jsonl"),   # *.jsonl only — the dir also holds per-session bundle subdirs
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        ) if events_dir.exists() else []
    except OSError:
        streams = []
    current = _current_session()
    rows = [_session_row(p.stem, current) for p in streams]
    return JSONResponse({"sessions": rows, "current": current.get("id"), "count": len(rows)})
