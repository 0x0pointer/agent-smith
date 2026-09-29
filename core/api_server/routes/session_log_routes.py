"""Per-session reasoning-log read API — feeds the dashboard's Session Log tab (issue #186).

Serves the client-agnostic reasoning stream captured at the MCP tool boundary at
``logs/smith-events/<engagement_id>.jsonl`` (one append-only file per scan). Lists past
sessions newest-first and replays a selected one by id, so an operator can circle back to
a single session's reasoning after a pentest — including watchdog / auto-spawned and
concurrent-tab sessions (each is its own file, immune to the session.json clobber).

Read-only. The events dir is referenced via ``core.paths`` (never by importing
``mcp_server`` — a ``core`` module must not depend on ``mcp_server`` at import time).
"""
from __future__ import annotations

import json
from collections import deque

from fastapi.responses import JSONResponse

from core import paths as _paths

from ._common import router

# Types shown in the reasoning view. `note`/`decision` are the explicit reasoning channel;
# action/result/finding/coverage_transition give the reconstructable trail even when the
# agent recorded no explicit reasoning (the "floor").
_DEFAULT_TYPES = {"note", "decision", "action", "result", "finding", "coverage_transition"}
_MAX_EVENTS = 5000


def _session_label(stem: str) -> dict:
    """Dropdown label for a session id, enriched from its durable meta.json subdir
    (logs/smith-events/<id>/meta.json) when present; falls back to the bare id (a
    decision/note-only stream has a .jsonl but no meta.json)."""
    info = {"id": stem, "target": None, "started": None}
    try:
        meta = _paths.SMITH_EVENTS_DIR / stem / "meta.json"
        if meta.exists():
            m = json.loads(meta.read_text(encoding="utf-8"))
            info["target"] = m.get("target")
            info["started"] = m.get("started")
    except Exception:
        pass
    return info


@router.get("/api/session-log")
async def api_session_log(session: str = "", limit: int = _MAX_EVENTS) -> JSONResponse:
    """List reasoning-stream sessions and replay one.

    ``session`` — the engagement id to replay; defaults to the newest by file mtime
    (session ids are random uuid4, so filename order is meaningless). Resolved against a
    trusted glob by stem — never built from the raw query param (path-traversal safety,
    mirroring /api/logs).
    """
    events_dir = _paths.SMITH_EVENTS_DIR
    try:
        streams = sorted(
            events_dir.glob("*.jsonl"),  # *.jsonl only — the dir also holds per-session bundle subdirs
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        ) if events_dir.exists() else []
    except OSError:
        streams = []

    sessions = [_session_label(p.stem) for p in streams]

    if not streams:
        return JSONResponse({"session": None, "sessions": [], "events": [],
                             "truncated": False, "count": 0})

    if session:
        target = next((p for p in streams if p.stem == session), None)
        if target is None:
            return JSONResponse({"session": None, "sessions": sessions, "events": [],
                                 "truncated": False, "count": 0, "error": "invalid session"})
    else:
        target = streams[0]  # newest by mtime

    cap = max(1, min(limit, _MAX_EVENTS))  # FastAPI already coerced limit to int

    rows: deque = deque(maxlen=cap)  # tail the most-recent events; bounded memory
    total = 0
    try:
        with target.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except Exception:
                    continue  # skip a truncated/malformed final line — never 500
                et = ev.get("event_type")
                if et not in _DEFAULT_TYPES:
                    continue
                total += 1
                rows.append({
                    "event_id": ev.get("event_id"),
                    "event_type": et,
                    "sequence": ev.get("sequence"),
                    "occurred_at": ev.get("occurred_at"),
                    "caused_by": ev.get("caused_by"),
                    "correlation_id": ev.get("correlation_id"),
                    "payload": ev.get(et),  # reasoning is NESTED under a key == event_type
                })
    except OSError:
        pass

    return JSONResponse({
        "session": target.stem,
        "sessions": sessions,
        "events": list(rows),
        "truncated": total > len(rows),
        "count": total,
    })
