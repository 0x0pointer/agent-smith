"""
Background-job registry  (PR-F)
===============================
A general background-job primitive for long-running tools — big nuclei/ffuf
sweeps, credential-audit hydra/spraying, deep sqlmap — so the agent's turn is
not blocked waiting on them.

Opt-in surface (default is unchanged, synchronous):
    kali(command=..., background=True)          → returns immediately
    scan(tool=..., target=..., background=True)  → returns immediately
        ↳ both return {"status": "running", "job_id": "..."}

    session(action="job_poll", options={"job_id": "..."})  → status / result
    session(action="job_list")                              → active + finished jobs

Design
------
* A module-level registry (``_REGISTRY``) maps ``job_id -> record``. Because MCP
  calls are independent invocations of the SAME server process, the module
  object (and therefore the registry) survives across them. Each record is ALSO
  persisted to ``logs/jobs/<job_id>.json`` so a poll in a later call — or after
  context compaction, or an in-process reload that dropped the in-memory map —
  can RECONSTRUCT the job from disk.
* The work runs as a tracked ``asyncio`` task kept in a module-level set
  (``_JOB_TASKS``) so it is not garbage-collected mid-flight — the same idiom as
  the existing ``_background_tasks`` fire-and-forget housekeeping, but
  user-pollable.
* The result STORED is exactly the envelope string the synchronous call would
  have produced (summary / facts / evidence + a real ``artifact_id``). ``wrap()``
  on the sync path already stores the raw tool output as an on-disk artifact, so
  the background path inherits a real ``artifact_id`` for free — it is parsed out
  of the stored envelope and hoisted onto the poll response.
* Simultaneous background jobs are capped (default 4, override with the
  ``SMITH_MAX_BACKGROUND_JOBS`` env var). A submission beyond the cap is REJECTED
  with a reason (the agent is told to poll/await capacity) rather than silently
  queued — queuing would hide resource pressure from the operator.
"""
from __future__ import annotations

import asyncio
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from core import paths as _paths

# ── Module-level state (survives across the independent MCP calls of one process) ──
_REGISTRY: dict[str, dict] = {}
_JOB_TASKS: set[asyncio.Task] = set()  # keeps background tasks alive (not GC'd)

# Persisted one-file-per-job under logs/jobs/. Aliased so tests can monkeypatch
# mcp_server.jobs._JOBS_DIR to a tmp dir (same convention as the other stores).
_JOBS_DIR: Path = _paths.JOBS_DIR


# Default cap on simultaneously-running background jobs. Monkeypatchable in tests;
# overridden at runtime by the SMITH_MAX_BACKGROUND_JOBS env var (see _max_concurrent).
_MAX_CONCURRENT_JOBS = 4


def _max_concurrent() -> int:
    """Cap on simultaneously-running background jobs (env-overridable)."""
    try:
        return max(1, int(os.environ.get("SMITH_MAX_BACKGROUND_JOBS", "") or _MAX_CONCURRENT_JOBS))
    except (TypeError, ValueError):
        return _MAX_CONCURRENT_JOBS


# ── Helpers ────────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _jobs_dir() -> Path:
    _JOBS_DIR.mkdir(parents=True, exist_ok=True)
    return _JOBS_DIR


def _slug(tool: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in (tool or "job"))[:40].strip("_") or "job"


def _new_job_id(tool: str) -> str:
    return f"{_slug(tool)}_bg_{datetime.now(timezone.utc).strftime('%H%M%S')}_{uuid.uuid4().hex[:8]}"


def _persist(record: dict) -> None:
    """Write (or overwrite) the job's on-disk record. Best-effort — a disk hiccup
    must never crash the tool call or the background task."""
    try:
        path = _jobs_dir() / f"{record['job_id']}.json"
        path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    except Exception:
        pass


def _load_from_disk(job_id: str) -> dict | None:
    """Reconstruct one job record from logs/jobs/<job_id>.json, or None."""
    try:
        path = _JOBS_DIR / f"{job_id}.json"
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _parse_artifact_id(result) -> str | None:
    """Pull the artifact_id out of a stored envelope string (the envelope's
    ``artifact`` field). Returns None for a non-JSON / artifact-less result."""
    if not isinstance(result, str):
        return None
    try:
        obj = json.loads(result)
    except Exception:
        return None
    if isinstance(obj, dict):
        art = obj.get("artifact")
        return art if isinstance(art, str) and art else None
    return None


def _elapsed(record: dict) -> float:
    """Seconds between started_at and finished_at (or now, if still running)."""
    try:
        start = datetime.fromisoformat(record["started_at"])
    except Exception:
        return 0.0
    end_raw = record.get("finished_at")
    try:
        end = datetime.fromisoformat(end_raw) if end_raw else datetime.now(timezone.utc)
    except Exception:
        end = datetime.now(timezone.utc)
    return round((end - start).total_seconds(), 1)


def _running_count() -> int:
    """How many in-memory jobs are currently running (drives the concurrency cap)."""
    return sum(1 for r in _REGISTRY.values() if r.get("status") == "running")


def get(job_id: str) -> dict | None:
    """Fetch a job record: in-memory first, else reconstructed from disk."""
    rec = _REGISTRY.get(job_id)
    if rec is not None:
        return rec
    rec = _load_from_disk(job_id)
    if rec is not None:
        _REGISTRY[job_id] = rec  # cache so repeated polls don't re-read disk
    return rec


# ── Lifecycle ────────────────────────────────────────────────────────────────

def _finalize(job_id: str, status: str, result: str | None, error: str | None) -> None:
    rec = _REGISTRY.get(job_id) or _load_from_disk(job_id) or {"job_id": job_id}
    rec["status"] = status
    rec["finished_at"] = _now_iso()
    rec["result"] = result
    rec["error"] = error
    rec["artifact_id"] = _parse_artifact_id(result)
    _REGISTRY[job_id] = rec
    _persist(rec)


async def _runner(job_id: str, work) -> None:
    """Task body: run the work coroutine, then record the outcome. Never re-raises
    a normal error (it is captured as job status=error); cancellation is recorded
    and propagated so loop shutdown stays correct."""
    try:
        result = await work()
    except asyncio.CancelledError:
        _finalize(job_id, status="error", result=None, error="cancelled")
        raise
    except Exception as exc:  # noqa: BLE001 — capture everything into the record
        _finalize(job_id, status="error", result=None, error=f"{type(exc).__name__}: {exc}")
        return
    _finalize(job_id, status="done", result=result, error=None)


def submit(tool: str, args: dict, work) -> str:
    """Launch ``work`` (a zero-arg callable returning a coroutine) as a tracked
    background task and return a ``{status:"running", job_id}`` envelope string
    IMMEDIATELY. Rejects (with a reason) when the concurrency cap is reached.

    Must be called from within a running event loop (every MCP tool handler is
    async, so this holds)."""
    cap = _max_concurrent()
    if _running_count() >= cap:
        return json.dumps({
            "status": "rejected",
            "reason": (
                f"background-job concurrency cap reached ({cap} running). Poll or await an "
                f"existing job via session(action='job_poll') before starting another, or run "
                f"this one synchronously (omit background=true)."
            ),
            "running": _running_count(),
            "max_concurrent": cap,
        }, indent=2)

    job_id = _new_job_id(tool)
    record = {
        "job_id": job_id,
        "tool": tool,
        "args": args or {},
        "status": "running",
        "started_at": _now_iso(),
        "finished_at": None,
        "result": None,
        "artifact_id": None,
        "error": None,
    }
    _REGISTRY[job_id] = record
    _persist(record)

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        # No running loop (should not happen from an async tool). Fail loudly rather
        # than silently never running the work.
        _finalize(job_id, status="error", result=None, error="no running event loop to schedule job")
        return json.dumps({"status": "error", "job_id": job_id,
                           "error": "no running event loop to schedule background job"}, indent=2)

    task = loop.create_task(_runner(job_id, work))
    _JOB_TASKS.add(task)
    task.add_done_callback(_JOB_TASKS.discard)

    return json.dumps({
        "status": "running",
        "job_id": job_id,
        "tool": tool,
        "started_at": record["started_at"],
        "summary": (
            f"⏳ Background job started: {tool}. It runs without blocking your turn — "
            f"keep working, then collect the result with "
            f"session(action='job_poll', options={{'job_id': '{job_id}'}})."
        ),
        "poll_with": f"session(action='job_poll', options={{'job_id': '{job_id}'}})",
        "running": _running_count(),
        "max_concurrent": cap,
    }, indent=2)


# ── Poll / list responses ───────────────────────────────────────────────────

def _done_response(rec: dict) -> str:
    """Return the finished job's full result envelope plus job metadata. The
    original envelope (summary/facts/evidence/artifact/next/...) is delivered
    under ``result`` so the poller gets exactly what the synchronous call
    produced; artifact_id is also hoisted for convenience."""
    result = rec.get("result")
    parsed = None
    if isinstance(result, str):
        try:
            parsed = json.loads(result)
        except Exception:
            parsed = None
    return json.dumps({
        "status": "done",
        "job_id": rec.get("job_id"),
        "tool": rec.get("tool"),
        "elapsed_seconds": _elapsed(rec),
        "artifact_id": rec.get("artifact_id"),
        "result": parsed if parsed is not None else result,
    }, indent=2)


def poll_response(opts: dict) -> str:
    """session(action='job_poll') handler."""
    job_id = str((opts or {}).get("job_id", "")).strip()
    if not job_id:
        return json.dumps({
            "status": "error",
            "error": "Missing job_id. Pass options={'job_id': '<id>'} (from a background start, "
                     "or session(action='job_list')).",
        }, indent=2)
    rec = get(job_id)
    if rec is None:
        return json.dumps({
            "status": "unknown",
            "job_id": job_id,
            "error": "No such job on record. List jobs with session(action='job_list').",
        }, indent=2)

    status = rec.get("status")
    if status == "running":
        return json.dumps({
            "status": "running",
            "job_id": job_id,
            "tool": rec.get("tool"),
            "elapsed_seconds": _elapsed(rec),
            "started_at": rec.get("started_at"),
            "message": "still running — keep working and poll again shortly.",
        }, indent=2)
    if status == "error":
        return json.dumps({
            "status": "error",
            "job_id": job_id,
            "tool": rec.get("tool"),
            "elapsed_seconds": _elapsed(rec),
            "error": rec.get("error"),
            "artifact_id": rec.get("artifact_id"),
        }, indent=2)
    return _done_response(rec)


def _summary(rec: dict) -> dict:
    return {
        "job_id": rec.get("job_id"),
        "tool": rec.get("tool"),
        "status": rec.get("status"),
        "started_at": rec.get("started_at"),
        "finished_at": rec.get("finished_at"),
        "elapsed_seconds": _elapsed(rec),
        "artifact_id": rec.get("artifact_id"),
        "args": rec.get("args"),
    }


def _all_jobs() -> list[dict]:
    """Every known job: in-memory plus any persisted on disk not yet in memory.
    In-memory wins (it is authoritative for live tasks in this process)."""
    merged: dict[str, dict] = {}
    try:
        if _JOBS_DIR.exists():
            for f in sorted(_JOBS_DIR.glob("*.json")):
                try:
                    rec = json.loads(f.read_text(encoding="utf-8"))
                    merged[rec.get("job_id", f.stem)] = rec
                except Exception:
                    continue
    except Exception:
        pass
    merged.update(_REGISTRY)  # live records override stale disk copies
    return list(merged.values())


def list_response(opts: dict) -> str:
    """session(action='job_list') handler. Optional options: {status: running|done|error}."""
    want = str((opts or {}).get("status", "")).strip().lower()
    jobs = _all_jobs()
    if want:
        jobs = [r for r in jobs if r.get("status") == want]
    jobs.sort(key=lambda r: r.get("started_at") or "", reverse=True)
    return json.dumps({
        "jobs": [_summary(r) for r in jobs],
        "count": len(jobs),
        "running": _running_count(),
        "max_concurrent": _max_concurrent(),
    }, indent=2)


def reset() -> None:
    """Clear in-memory registry + task set (tests only; does not touch disk)."""
    _REGISTRY.clear()
    _JOB_TASKS.clear()
