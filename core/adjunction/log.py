"""
Adjudication activity log
=========================
Append-only JSONL feed of adjudication events for the Activity tab.

Entry types
-----------
  directive — adjudication pass kicked off; lists the pending finding titles
  verdict   — Smith recorded a verdict for one finding via update_finding
  complete  — all findings adjudicated; scan closed

Written by:
  mcp_server.report_tools   — verdict on each update_finding with adjudication
  mcp_server.session_tools  — directive (non-force path) + complete (auto-close)
  core.api_server.routes    — directive (force-complete path)

The file is cleared at scan start (called from session_tools._do_start).
"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

from core import paths as _paths

_LOG_FILE = _paths.ADJUDICATION_LOG_FILE
_lock = threading.Lock()

# In-process guard: only write one `directive` entry per scan regardless of
# how many times _do_complete() runs adjudication blockers.
_directive_logged = False


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _append(entry: dict) -> None:
    with _lock:
        with open(_LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")


def clear() -> None:
    """Clear the log at scan start."""
    global _directive_logged
    with _lock:
        _directive_logged = False
        try:
            _LOG_FILE.unlink(missing_ok=True)
        except Exception:
            pass


def log_directive(pending: list[dict]) -> None:
    """Log that the adjudication directive was sent to Smith."""
    global _directive_logged
    if _directive_logged:
        return
    _directive_logged = True
    _append({
        "type": "directive",
        "ts": _now(),
        "n_pending": len(pending),
        "titles": [f.get("title", "?") for f in pending],
    })


def log_verdict(
    finding_id: str,
    title: str,
    original_severity: str,
    revised_severity: str,
    reproducible: bool | str,
    rationale: str,
) -> None:
    """Log a single finding verdict recorded by Smith."""
    _append({
        "type": "verdict",
        "ts": _now(),
        "finding_id": finding_id,
        "title": title,
        "original_severity": original_severity,
        "revised_severity": revised_severity,
        "reproducible": reproducible,
        "rationale": rationale,
    })


def log_complete(n_adjudicated: int) -> None:
    """Log that all findings were adjudicated and the scan was closed."""
    _append({
        "type": "complete",
        "ts": _now(),
        "n_adjudicated": n_adjudicated,
    })


def read_all() -> list[dict]:
    """Return all log entries as a list (newest-last)."""
    if not _LOG_FILE.exists():
        return []
    entries = []
    try:
        for line in _LOG_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except Exception:
                    pass
    except Exception:
        pass
    return entries
