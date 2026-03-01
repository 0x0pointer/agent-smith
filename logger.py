"""
Session logger
==============
Writes one structured log file per MCP server process (= one Claude session).
Log files land in logs/session_YYYY-MM-DD_HH-MM-SS.log

Public API
----------
tool_call(name, kwargs)      — tool invoked
tool_result(name, result)    — tool returned
finding(severity, title, target)
diagram(title)
note(message)                — explicit reasoning / decision note from Claude
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Setup — one log file per process
# ---------------------------------------------------------------------------

_LOG_DIR = Path(__file__).parent / "logs"
_LOG_DIR.mkdir(exist_ok=True)

_session_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
log_path    = _LOG_DIR / f"session_{_session_ts}.log"

_fmt = logging.Formatter(
    fmt="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)

_fh = logging.FileHandler(log_path, encoding="utf-8")
_fh.setFormatter(_fmt)

_log = logging.getLogger("pentest")
_log.setLevel(logging.DEBUG)
_log.addHandler(_fh)

# Write session header
_log.info("SESSION_START  log=%s", log_path.name)


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def tool_call(name: str, kwargs: dict) -> None:
    """Log a tool invocation before it runs."""
    _log.info("TOOL_CALL    %-20s  args=%s", name, json.dumps(kwargs, default=str))


def tool_result(name: str, result: str) -> None:
    """Log a truncated preview of the tool output."""
    preview = result[:400].replace("\n", " ")
    if len(result) > 400:
        preview += "…"
    _log.info("TOOL_RESULT  %-20s  %s", name, preview)


def finding(severity: str, title: str, target: str) -> None:
    """Log a confirmed vulnerability finding."""
    _log.warning("FINDING      [%-8s]  %s  @  %s", severity.upper(), title, target)


def diagram(title: str) -> None:
    """Log that a diagram was saved."""
    _log.info("DIAGRAM      %s", title)


def note(message: str) -> None:
    """Log a reasoning note or decision written explicitly by Claude."""
    _log.info("NOTE         %s", message)
