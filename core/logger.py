"""
Session logger
==============
Appends all sessions to a single log file: logs/pentest.log
Each server start writes a SESSION_START marker so sessions are easy to tell apart.

Public API
----------
tool_call(name, kwargs)      — tool invoked
tool_result(name, result)    — tool returned
finding(severity, title, target)
diagram(title)
note(message)                — explicit reasoning / decision note from Claude
skill_start(name, reason, chained_from)  — skill selected (SKILL_START) or chained (SKILL_CHAIN)
"""
from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from core import paths as _paths

# ---------------------------------------------------------------------------
# Secret redaction — tool output (HTTP responses, kali stdout) routinely carries
# Authorization/Cookie headers, JWTs and login bodies. pentest.log is a long-lived
# forensic file; mask those before they land at rest (AS-06 / AS-15). The log stays
# useful — only the secret VALUE is masked, not the surrounding context.
# ---------------------------------------------------------------------------

_SECRET_PATTERNS = [
    (re.compile(r"(?i)(authorization:\s*(?:bearer\s+)?)\S+"), r"\1<redacted>"),
    (re.compile(r"(?i)((?:set-)?cookie:\s*)[^\r\n]+"), r"\1<redacted>"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"), "<redacted-jwt>"),
    (re.compile(r'(?i)("?(?:password|passwd|api[_-]?key|secret|access[_-]?token|refresh[_-]?token|token|otp)"?\s*[:=]\s*"?)([^"\s,&}\r\n]+)'), r"\1<redacted>"),
]


def _redact(text: str) -> str:
    """Mask credential/token values in a string before it is logged at rest."""
    if not text:
        return text
    for pat, repl in _SECRET_PATTERNS:
        text = pat.sub(repl, text)
    return text

# ---------------------------------------------------------------------------
# Setup — single persistent log file, appended across sessions
# ---------------------------------------------------------------------------

_LOG_DIR = _paths.LOGS_DIR
_LOG_DIR.mkdir(exist_ok=True)

log_path = _LOG_DIR / "pentest.log"

_fmt = logging.Formatter(
    fmt="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)

_fh = logging.FileHandler(log_path, mode="a", encoding="utf-8")
_fh.setFormatter(_fmt)
# Owner-only — the log carries harvested tokens/cookies/creds (redacted below, but
# defense-in-depth) and must not be world-readable on a shared host (AS-15).
try:
    os.chmod(log_path, 0o600)
except OSError:
    pass

_log = logging.getLogger("pentest")
_log.setLevel(logging.DEBUG)
_log.addHandler(_fh)

# Write session boundary so multiple restarts are easy to distinguish
_session_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
_log.info("=" * 80)
_log.info("SESSION_START  %s", _session_ts)


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def tool_call(name: str, kwargs: dict) -> None:
    """Log a tool invocation before it runs."""
    _log.info("TOOL_CALL    %-20s  args=%s", name, json.dumps(kwargs, default=str))


def tool_result(name: str, result: str) -> None:
    """Log the full (secret-redacted) tool output for forensic review."""
    _log.info("TOOL_RESULT  %-20s\n%s\n%s", name, _redact(result), "─" * 80)


def tool_result_verbose(name: str, raw_stdout: str, raw_stderr: str) -> None:
    """Log raw stdout+stderr (secret-redacted) before any clipping."""
    if raw_stdout:
        _log.debug("RAW_STDOUT   %-20s\n%s", name, _redact(raw_stdout))
    if raw_stderr:
        _log.debug("RAW_STDERR   %-20s\n%s", name, _redact(raw_stderr))


def finding(severity: str, title: str, target: str) -> None:
    """Log a confirmed vulnerability finding."""
    _log.warning("FINDING      [%-8s]  %s  @  %s", severity.upper(), title, target)


def diagram(title: str) -> None:
    """Log that a diagram was saved."""
    _log.info("DIAGRAM      %s", title)


def note(message: str) -> None:
    """Log a reasoning note or decision written explicitly by Claude."""
    _log.info("NOTE         %s", message)


def skill_start(name: str, reason: str = "", chained_from: str = "") -> None:
    """Log a skill invocation decision with reasoning and optional chain context.

    Writes SKILL_CHAIN when the agent is chaining from a parent skill, or
    SKILL_START for the initial skill selection.
    """
    if chained_from:
        _log.info(
            "SKILL_CHAIN  %-20s  chained_from=%-20s  reason=%s",
            name, chained_from, reason,
        )
    else:
        _log.info("SKILL_START  %-20s  reason=%s", name, reason)
