"""
Shared module state and tiny helpers for the session_tools package.

Split out for the <300-lines-per-file convention. Names here are re-exported by
the package facade (__init__). Functions that consume facade-patched names or the
mutable completion counters reference them through the package object at call
time (import mcp_server.session_tools as _st) so unittest.mock.patch on
`mcp_server.session_tools.<name>` and the external counter reset in
core/session/__init__.py continue to work identically to the old single module.
"""
import os
import re
from typing import Any

from core import findings as findings_store
from core import logger as log
from core import session as scan_session

import mcp_server.session_tools as _st

# Minimum complete() calls required before thorough scans are allowed to finish.
# Each blocked call is one "iteration" — the model must go deeper and try again.
# This is the FULL-profile default; _min_iterations() scales it down by profile.
_THOROUGH_MIN_ITERATIONS = 3


def _min_iterations() -> int:
    """Profile-aware thorough-pass requirement (full=3, medium=2, small=1).

    A 16-32K-token local model cannot hold three deep analysis passes in context;
    capable (full-profile) models keep the full 3, honouring the white-box-3-passes
    rule for them. Small/medium reduce so the run is completable instead of looping.
    """
    try:
        from mcp_server.scan_engine.budget import get_profile
        return int(get_profile().get("thorough_min_passes", _THOROUGH_MIN_ITERATIONS))
    except Exception:
        return _THOROUGH_MIN_ITERATIONS


def _condensed_directives() -> bool:
    """True under medium/small profiles — serialize blockers + emit digest directives."""
    try:
        from mcp_server.scan_engine.budget import get_profile
        return bool(get_profile().get("condensed_directives", False))
    except Exception:
        return False

# ── CTF flag pattern (e.g. CTF{...}, flag{...}, HTB{...}) ─────────────────────
_FLAG_RE = re.compile(r'\w{2,10}\{[A-Za-z0-9_\-!@#$%^&*()+=,.?]{4,}\}')


def _has_ctf_flag(data: dict) -> bool:
    """Return True when this looks like a CTF/benchmark run.

    CTF/benchmark runs are allowed to skip coverage matrix population because
    the goal is flag extraction, not methodology auditability.  Detection:
      1. Session explicitly started with ctf=True in session.json.
      2. A finding contains a recognisable CTF flag pattern (e.g. CTF{...}).
    """
    current = scan_session.get() or {}
    if current.get("ctf"):
        return True
    for f in data.get("findings", []):
        text = f"{f.get('title', '')} {f.get('evidence', '')} {f.get('description', '')}"
        if _FLAG_RE.search(text):
            return True
    return False


def _effective_tools() -> set[str]:
    """Return the union of in-memory tracked tools and tools persisted in session.json.

    Using only _session_tools_called loses tool history after an MCP process
    restart; using only session.json misses tools added in the current process
    before the next flush.  Merging both gives the correct picture in all cases.
    """
    current = scan_session.get() or {}
    return _st._session_tools_called | set(current.get("tools_called", []))
