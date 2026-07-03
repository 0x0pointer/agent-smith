"""
No-progress backoff: fingerprint scan progress across respawns and escalate to
a human once a run of respawns accomplishes nothing.

The mutable counters ``_watchdog_last_progress`` / ``_watchdog_no_progress_count``
live on the package facade (__init__) so tests and the parent re-export see the
same object; the functions here read AND write them through ``_smith.<name>``
(attribute assignment, not ``global``) — identical to the old module-global
mutation because the attributes live on the package.
"""
from __future__ import annotations

import core.api_server as _api
import core.api_server.smith as _smith

from ._common import _log, _WATCHDOG_MAX_NO_PROGRESS


def _scan_progress_snapshot() -> tuple:
    """(findings, addressed cells, quick_log mtime) — the watchdog's fingerprint
    for 'did the last respawn actually accomplish anything?'."""
    import json
    findings = addressed = 0
    qmtime = 0.0
    try:
        findings = len(json.loads(_api._FINDINGS_FILE.read_text()).get("findings", []))
    except Exception:
        pass
    try:
        cov = json.loads(_api._COVERAGE_FILE.read_text())
        addressed = sum(1 for c in cov.get("matrix", [])
                        if c.get("status") in ("tested_clean", "vulnerable", "not_applicable"))
    except Exception:
        pass
    try:
        qmtime = round(_api._QUICK_LOG_FILE.stat().st_mtime, 1)
    except Exception:
        pass
    return (findings, addressed, qmtime)


def _watchdog_should_escalate_no_progress() -> bool:
    """Track consecutive futile respawns; True once the cap is hit. A respawn
    that advances findings/cells/heartbeat resets the counter."""
    cur = _smith._scan_progress_snapshot()
    if _smith._watchdog_last_progress is not None and cur == _smith._watchdog_last_progress:
        _smith._watchdog_no_progress_count += 1
    else:
        _smith._watchdog_no_progress_count = 0
    _smith._watchdog_last_progress = cur
    return _smith._watchdog_no_progress_count >= _WATCHDOG_MAX_NO_PROGRESS


def _escalate_no_progress_hir() -> None:
    """Pause the scan for a human instead of respawning into the same dead end."""
    n = _smith._watchdog_no_progress_count
    try:
        from core import session as scan_session
        scan_session.trigger_intervention(
            code="HIR_NO_PROGRESS",
            situation=(
                f"The scan respawned {n}× with no new findings, no newly-closed cells, and no MCP "
                "activity — the agent loop keeps exiting without testing. Pausing instead of "
                "respawning into the same dead end."
            ),
            tried=[f"{n} consecutive respawns with zero progress"],
            options=[
                "COMPLETE: accept the current findings + documented coverage gaps and finish",
                "GUIDE: give specific next steps (endpoints/findings to focus on) and resume",
                "EXTEND: raise limits / provide credentials, then resume",
                "ABORT: stop the scan",
            ],
        )
    except Exception:
        _log.exception("no-progress HIR escalation failed")
    try:
        from core import notifiers as _nfr
        _nfr.notify(
            title="Smith stuck — respawns making no progress",
            body=("The watchdog paused the scan after repeated respawns produced no new findings or "
                  "coverage. Decide on the dashboard: complete, guide, extend, or abort."),
            urgency="high", code="WATCHDOG_NO_PROGRESS",
        )
    except Exception:
        pass
    _smith._watchdog_no_progress_count = 0
    _smith._watchdog_last_progress = None
