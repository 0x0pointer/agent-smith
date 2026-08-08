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
    """(findings, addressed cells, chains) — the watchdog's fingerprint for 'did the
    last respawn accomplish anything SUBSTANTIVE?'.

    Deliberately does NOT include quick_log mtime: a respawned agent that merely
    thrashes (recovery -> list -> exit) still bumps the log, so including mtime made
    the fingerprint change on pure activity and reset the no-progress counter every
    time — the breaker then never fired and the watchdog respawned indefinitely.

    Includes CHAINS because Phase C (synthesis) advances by PROVING chains, not by
    filing new findings or closing cells — without this, every productive synthesis
    respawn looked like 'no progress', tripping the no-progress breaker / per-scan cap
    and stalling the scan in Phase C. Real progress = a new finding, a newly-closed
    cell, OR a newly-proven chain."""
    import json
    findings = addressed = chains = 0
    try:
        f = json.loads(_api._FINDINGS_FILE.read_text())
        findings = len(f.get("findings", []))
        chains = len(f.get("chains", []))
    except Exception:
        pass
    try:
        cov = json.loads(_api._COVERAGE_FILE.read_text())
        addressed = sum(1 for c in cov.get("matrix", [])
                        if c.get("status") in ("tested_clean", "vulnerable", "not_applicable"))
    except Exception:
        pass
    return (findings, addressed, chains)


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


def _classify_spawn_failure(reason: str) -> tuple[str, str] | None:
    """If ``reason`` (a failed respawn's own exit line) indicates a billing / usage /
    auth block rather than a stuck agent, return (kind, operator-facing remedy)."""
    r = (reason or "").lower()
    if any(p in r for p in ("out of extra usage", "usage limit", "usage_limit",
                            "rate limit", "rate_limit", "429", "quota")):
        return ("usage", "Your Claude subscription hit its usage limit. Wait for the "
                "reset shown in the message, then resume (CONTINUE). The interactive "
                "session shares the same pool, so it may be limited until then too.")
    if any(p in r for p in ("credit balance", "billing", "insufficient", "payment")):
        return ("credit", "The API account is out of credit. Top it up, OR use your "
                "subscription instead (unset ANTHROPIC_API_KEY for the server / leave "
                "SMITH_SPAWN_USE_API_KEY unset), then resume.")
    if any(p in r for p in ("unauthorized", "not logged in", "please run /login",
                            "authentication", "invalid api key", "no api key")):
        return ("auth", "The agent client isn't authenticated. Log it in (or fix the "
                "API key), then resume.")
    return None


def _escalate_no_progress_hir() -> None:
    """Pause the scan for a human instead of respawning into the same dead end."""
    n = _smith._watchdog_no_progress_count
    reason = (getattr(_smith, "_last_spawn_failure", "") or "").strip()
    blocked = _classify_spawn_failure(reason)
    if blocked:
        # A respawn couldn't LAUNCH (billing/usage/auth) — NOT a coverage/logic dead
        # end. Report the real cause + the actual remedy so the operator doesn't chase
        # a phantom "agent keeps exiting without testing".
        _kind, remedy = blocked
        situation = (
            f"The scan is paused because the agent client could not launch: "
            f"“{reason[:200]}”. This is NOT a testing dead-end — {remedy}"
        )
        tried = [f"{n} respawns failed to launch — {reason[:120]}"]
        options = [
            "RESUME: once the limit resets / credit is added / auth is fixed, resume the scan",
            "ACCEPT_PARTIAL: finish now with the current findings + documented gaps",
            "EXTEND: provide working credentials/credit or switch auth, then resume",
            "ABORT: stop the scan",
        ]
    else:
        situation = (
            f"The scan respawned {n}× with no new findings, no newly-closed cells, and no MCP "
            "activity — the agent loop keeps exiting without testing. Pausing instead of "
            "respawning into the same dead end."
        )
        tried = [f"{n} consecutive respawns with zero progress"]
        options = [
            "COMPLETE: accept the current findings + documented coverage gaps and finish",
            "GUIDE: give specific next steps (endpoints/findings to focus on) and resume",
            "EXTEND: raise limits / provide credentials, then resume",
            "ABORT: stop the scan",
        ]
    try:
        from core import session as scan_session
        scan_session.trigger_intervention(
            code="HIR_NO_PROGRESS", situation=situation, tried=tried, options=options,
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
