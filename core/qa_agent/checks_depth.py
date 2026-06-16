"""
QA agent — depth & stall checks.

Push Smith to go deeper after a finding, enforce the 3-pass thorough-scan
requirement (and block premature completion), detect tool inactivity, and
catch spinning on a target with no progress (escalating to HIR on the second
consecutive cycle).
"""
from __future__ import annotations

from datetime import datetime, timezone

import core.qa_agent as _qa
from ._util import _ts_age_secs
from .hir import _hir


def _check_depth_after_finding(entries: list[dict], findings_data: dict) -> dict | None:
    """Push deeper when a high/critical finding sits untouched >20 min."""
    findings = [
        f for f in findings_data.get("findings", [])
        if f.get("severity") in ("high", "critical")
    ]
    if not findings:
        return None
    now = datetime.now(timezone.utc)
    for finding in findings:
        age_secs = _ts_age_secs(finding.get("ts", ""), now)
        if age_secs < 1200:  # 20 min
            continue
        target = finding.get("target", "")
        tools_after = [
            e for e in entries
            if e.get("type") in ("TOOL", "SPIDER")
            and e.get("target", "") == target
            and e.get("ts", "") > finding.get("ts", "")
        ]
        if tools_after:
            continue
        age_mins = int(age_secs / 60)
        if not _qa._has_pending_directives():
            from core.steering import steering_queue, RESUME_TESTING
            steering_queue.add_directive(
                code=RESUME_TESTING,
                message=(
                    f"You found '{finding['title']}' ({finding['severity']}) "
                    f"{age_mins}min ago on {target or 'target'} — and ran nothing since. "
                    "Go deeper before moving on. What can you chain from this? "
                    "Try: privilege escalation, lateral movement, data access, or a second-order injection path."
                ),
                priority="high", skill=None, trigger="DEPTH_AFTER_FINDING",
            )
        return {
            "code": "DEPTH_AFTER_FINDING", "urgency": "high", "blocking": False,
            "message": f"Finding '{finding['title']}' ({finding['severity']}) logged {age_mins}min ago — no follow-up tools on same target",
        }
    return None


def _check_whitebox_passes(entries: list[dict], session_data: dict) -> dict | None:
    """Enforce 3 analysis passes on thorough-depth scans."""
    if session_data.get("depth") != "thorough":
        return None
    semgrep_runs = [e for e in entries if e.get("type") == "TOOL" and e.get("name") == "semgrep"]
    pass_count = len(semgrep_runs)
    if pass_count >= 3:
        return None
    next_pass = pass_count + 1
    focus = (
        "Focus on logic flaws and auth issues." if next_pass == 2
        else "Focus on chained vulnerabilities and second-order sinks."
    )
    if not _qa._has_pending_directives():
        from core.steering import steering_queue, RESUME_TESTING
        steering_queue.add_directive(
            code=RESUME_TESTING,
            message=(
                f"Thorough scan requires 3 analysis passes — you have completed {pass_count}. "
                f"Start pass {next_pass} now. {focus} "
                "Run scan(tool='semgrep') with a new ruleset angle."
            ),
            priority="medium", skill=None, trigger="WHITEBOX_PASSES",
        )
    return {
        "code": "WHITEBOX_PASSES", "urgency": "medium", "blocking": False,
        "message": f"Thorough scan: {pass_count}/3 semgrep passes completed — start pass {next_pass}",
    }


def _check_premature_complete(entries: list[dict], session_data: dict) -> dict | None:
    """Block scan completion when called before 3-pass requirement is met on thorough scans."""
    if session_data.get("depth") != "thorough":
        return None
    complete_events = [e for e in entries if e.get("type") == "COMPLETE"]
    if not complete_events:
        return None
    semgrep_runs = [e for e in entries if e.get("type") == "TOOL" and e.get("name") == "semgrep"]
    pass_count = len(semgrep_runs)
    if pass_count >= 3:
        return None
    return {
        "code": "PREMATURE_COMPLETE", "urgency": "high", "blocking": True,
        "message": (
            f"Completion blocked: thorough scan requires 3 semgrep passes, only {pass_count} done. "
            f"Run pass {pass_count + 1} before calling session(action='complete')."
        ),
    }


def _check_tool_inactivity(entries: list[dict]) -> dict | None:
    """Detect stall when no tool has run for >15 min."""
    tools = [e for e in entries if e.get("type") in ("TOOL", "SPIDER")]
    if not tools:
        return None
    now = datetime.now(timezone.utc)
    age_secs = _ts_age_secs(tools[-1].get("ts", ""), now)
    if age_secs <= 900:  # 15 min
        return None
    mins = int(age_secs / 60)
    if not _qa._has_pending_directives():
        from core.steering import steering_queue, RESUME_REQUIRED
        steering_queue.add_directive(
            code=RESUME_REQUIRED,
            message=(
                f"Smith stalled for {mins}min with no tool activity. "
                "EXECUTE: session(action='recovery') — then continue from EXECUTE_NOW field."
            ),
            priority="high", skill=None, trigger="TOOL_INACTIVITY",
        )
    return {
        "code": "TOOL_INACTIVITY", "urgency": "high", "blocking": False,
        "message": f"No tool activity for {mins}min — Smith may have stalled",
    }


def _check_stuck_on_target(entries: list[dict], findings_data: dict, previous_alerts: list[dict]) -> dict | None:
    """Detect when Smith is spinning on a target with no progress — escalates to HIR on second cycle.

    Pattern: 5+ tool calls against the same target in the last 30 min, no new finding logged
    for that target in the same window, no coverage cells closed for it either.

    Cycle 1 — STUCK_ON_TARGET alert + directive: tell Smith to either log what it sees or
              call session(action='intervene') if it genuinely needs a human.
    Cycle 2 — same target still flagged from previous cycle → trigger HIR directly.
    """
    now = datetime.now(timezone.utc)
    window_secs = 1800  # 30 min

    tool_entries = [
        e for e in entries
        if e.get("type") in ("TOOL", "SPIDER")
        and _ts_age_secs(e.get("ts", ""), now) <= window_secs
    ]
    if not tool_entries:
        return None

    # Count tool calls per target in the window
    from collections import Counter
    target_counts = Counter(e.get("target", "") for e in tool_entries if e.get("target"))
    # Find any target hit 5+ times
    stuck_target = next(
        (t for t, count in target_counts.most_common() if count >= 5 and t), None
    )
    if not stuck_target:
        return None

    hit_count = target_counts[stuck_target]

    # Check if a new finding was logged for this target in the same window
    recent_findings = [
        f for f in findings_data.get("findings", [])
        if f.get("target", "") == stuck_target
        and _ts_age_secs(f.get("ts", ""), now) <= window_secs
    ]
    if recent_findings:
        # Smith is making progress — findings are being logged
        return None

    # Was the same target flagged as stuck in the previous QA cycle?
    was_flagged_before = any(
        a.get("code") == "STUCK_ON_TARGET" and stuck_target in a.get("message", "")
        for a in previous_alerts
    )

    if was_flagged_before:
        # Second consecutive cycle with the same target stuck — escalate to HIR.
        # Uses the _hir() helper instead of trigger_intervention() directly so:
        #   (a) dedup goes through the same code path every HIR check uses,
        #       which now force-reloads session.json mtime before reading
        #       (avoids the stale-cache race the user hit where 5 HIRs fired
        #       within 137ms because each call's get_intervention() read a
        #       cached _current that hadn't seen the previous flush yet);
        #   (b) the min-gap floor (_HIR_MIN_GAP_SECONDS) caps burst frequency
        #       to one HIR-of-this-code per minute even if dedup were ever
        #       defeated, so dashboard "Stuck Events" stops getting flooded.
        _hir(
            code="HIR_STUCK_ON_TARGET",
            situation=(
                f"Smith has made {hit_count} tool calls against '{stuck_target}' "
                f"in the last 30 min with no finding logged and no coverage progress. "
                "It appears to be stuck investigating something it cannot confirm or rule out."
            ),
            tried=[
                f"Ran {hit_count} tool calls against {stuck_target} without result"
            ],
            options=[
                "HINT: Share what you know about this target — give Smith a specific payload, endpoint, or technique to try next",
                "SKIP: Tell Smith to document what it observed, mark as informational, and move on",
                "DEEPER: Approve going further — e.g. manual SQLi, out-of-band callbacks, or Metasploit exploitation",
                "ABORT_TARGET: Drop this target entirely and continue with remaining coverage",
            ],
        )
        return {
            "code": "STUCK_ON_TARGET", "urgency": "high", "blocking": False,
            "message": (
                f"HIR triggered: Smith made {hit_count} tool calls against '{stuck_target}' "
                "over 30 min with no finding — human guidance required"
            ),
        }

    # First detection — inject a directive, let Smith self-correct before escalating
    if not _qa._has_pending_directives():
        from core.steering import steering_queue, RESUME_TESTING
        steering_queue.add_directive(
            code=RESUME_TESTING,
            message=(
                f"You have run {hit_count} tools against '{stuck_target}' in the last 30 min "
                "with no finding logged. You may be stuck. "
                "Choose one: (1) Log what you observed as an informational finding and move on. "
                "(2) Run one final targeted attempt with a specific technique — then move on regardless. "
                "(3) Call session(action='intervene') if you genuinely cannot proceed without human input."
            ),
            priority="high", skill=None, trigger="STUCK_ON_TARGET",
        )
    return {
        "code": "STUCK_ON_TARGET", "urgency": "high", "blocking": False,
        "message": (
            f"Stuck on target: {hit_count} tool calls against '{stuck_target}' "
            "in 30 min, no finding logged — directive sent, HIR queued if unresolved"
        ),
    }
