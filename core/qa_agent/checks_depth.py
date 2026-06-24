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


def _check_chain_correlation(findings_data: dict) -> dict | None:
    """Nudge exploit-chain correlation.

    When ≥2 high/critical findings (not adjudicated false-positive) share a
    target and no exploit chain has been recorded yet, push Smith to correlate
    them into a kill chain (report(action='chain')) or explicitly dismiss the
    lead — compound criticals are exactly the high-impact findings that go
    under-reported when chaining lives only in one agent's memory.
    """
    if findings_data.get("chains"):
        return None  # a chain already exists — don't nag
    confirmed = [
        f for f in findings_data.get("findings", [])
        if f.get("severity") in ("high", "critical")
        and f.get("status", "confirmed") != "false_positive"
    ]
    if len(confirmed) < 2:
        return None
    from collections import Counter
    by_target = Counter(f.get("target", "") for f in confirmed if f.get("target"))
    hot = next((t for t, n in by_target.most_common() if n >= 2 and t), None)
    if not hot:
        return None
    titles = [f.get("title", "?") for f in confirmed if f.get("target") == hot][:3]
    if not _qa._has_pending_directives():
        from core.steering import steering_queue, RESUME_TESTING
        steering_queue.add_directive(
            code=RESUME_TESTING,
            message=(
                f"{by_target[hot]} confirmed high/critical findings share target '{hot}' "
                f"({', '.join(titles)}). Correlate them: can one feed another into a worse "
                "terminal (account takeover, RCE, mass/cross-tenant data exfil)? If a transition "
                "is proven, file the kill chain with report(action='chain', data={name, steps:[...]}) "
                "— chains compose to terminal blast radius, they never average. If they don't chain, "
                "note why and move on."
            ),
            priority="medium", skill=None, trigger="CHAIN_CORRELATION",
        )
    return {
        "code": "CHAIN_CORRELATION", "urgency": "medium", "blocking": False,
        "message": (
            f"{by_target[hot]} confirmed high/critical findings on '{hot}' with no exploit "
            "chain recorded — correlate into a kill chain or dismiss"
        ),
    }


def _check_oob_unpolled(session_data: dict) -> dict | None:
    """Nudge Smith to poll a fired-but-unchecked OOB callback.

    A minted OOB subdomain that was never polled means a blind vuln was probed
    but left unconfirmed — the received callback is the only proof for blind
    SSRF/RCE/XXE/OAST-SQLi, so an unpolled callback is a coverage hole.
    """
    oob = (session_data.get("known_assets") or {}).get("oob_interactions") or []
    now = datetime.now(timezone.utc)
    stale = [
        o for o in oob
        if isinstance(o, dict) and not o.get("polled")
        and _ts_age_secs(o.get("minted_at", ""), now) > 300  # 5 min
    ]
    if not stale:
        return None
    o = stale[0]
    cid = o.get("correlation_id", "")
    if not _qa._has_pending_directives():
        from core.steering import steering_queue, RESUME_TESTING
        steering_queue.add_directive(
            code=RESUME_TESTING,
            message=(
                f"You minted an OOB callback ({o.get('subdomain', '')}) for a blind-vuln test "
                "but never polled the result. Run "
                f"session(action='oob_poll', options={{'correlation_id': '{cid}'}}) — a received "
                "callback is the only proof for blind SSRF/RCE/XXE/OAST-SQLi. If none arrives after "
                "a reasonable wait, that's evidence the payload did not reach an OOB sink."
            ),
            priority="medium", skill=None, trigger="OOB_UNPOLLED",
        )
    return {
        "code": "OOB_UNPOLLED", "urgency": "medium", "blocking": False,
        "message": (
            f"{len(stale)} OOB callback(s) minted but never polled — confirm or rule out the "
            "blind vuln before completing"
        ),
    }


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


def _last_resolved_stuck_age(session_data: dict, target: str, now) -> float | None:
    """Age (seconds) of the most recent RESOLVED STUCK-on-target HIR for ``target``,
    or None if none has been resolved. Used to keep a resolved target from
    re-firing off its own stale tool calls still inside the lookback window."""
    best = None
    history = list(session_data.get("intervention_history", []) or [])
    cur = session_data.get("intervention")
    if isinstance(cur, dict):
        history.append(cur)
    for h in history:
        if h.get("code") != "HIR_STUCK_ON_TARGET":
            continue
        if target not in (h.get("situation") or ""):
            continue
        resolved_at = h.get("resolved_at")
        if not resolved_at:
            continue
        age = _ts_age_secs(resolved_at, now)
        if best is None or age < best:
            best = age
    return best


def _check_stuck_on_target(entries: list[dict], findings_data: dict, session_data: dict, previous_alerts: list[dict]) -> dict | None:
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

    # Don't re-escalate a target whose STUCK HIR the operator already resolved,
    # unless Smith has spun 5+ MORE times against it SINCE that resolution. Without
    # this, the original calls stay inside the 30-min lookback and re-fire the HIR
    # every QA cycle even after it was resolved — an HIR storm against one target.
    resolved_age = _last_resolved_stuck_age(session_data, stuck_target, now)
    if resolved_age is not None:
        new_calls = sum(
            1 for e in tool_entries
            if e.get("target") == stuck_target
            and _ts_age_secs(e.get("ts", ""), now) < resolved_age  # newer than the resolution
        )
        if new_calls < 5:
            return None
        hit_count = new_calls
    else:
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
                f"with no finding logged and no coverage cell closed for it (flagged across "
                f"two QA cycles). It appears to be stuck investigating something it cannot "
                f"confirm or rule out."
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
                "with no finding or coverage progress — human guidance required"
            ),
        }

    # First detection — inject a directive, let Smith self-correct before escalating
    if not _qa._has_pending_directives():
        from core.steering import steering_queue, RESUME_TESTING
        steering_queue.add_directive(
            code=RESUME_TESTING,
            message=(
                f"You have run {hit_count} tools against '{stuck_target}' "
                "with no finding logged and no coverage cell closed. You may be stuck. "
                "Choose one: (1) Log what you observed as an informational finding and move on. "
                "(2) Run one final targeted attempt with a specific technique — then move on regardless. "
                "(3) Call session(action='intervene') if you genuinely cannot proceed without human input."
            ),
            priority="high", skill=None, trigger="STUCK_ON_TARGET",
        )
    return {
        "code": "STUCK_ON_TARGET", "urgency": "high", "blocking": False,
        "message": (
            f"Stuck on target: {hit_count} tool calls against '{stuck_target}', "
            "no finding/coverage progress — directive sent, HIR queued if unresolved"
        ),
    }
