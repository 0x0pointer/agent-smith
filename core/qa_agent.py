"""
QA Agent — depth enforcer
=========================
Depth-enforcement daemon. Runs every 2 minutes during an active scan.

Focus: push Smith to go deeper, not cut corners, and complete full scan cycles.
Not concerned with PoC files, coverage bookkeeping, scope housekeeping, or gate timers.

Two responsibilities:
1. Alert generation — coded alerts written to qa_state.json and surfaced in envelopes.
2. Steering directives — written to steering_queue.json, injected into Smith's next
   tool response automatically. One directive at a time — never pile on.

Alert schema
  {
    "code":     str,   — machine-readable code
    "urgency":  str,   — "high" | "medium" | "low"
    "blocking": bool,  — true = blocks scan completion
    "message":  str,   — human-readable description
  }

Checks kept:
  BULK_MARKING         — >10 N/A cells with no tested_by tool (blocking anti-shortcut)
  COVERAGE_INTEGRITY   — tested/vulnerable cells missing tested_by tool (blocking anti-shortcut)
  SUSPICIOUS_SPEED     — >20 cells closed in <10 min (shortcut detection)
  NA_ABUSE             — N/A rate >35% of addressed cells (shortcut detection)
  DEPTH_AFTER_FINDING  — high/critical finding >20 min old with no follow-up tools
  WHITEBOX_PASSES      — thorough scan with <3 semgrep passes (3-pass enforcement)
  PREMATURE_COMPLETE   — complete called before 3-pass requirement met
  TOOL_INACTIVITY      — no tool activity for >15 min (stall detection)
  NO_SPIDER            — httpx ran but spider never did (mandatory tool chain)
  MISSING_SKILL        — endpoint type discovered but required skill never invoked

Checks removed (as of 2025-05-22):
  POC_GAP, COVERAGE_STALL, SCOPE_DRIFT, INJECTION_BREADTH_GAP, ENDPOINT_TRIGGER_GAP,
  SPIDER_WITHOUT_COVERAGE
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

_log = logging.getLogger(__name__)
_REPO_ROOT      = Path(__file__).parent.parent
_QA_STATE_FILE  = _REPO_ROOT / "qa_state.json"
_SESSION_FILE   = _REPO_ROOT / "session.json"
_FINDINGS_FILE  = _REPO_ROOT / "findings.json"
_COVERAGE_FILE  = _REPO_ROOT / "coverage_matrix.json"
_STEERING_FILE  = _REPO_ROOT / "steering_queue.json"


def _has_pending_directives() -> bool:
    """Return True if Smith already has an unacknowledged directive in the queue."""
    try:
        data = json.loads(_STEERING_FILE.read_text()) if _STEERING_FILE.exists() else {}
        return any(
            d.get("status") in ("pending", "injected")
            for d in data.get("directives", [])
        )
    except Exception:
        return False


# ── Deterministic checks ──────────────────────────────────────────────────────

def _check_bulk_marking(entries: list[dict]) -> dict | None:
    """Block completion when >10 N/A cells have no tested_by tool."""
    cov_entries = [e for e in entries if e.get("type") == "COVERAGE"]
    if not cov_entries:
        return None
    na_untooled = cov_entries[-1].get("na_untooled", 0)
    if na_untooled <= 10:
        return None
    return {
        "code": "BULK_MARKING", "urgency": "high", "blocking": True,
        "message": f"Bulk-marking detected: {na_untooled} N/A cells have no tested_by tool — run actual tools before marking N/A",
    }


def _check_coverage_integrity(entries: list[dict]) -> dict | None:
    """Block completion when tested/vulnerable cells have no tested_by tool."""
    cov_entries = [e for e in entries if e.get("type") == "COVERAGE"]
    if not cov_entries:
        return None
    untooled = cov_entries[-1].get("untooled", 0)
    if untooled == 0:
        return None
    return {
        "code": "COVERAGE_INTEGRITY", "urgency": "high", "blocking": True,
        "message": f"Coverage integrity: {untooled} tested/vulnerable cells lack a tested_by tool — cite the artifact before closing",
    }


def _check_suspicious_speed(entries: list[dict]) -> dict | None:
    """Detect >20 coverage cells closed in <10 min — impossible at real test pace."""
    cov_entries = [e for e in entries if e.get("type") == "COVERAGE"]
    if len(cov_entries) < 2:
        return None
    now = datetime.now(timezone.utc)
    window = [
        e for e in cov_entries
        if _ts_age_secs(e.get("ts", ""), now) <= 600
    ]
    cells_closed = sum(e.get("cells_closed", 0) for e in window)
    if cells_closed <= 20:
        return None
    if not _has_pending_directives():
        from core.steering import steering_queue, RESUME_TESTING
        steering_queue.add_directive(
            code=RESUME_TESTING,
            message=(
                f"STOP — {cells_closed} cells closed in under 10 min. "
                "That pace is impossible with real tool runs. "
                "Pick your last 5 closed cells and re-test them with actual scanner output. "
                "Do not close another cell until you have run a tool and can cite the artifact_id."
            ),
            priority="high", skill=None, trigger="SUSPICIOUS_SPEED",
        )
    return {
        "code": "SUSPICIOUS_SPEED", "urgency": "high", "blocking": False,
        "message": f"Speed anomaly: {cells_closed} cells closed in <10 min — re-verify with real tool runs",
    }


def _check_na_abuse(coverage_data: dict) -> dict | None:
    """Detect N/A rate >35% of addressed cells."""
    matrix = coverage_data.get("matrix", [])
    if not matrix:
        return None
    addressed = [c for c in matrix if c.get("status") not in ("pending", None, "")]
    if len(addressed) < 10:
        return None
    na_count = sum(1 for c in addressed if c.get("status") == "not_applicable")
    rate = na_count / len(addressed)
    if rate <= 0.35:
        return None
    pct = int(rate * 100)
    if not _has_pending_directives():
        from core.steering import steering_queue, RESUME_TESTING
        steering_queue.add_directive(
            code=RESUME_TESTING,
            message=(
                f"N/A rate is {pct}% — too high. "
                "Pick 3 recent N/A cells and verify them with actual tools. "
                "N/A is only valid when the injection type structurally cannot apply "
                "(e.g. SSRF on a boolean param). Run a tool and cite the result before re-marking."
            ),
            priority="high", skill=None, trigger="NA_ABUSE",
        )
    return {
        "code": "NA_ABUSE", "urgency": "high", "blocking": False,
        "message": f"N/A abuse: {pct}% of addressed cells marked N/A ({na_count}/{len(addressed)}) — verify 3 recent N/A cells with tools",
    }


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
        if not _has_pending_directives():
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
    if not _has_pending_directives():
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
    if not _has_pending_directives():
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
        # Second consecutive cycle with the same target stuck — escalate to HIR
        try:
            from core import session as scan_session
            iv = scan_session.get_intervention()
            if not iv:  # Don't double-trigger if HIR is already active
                scan_session.trigger_intervention(
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
        except Exception:
            pass
        return {
            "code": "STUCK_ON_TARGET", "urgency": "high", "blocking": False,
            "message": (
                f"HIR triggered: Smith made {hit_count} tool calls against '{stuck_target}' "
                "over 30 min with no finding — human guidance required"
            ),
        }

    # First detection — inject a directive, let Smith self-correct before escalating
    if not _has_pending_directives():
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


def _check_no_spider_after_httpx(entries: list[dict]) -> dict | None:
    """Mandatory tool chain: httpx must be followed by spider."""
    tool_names = {e.get("name") for e in entries if e.get("type") == "TOOL"}
    if "httpx" not in tool_names:
        return None
    if any(e.get("type") == "SPIDER" for e in entries):
        return None
    return {
        "code": "NO_SPIDER", "urgency": "medium", "blocking": False,
        "message": "httpx confirmed web targets but spider never ran — run scan(tool='spider') to crawl the application",
    }


def _maybe_inject_web_exploit_directive(
    spider_ts: str, skills_run: set, now, alerts: list
) -> None:
    """Append MISSING_WEB_EXPLOIT alert and inject a directive when applicable."""
    if not spider_ts or "web-exploit" in skills_run:
        return
    age = _ts_age_secs(spider_ts, now)
    if age < 1200:  # 20 min grace — give Smith time to register endpoints first
        return
    alerts.append({
        "code": "MISSING_WEB_EXPLOIT", "urgency": "high", "blocking": False,
        "message": (
            f"Spider completed {int(age/60)}min ago but /web-exploit has never been invoked. "
            "This skill is mandatory — without it systematic injection testing won't happen."
        ),
    })
    if not _has_pending_directives():
        from core.steering import steering_queue, CHAIN_REQUIRED
        steering_queue.add_directive(
            code=CHAIN_REQUIRED,
            message=(
                "Spider has crawled the application but /web-exploit was never started. "
                "EXECUTE NOW: call session(action='set_skill', options={skill:'web-exploit', reason:'mandatory post-spider'}) "
                "then invoke the /web-exploit skill (Claude Code: Skill tool skill='web-exploit'; "
                "opencode/other: read ~/.config/opencode/commands/web-exploit.md and follow its workflow). "
                "Do not run any other tool until this skill is started."
            ),
            priority="high", skill="web-exploit", trigger="MISSING_WEB_EXPLOIT",
        )


def _maybe_inject_param_fuzz_directive(
    web_exploit_ts: str, skills_run: set, now, alerts: list
) -> None:
    """Append MISSING_PARAM_FUZZ alert and inject a directive when applicable."""
    if not web_exploit_ts or "param-fuzz" in skills_run:
        return
    age = _ts_age_secs(web_exploit_ts, now)
    if age < 1200:
        return
    alerts.append({
        "code": "MISSING_PARAM_FUZZ", "urgency": "high", "blocking": False,
        "message": (
            f"/web-exploit completed {int(age/60)}min ago but /param-fuzz has never been invoked. "
            "/param-fuzz is the next mandatory chain — it catches auth stripping, type confusion, "
            "mass assignment, and boundary violations that /web-exploit misses."
        ),
    })
    if not _has_pending_directives() and not any(a.get("code") == "MISSING_WEB_EXPLOIT" for a in alerts):
        from core.steering import steering_queue, CHAIN_REQUIRED
        steering_queue.add_directive(
            code=CHAIN_REQUIRED,
            message=(
                "/web-exploit is done but /param-fuzz was never chained. "
                "EXECUTE NOW: call session(action='set_skill', options={skill:'param-fuzz', reason:'mandatory chain after web-exploit'}) "
                "then invoke the /param-fuzz skill (Claude Code: Skill tool skill='param-fuzz'; "
                "opencode/other: read ~/.config/opencode/commands/param-fuzz.md and follow its workflow)."
            ),
            priority="high", skill="param-fuzz", trigger="MISSING_PARAM_FUZZ",
        )


def _maybe_inject_business_logic_directive(
    depth: str, skill_history: list, skills_run: set, now, alerts: list
) -> None:
    """Append MISSING_BUSINESS_LOGIC alert and inject a directive when applicable."""
    if not (
        depth == "thorough"
        and "web-exploit" in skills_run
        and "param-fuzz" in skills_run
        and "business-logic" not in skills_run
    ):
        return
    param_fuzz_entry = next((e for e in reversed(skill_history) if e.get("skill") == "param-fuzz"), None)
    param_fuzz_ts = param_fuzz_entry.get("ts", "") if param_fuzz_entry else ""
    if not param_fuzz_ts:
        return
    age = _ts_age_secs(param_fuzz_ts, now)
    if age < 1200:
        return
    alerts.append({
        "code": "MISSING_BUSINESS_LOGIC", "urgency": "medium", "blocking": False,
        "message": (
            "/web-exploit and /param-fuzz are done but /business-logic was never invoked. "
            "Thorough scans must test value/quantity abuse, workflow bypass, BOLA/BFLA, and state machine flaws."
        ),
    })
    if not _has_pending_directives() and not any(
        a.get("code") in ("MISSING_WEB_EXPLOIT", "MISSING_PARAM_FUZZ") for a in alerts
    ):
        from core.steering import steering_queue, CHAIN_REQUIRED
        steering_queue.add_directive(
            code=CHAIN_REQUIRED,
            message=(
                "Thorough scan: /business-logic has not been run. "
                "EXECUTE NOW: session(action='set_skill', options={skill:'business-logic', reason:'thorough depth requirement'}) "
                "then invoke the /business-logic skill (Claude Code: Skill tool skill='business-logic'; "
                "opencode/other: read ~/.config/opencode/commands/business-logic.md and follow its workflow)."
            ),
            priority="medium", skill="business-logic", trigger="MISSING_BUSINESS_LOGIC",
        )


def _check_core_skill_chain(entries: list[dict], session_data: dict) -> list[dict]:
    """Enforce the mandatory skill progression every web pentest must complete.

    Sequence enforced:
      spider ran → /web-exploit must follow (within 20 min of spider completing)
      /web-exploit done → /param-fuzz must chain (within 20 min of web-exploit)
      /web-exploit done → /business-logic must chain for thorough scans

    One directive at a time — skips injection when another directive is pending.
    """
    alerts: list[dict] = []
    now = datetime.now(timezone.utc)
    skill_history = session_data.get("skill_history", [])
    skills_run = {e["skill"] for e in skill_history}
    depth = session_data.get("depth", "")

    spider_entries = [e for e in entries if e.get("type") == "SPIDER"]
    spider_ts = spider_entries[-1].get("ts", "") if spider_entries else ""
    web_exploit_entry = next((e for e in reversed(skill_history) if e.get("skill") == "web-exploit"), None)
    web_exploit_ts = web_exploit_entry.get("ts", "") if web_exploit_entry else ""

    _maybe_inject_web_exploit_directive(spider_ts, skills_run, now, alerts)
    _maybe_inject_param_fuzz_directive(web_exploit_ts, skills_run, now, alerts)
    _maybe_inject_business_logic_directive(depth, skill_history, skills_run, now, alerts)

    return alerts


def _check_missing_skill(coverage_data: dict, session_data: dict) -> list[dict]:
    """Flag when a discovered endpoint type requires a skill that has never been invoked."""
    try:
        from core.session import _TRIGGER_MAP
        from core.coverage import classify_endpoint
    except Exception:
        return []

    _TYPE_TO_SKILL: dict[str, str] = {
        ep_type: entry["required_skills"][0]
        for ep_type, entry in _TRIGGER_MAP.items()
        if entry.get("required_skills")
    }

    endpoints = coverage_data.get("endpoints", [])
    if not endpoints:
        return []

    skill_history_skills = {e["skill"] for e in session_data.get("skill_history", [])}
    missing_by_type: dict[str, list[str]] = {}
    for ep in endpoints:
        ep_type = classify_endpoint(ep.get("path", ""))
        if not ep_type or ep_type not in _TYPE_TO_SKILL:
            continue
        skill = _TYPE_TO_SKILL[ep_type]
        if skill not in skill_history_skills:
            missing_by_type.setdefault(ep_type, []).append(ep.get("path", ""))

    alerts = []
    for ep_type, paths in missing_by_type.items():
        skill = _TYPE_TO_SKILL[ep_type]
        alerts.append({
            "code": "MISSING_SKILL", "urgency": "high", "blocking": False,
            "message": (
                f"{len(paths)} {ep_type} endpoint(s) found "
                f"({', '.join(paths[:3])}) but /{skill} has never been invoked"
            ),
        })
    return alerts


# ── HIR checks — conditions Smith cannot self-resolve ────────────────────────

def _hir(code: str, situation: str, tried: list[str], options: list[str]) -> None:
    """Trigger HIR if one is not already active. Always fires regardless of scan mode."""
    try:
        from core import session as scan_session
        if not scan_session.get_intervention():
            scan_session.trigger_intervention(code, situation, tried, options)
    except Exception:
        pass


def _check_auth_failure(entries: list[dict]) -> dict | None:
    """HIR when session auth appears to have expired mid-scan.

    Fires when >60% of the last 10 http_request calls return 401/403
    AND there were earlier successful (2xx) http calls — meaning auth worked before.
    """
    http_entries = [
        e for e in entries
        if e.get("type") == "TOOL" and e.get("name") == "http_request"
        and e.get("status_code")
    ]
    if len(http_entries) < 5:
        return None
    # Check if auth ever worked (any 2xx in history)
    ever_authed = any(200 <= e.get("status_code", 0) < 300 for e in http_entries)
    if not ever_authed:
        return None
    # Exclude credential-validation attempts (entries flagged as auth_attempt
    # by the envelope — request body contained password/secret/api_key/etc.,
    # or URL matched a known auth endpoint). 401s on those are credential
    # tests, not session expiry — counting them here causes false-positive HIRs
    # while Smith is actively logging in.
    recent = http_entries[-10:]
    non_auth_recent = [e for e in recent if not e.get("auth_attempt")]
    if len(non_auth_recent) < 5:
        return None  # too few non-auth signals to judge session validity
    auth_failures = [e for e in non_auth_recent if e.get("status_code") in (401, 403)]
    if len(auth_failures) / len(non_auth_recent) < 0.6:
        return None
    # Rebind `recent` for the message below so target/counts reflect the
    # signal we actually triggered on, not credential-attempt noise.
    recent = non_auth_recent
    target = recent[-1].get("target", "target")
    _hir(
        code="HIR_AUTH_FAILURE",
        situation=(
            f"{len(auth_failures)}/{len(recent)} recent HTTP requests to {target} "
            "returned 401/403 after previously authenticated calls succeeded. "
            "Session credentials appear to have expired or the account was locked."
        ),
        tried=[f"{len(auth_failures)} consecutive auth failures (401/403)"],
        options=[
            "RECREDENTIAL: Provide fresh session cookies or API tokens — I will inject them and resume",
            "REAUTH: Tell me the login endpoint and credentials — I will re-authenticate",
            "SKIP_AUTH: Continue with unauthenticated testing only and document the coverage gap",
            "ABORT: Stop the scan — auth cannot be recovered",
        ],
    )
    return {
        "code": "HIR_AUTH_FAILURE", "urgency": "high", "blocking": False,
        "message": f"Auth failure: {len(auth_failures)}/{len(recent)} recent requests returned 401/403 — session likely expired",
    }


def _check_budget_limit(session_data: dict, coverage_data: dict) -> dict | None:
    """HIR when tool call budget is >90% used but scan coverage is <80% complete."""
    calls_used = session_data.get("calls_used", 0)
    max_calls  = session_data.get("max_tool_calls", 0)
    if not max_calls or calls_used / max_calls < 0.9:
        return None
    meta = coverage_data.get("meta", {})
    total = meta.get("total_cells", 0)
    tested = meta.get("tested", 0) + meta.get("not_applicable", 0)
    coverage_pct = (tested / total) if total else 1.0
    if coverage_pct >= 0.8:
        return None  # Nearly done — let Smith finish
    remaining_calls = max_calls - calls_used
    pending_cells = total - tested
    _hir(
        code="HIR_BUDGET_LIMIT",
        situation=(
            f"{calls_used}/{max_calls} tool calls used ({int(calls_used/max_calls*100)}%) "
            f"but only {int(coverage_pct*100)}% of coverage complete "
            f"({pending_cells} cells pending, ~{remaining_calls} calls left). "
            "The scan cannot complete all planned testing within the current budget."
        ),
        tried=[f"{calls_used} tool calls consumed"],
        options=[
            "EXTEND: Increase max_tool_calls — specify new limit and I will continue",
            "PRIORITIZE: Tell me which endpoint types or findings to focus on — I will test those and skip the rest",
            "ACCEPT_PARTIAL: Complete now with documented coverage gaps in the report",
            "ABORT: Stop the scan immediately",
        ],
    )
    return {
        "code": "HIR_BUDGET_LIMIT", "urgency": "high", "blocking": False,
        "message": f"Budget at {int(calls_used/max_calls*100)}% with {int(coverage_pct*100)}% coverage done — {pending_cells} cells will be missed",
    }


def _check_zero_endpoints(entries: list[dict], coverage_data: dict) -> dict | None:
    """HIR when spider completed but found nothing and coverage matrix is still empty."""
    spider_entries = [e for e in entries if e.get("type") == "SPIDER"]
    if not spider_entries:
        return None
    last_spider = spider_entries[-1]
    if last_spider.get("endpoints_found", 1) > 0:
        return None
    if coverage_data.get("meta", {}).get("total_cells", 0) > 0:
        return None
    # Give Smith 10 min to register endpoints manually before firing
    now = datetime.now(timezone.utc)
    if _ts_age_secs(last_spider.get("ts", ""), now) < 600:
        return None
    target = last_spider.get("target", "target")
    _hir(
        code="HIR_NO_ENDPOINTS",
        situation=(
            f"Spider completed against {target} but found 0 endpoints, "
            "and the coverage matrix is still empty after 10 minutes. "
            "There is nothing to test — the application may require authentication, "
            "a specific entry point, or a different crawl mode."
        ),
        tried=["Spider completed with 0 endpoints discovered"],
        options=[
            "SEED_URLS: Provide specific URLs or API paths to test — I will register them manually and start testing",
            "AUTH_CRAWL: Provide session cookies or auth headers — I will re-spider with authentication",
            "PLAYWRIGHT: Switch to Playwright spider mode for JavaScript-heavy SPAs",
            "ABORT: Target is not crawlable — stop the scan",
        ],
    )
    return {
        "code": "HIR_NO_ENDPOINTS", "urgency": "high", "blocking": False,
        "message": f"Spider found 0 endpoints on {target} and coverage matrix is empty — cannot proceed without human input",
    }


def _check_target_unreachable(entries: list[dict]) -> dict | None:
    """HIR when 3+ consecutive tool calls to the same target all errored out."""
    tool_entries = [e for e in entries if e.get("type") == "TOOL"]
    if len(tool_entries) < 3:
        return None
    # Check last 5 entries for a run of errors on the same target
    recent = tool_entries[-5:]
    # Find longest consecutive error run
    run_target = None
    run_count = 0
    current_target = None
    current_count = 0
    for e in recent:
        t = e.get("target", "")
        if e.get("error") and t == current_target:
            current_count += 1
        elif e.get("error"):
            current_target = t
            current_count = 1
        else:
            current_target = None
            current_count = 0
        if current_count >= run_count:
            run_count = current_count
            run_target = current_target
    if run_count < 3 or not run_target:
        return None
    _hir(
        code="HIR_TARGET_UNREACHABLE",
        situation=(
            f"{run_count} consecutive tool calls to '{run_target}' all failed with errors. "
            "The target may be down, rate-limiting, or blocking scanner traffic."
        ),
        tried=[f"{run_count} consecutive failed tool calls to {run_target}"],
        options=[
            "WAIT: Target may be temporarily down — tell me how long to wait before retrying",
            "ROTATE: Provide an alternative IP, proxy, or User-Agent to bypass the block",
            "SKIP_TARGET: Mark this target as unreachable and continue with remaining scope",
            _ABORT_OPTION,
        ],
    )
    return {
        "code": "HIR_TARGET_UNREACHABLE", "urgency": "high", "blocking": False,
        "message": f"{run_count} consecutive errors against '{run_target}' — target may be down or blocking",
    }


def _check_exploit_escalation(entries: list[dict], findings_data: dict, session_data: dict) -> dict | None:
    """Benchmark mode only: push Smith to exploit critical/high findings deeper.

    In pentest mode this is a human decision (HIR). In benchmark mode, Smith should
    demonstrate full impact autonomously — this directive pushes it to do so instead of
    logging and moving on.

    Fires when a critical/high finding was logged >10 min ago with no exploitation
    tool (metasploit, kali, sqlmap) run against the same target since.
    """
    if session_data.get("scan_mode") != "benchmark":
        return None
    findings = [
        f for f in findings_data.get("findings", [])
        if f.get("severity") in ("critical", "high")
    ]
    if not findings:
        return None
    now = datetime.now(timezone.utc)
    _EXPLOIT_TOOLS = {"metasploit", "kali", "sqlmap", "kali_sqlmap"}
    for finding in findings:
        age_secs = _ts_age_secs(finding.get("ts", ""), now)
        if age_secs < 600:  # 10 min grace
            continue
        target = finding.get("target", "")
        exploit_tools_after = [
            e for e in entries
            if e.get("type") == "TOOL"
            and e.get("name", "") in _EXPLOIT_TOOLS
            and e.get("target", "") == target
            and e.get("ts", "") > finding.get("ts", "")
        ]
        if exploit_tools_after:
            continue
        age_mins = int(age_secs / 60)
        if not _has_pending_directives():
            from core.steering import steering_queue, RESUME_TESTING
            steering_queue.add_directive(
                code=RESUME_TESTING,
                message=(
                    f"[BENCHMARK] You found '{finding['title']}' ({finding['severity']}) "
                    f"{age_mins}min ago — demonstrate full impact. "
                    "Do NOT stop at the finding. Chain exploitation: "
                    "try privilege escalation, data extraction, lateral movement, or persistence. "
                    "Use kali(), metasploit, or sqlmap to prove the real-world impact. "
                    "Document every step as a finding before moving on."
                ),
                priority="high", skill=None, trigger="EXPLOIT_ESCALATION",
            )
        return {
            "code": "EXPLOIT_ESCALATION", "urgency": "high", "blocking": False,
            "message": f"[BENCHMARK] '{finding['title']}' found {age_mins}min ago — no exploitation follow-up yet",
        }
    return None


# Tools that run in-process (Python aiohttp / requests / playwright) and
# therefore have NO Docker dependency. Failure modes here are network /
# target / DNS / SSL, not container infrastructure.
_PYTHON_NATIVE_TOOLS = {"http_request", "spider"}
_ABORT_OPTION = "ABORT: Stop the scan"


def _check_repeated_tool_failure(entries: list[dict]) -> dict | None:
    """HIR when the same tool fails 3+ times in a row — likely an infrastructure issue.

    Message + remediation options are tool-aware: Python-native tools
    (http_request, spider) get a target-reachability framing; Docker-backed
    tools (kali, metasploit, nuclei, ...) keep the container/infra framing.
    """
    tool_entries = [e for e in entries if e.get("type") == "TOOL" and e.get("error")]
    if len(tool_entries) < 3:
        return None
    # Check if the last 3 error entries are from the same tool
    last_three = tool_entries[-3:]
    tools_in_run = {e.get("name") for e in last_three}
    if len(tools_in_run) != 1:
        return None  # Different tools failing — not an infra issue for one specific tool
    broken_tool = last_three[0].get("name", "unknown")
    # Only fire if all 3 are recent (last 20 min)
    now = datetime.now(timezone.utc)
    if any(_ts_age_secs(e.get("ts", ""), now) > 1200 for e in last_three):
        return None

    is_python_native = broken_tool in _PYTHON_NATIVE_TOOLS
    if is_python_native:
        situation = (
            f"Tool '{broken_tool}' has failed 3 times in a row in the last 20 minutes. "
            f"'{broken_tool}' runs in-process (Python aiohttp/requests) and has no "
            "container dependency — most likely a target reachability problem: target "
            "down, DNS failure, SSL/TLS error, or proxy/network block."
        )
        options = [
            "WAIT: Target may be temporarily down — tell me how long to wait before retrying",
            "VERIFY: Confirm the target URL is correct (DNS, port, scheme) and I will retry",
            "ROTATE: Provide an alternative proxy / User-Agent / endpoint to bypass blocks",
            "SKIP_TOOL: Stop using this tool and rely on alternatives for the rest of the scan",
            _ABORT_OPTION,
        ]
        message = (
            f"Tool '{broken_tool}' failed 3 times in a row — target reachability / network suspected"
        )
    else:
        situation = (
            f"Tool '{broken_tool}' has failed 3 times in a row in the last 20 minutes. "
            "This is likely a Docker/infrastructure issue rather than a target problem."
        )
        options = [
            "RESTART_INFRA: I will run session(action='start_kali') to restart the Kali container and retry",
            "SKIP_TOOL: Tell me to avoid this tool for the rest of the scan and use alternatives",
            "INVESTIGATE: Check the logs — run `docker ps` to verify containers are healthy",
            _ABORT_OPTION,
        ]
        message = (
            f"Tool '{broken_tool}' failed 3 times in a row — infrastructure issue suspected"
        )

    _hir(
        code="HIR_TOOL_FAILURE",
        situation=situation,
        tried=[f"'{broken_tool}' called 3 times, all failed with errors"],
        options=options,
    )
    return {
        "code": "HIR_TOOL_FAILURE", "urgency": "high", "blocking": False,
        "message": message,
    }


# ── Orchestrator ──────────────────────────────────────────────────────────────

def _deterministic_qa_checks(
    entries: list[dict],
    findings_data: dict,
    coverage_data: dict,
    session_data: dict,
    previous_alerts: list[dict] | None = None,
) -> list[dict]:
    """Run all checks. Priority order: blocking → HIR conditions → depth → stall → chain."""
    checks = [
        # Blocking anti-shortcuts (complete gate)
        _check_bulk_marking(entries),
        _check_coverage_integrity(entries),
        _check_premature_complete(entries, session_data),
        # HIR conditions — Smith cannot self-resolve these (suppressed in benchmark mode)
        _check_auth_failure(entries),
        _check_budget_limit(session_data, coverage_data),
        _check_zero_endpoints(entries, coverage_data),
        _check_target_unreachable(entries),
        _check_repeated_tool_failure(entries),
        _check_stuck_on_target(entries, findings_data, previous_alerts or []),
        # Benchmark-only: push exploitation instead of pausing
        _check_exploit_escalation(entries, findings_data, session_data),
        # Active shortcut detection
        _check_suspicious_speed(entries),
        _check_na_abuse(coverage_data),
        # Depth enforcement
        _check_depth_after_finding(entries, findings_data),
        _check_whitebox_passes(entries, session_data),
        # Stall detection
        _check_tool_inactivity(entries),
        # Mandatory tool / skill chain
        _check_no_spider_after_httpx(entries),
    ]
    alerts = [c for c in checks if c is not None]
    # Core skill sequence (spider → web-exploit → param-fuzz → business-logic)
    alerts.extend(_check_core_skill_chain(entries, session_data))
    # Endpoint-type triggered skills (graphql, auth, admin, upload, api, financial)
    alerts.extend(_check_missing_skill(coverage_data, session_data))
    return alerts


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ts_age_secs(ts: str, now: datetime) -> float:
    try:
        return (now - datetime.fromisoformat(ts)).total_seconds()
    except Exception:
        return 0.0


def _session_is_running() -> bool:
    try:
        return json.loads(_SESSION_FILE.read_text()).get("status") == "running"
    except Exception:
        return False


def _read_qa_state() -> dict:
    try:
        return json.loads(_QA_STATE_FILE.read_text()) if _QA_STATE_FILE.exists() else {}
    except Exception:
        return {}


def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text()) if path.exists() else {}
    except Exception:
        return {}


def _deduplicate(new_alerts: list[dict], previous_alerts: list[dict]) -> list[dict]:
    """Return only alerts whose message changed since the previous cycle."""
    prev_by_code = {a.get("code", ""): a for a in previous_alerts}
    return [
        a for a in new_alerts
        if prev_by_code.get(a.get("code", ""), {}).get("message") != a.get("message")
    ]


def _merge_alerts(unique_alerts: list[dict], all_alerts: list[dict], cap: int = 4) -> list[dict]:
    """Changed alerts first, then fill remaining slots with unchanged persistent ones."""
    seen: set[str] = set()
    merged: list[dict] = []
    for a in unique_alerts + all_alerts:
        code = a.get("code", "")
        if code not in seen:
            seen.add(code)
            merged.append(a)
    return merged[:cap]


def _sanitize_history(raw: list) -> list[dict]:
    result = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        reply = entry.get("smith_reply")
        result.append({
            "ts":            str(entry.get("ts", ""))[:50],
            "alerts":        [a for a in entry.get("alerts", []) if isinstance(a, dict)][:10],
            "smith_reply":   str(reply)[:2000] if reply else None,
            "smith_actions": [a for a in entry.get("smith_actions", []) if isinstance(a, dict)][:50],
        })
    return result


# ── Daemon ────────────────────────────────────────────────────────────────────

class QADaemon:
    async def run(self, interval_s: int = 120) -> None:
        _log.info("QA Daemon started (interval=%ds)", interval_s)
        while True:
            await asyncio.sleep(interval_s)
            try:
                await self._cycle()
            except Exception as exc:
                _log.warning("QA Daemon cycle error: %s", exc)

    async def _cycle(self) -> None:
        await asyncio.sleep(0)
        if not _session_is_running():
            return

        from core.quick_log import quick_log
        entries = quick_log.read_all()
        if not any(e.get("type") in ("TOOL", "SPIDER", "SKILL", "FINDING", "COVERAGE") for e in entries):
            return

        findings_data = _load_json(_FINDINGS_FILE)
        coverage_data = _load_json(_COVERAGE_FILE)
        session_data  = _load_json(_SESSION_FILE)

        existing        = _read_qa_state()
        previous_alerts = existing.get("alerts", [])

        determ_alerts = _deterministic_qa_checks(entries, findings_data, coverage_data, session_data, previous_alerts)

        unique_alerts = _deduplicate(determ_alerts, previous_alerts)
        if not unique_alerts and not determ_alerts:
            return

        final_alerts = _merge_alerts(unique_alerts, determ_alerts)

        ts_before = datetime.now(timezone.utc).isoformat()

        post_existing = _read_qa_state()
        history       = _sanitize_history(post_existing.get("history", []))
        prev_cycle_ts = history[-1]["ts"] if history else ""
        events_since  = quick_log.read_since(prev_cycle_ts) if prev_cycle_ts else []

        smith_reply = " ".join(
            e["message"] for e in events_since
            if e.get("type") == "QA_REPLY" and e.get("message")
        ).strip() or None
        smith_actions = [e for e in events_since if e.get("type") != "QA_REPLY"]

        history.append({
            "ts":            ts_before,
            "alerts":        final_alerts,
            "smith_reply":   smith_reply,
            "smith_actions": smith_actions,
        })

        _QA_STATE_FILE.write_text(json.dumps({  # NOSONAR
            "ts":      datetime.now(timezone.utc).isoformat(),
            "alerts":  final_alerts,
            "history": history[-20:],
        }))

        _log.info("QA Daemon: %d alert(s) written", len(final_alerts))

        # Out-of-band notification for new high-urgency alerts.
        # Notifier dedup (30 min window) prevents repeat spam on every cycle.
        try:
            from core.notifiers import notify as _notify
            for alert in unique_alerts:
                if alert.get("urgency") == "high":
                    _notify(
                        title=f"[QA] {alert['code']}",
                        body=alert.get("message", ""),
                        urgency="high",
                        code=alert["code"],
                    )
        except Exception:
            pass


qa_daemon = QADaemon()
