"""
QA agent — mandatory skill-chain checks.

Enforce the universal progression (spider → /web-exploit → /param-fuzz →
/business-logic) and flag endpoint types whose required skill was never
invoked. Directives are injected one at a time — later chain steps hold off
while an earlier step's directive is still pending.
"""
from __future__ import annotations

from datetime import datetime, timezone

import core.qa_agent as _qa
from ._util import _ts_age_secs


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
    if not _qa._has_pending_directives():
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
    if not _qa._has_pending_directives() and not any(a.get("code") == "MISSING_WEB_EXPLOIT" for a in alerts):
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
    if not _qa._has_pending_directives() and not any(
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
