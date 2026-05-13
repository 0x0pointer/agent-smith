"""
QA Agent
========
Deterministic QA reviewer + active steering daemon.

Runs every 2 minutes during an active scan. Two responsibilities:

1. Alert generation — coded alerts written to qa_state.json and injected into
   tool envelopes (via envelope P5.5). Purely observational — no blocking on
   most codes, completeness blocking only on BULK_MARKING and COVERAGE_INTEGRITY.

2. Steering directives — when Smith stalls, misses a skill chain, or leaves a gate
   open too long, the QA daemon writes a SteeringDirective to steering_queue.json.
   The envelope P5.7 injects pending directives directly into Smith's next tool
   response. No model action needed — Smith sees it automatically.

Alert schema
  {
    "code":     str,   — machine-readable code (SCOPE_DRIFT, COVERAGE_STALL, …)
    "urgency":  str,   — "high" | "medium" | "low"
    "blocking": bool,  — true = this alert blocks scan completion
    "message":  str,   — human-readable description
  }

All checks operate on structured data (session.json, coverage_matrix.json,
findings.json, quick_log entries). No regex parsing of summary text.
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

_DOCKER_ALIASES = {"host.docker.internal", "172.17.0.1", "172.18.0.1"}  # NOSONAR


def _norm_target(t: str) -> str:
    for alias in _DOCKER_ALIASES:
        t = t.replace(alias, "localhost")
    return t


# ── Deterministic checks — structured data only ───────────────────────────────

def _check_scope_drift(entries: list[dict], session_data: dict) -> dict | None:
    declared = _norm_target(session_data.get("target", ""))
    if not declared:
        return None
    off_scope: set[str] = set()
    for e in entries:
        if e.get("type") != "TOOL":
            continue
        tgt = _norm_target(e.get("target", ""))
        if tgt and declared not in tgt and tgt not in declared:
            off_scope.add(e.get("target", ""))
    if not off_scope:
        return None
    targets = ", ".join(list(off_scope)[:5])
    return {"code": "SCOPE_DRIFT", "urgency": "high", "blocking": False,
            "message": f"Scope drift: tools ran against {targets}"}


def _check_coverage_stall(coverage_data: dict, entries: list[dict]) -> dict | None:
    cov_entries = [e for e in entries if e.get("type") == "COVERAGE"]
    if not cov_entries:
        return None
    last = cov_entries[-1]
    pending = last.get("pending", 0)
    if pending == 0:
        return None
    try:
        last_ts = datetime.fromisoformat(last["ts"])
        mins = int((datetime.now(timezone.utc) - last_ts).total_seconds() / 60)
    except Exception:
        return None
    if mins < 15:
        return None
    from core.steering import steering_queue, RESUME_TESTING
    steering_queue.add_directive(
        code=RESUME_TESTING,
        message=(
            f"Coverage stalled {mins}min — {pending} cells pending. "
            "EXECUTE: session(action='recovery') then resume systematic testing from EXECUTE_NOW."
        ),
        priority="high",
        skill=None,
        trigger="COVERAGE_STALL",
    )
    return {"code": "COVERAGE_STALL", "urgency": "high", "blocking": False,
            "message": f"Coverage stall — {pending} cells untested, last update {mins}min ago"}


def _check_spider_without_coverage(entries: list[dict], coverage_data: dict) -> dict | None:
    spiders = [e for e in entries if e.get("type") == "SPIDER"]
    if not spiders:
        return None
    if coverage_data.get("meta", {}).get("total_cells", 0) != 0:
        return None
    count = spiders[-1].get("endpoints_found", "?")
    return {"code": "SPIDER_WITHOUT_COVERAGE", "urgency": "high", "blocking": False,
            "message": f"Spider found {count} endpoint(s) but coverage matrix is empty — register endpoints"}


def _check_poc_gap(findings_data: dict) -> dict | None:
    high_crit   = [f for f in findings_data.get("findings", [])
                   if f.get("severity") in ("high", "critical")]
    missing_poc = [f for f in high_crit if not f.get("poc_files")]
    if not missing_poc:
        return None
    titles = ", ".join(f["title"] for f in missing_poc[:3])
    if len(missing_poc) > 3:
        titles += f" +{len(missing_poc) - 3} more"
    from core.steering import steering_queue, POC_REQUIRED
    steering_queue.add_directive(
        code=POC_REQUIRED,
        message=(
            f"PoC required for {len(missing_poc)} high/critical finding(s): {titles}. "
            "Call http(action='save_poc', options={title: '...', finding_id: '<id>'}) for each."
        ),
        priority="high",
        skill=None,
        trigger="POC_GAP",
    )
    return {"code": "POC_GAP", "urgency": "high", "blocking": False,
            "message": f"PoC gap: {len(missing_poc)}/{len(high_crit)} high/critical findings have no saved PoC: {titles}"}


def _check_tool_inactivity(entries: list[dict]) -> dict | None:
    tools = [e for e in entries if e.get("type") in ("TOOL", "SPIDER")]
    if not tools:
        return None
    try:
        last_ts = datetime.fromisoformat(tools[-1]["ts"])
        mins = int((datetime.now(timezone.utc) - last_ts).total_seconds() / 60)
    except Exception:
        return None
    if mins <= 10:
        return None
    urgency = "high" if mins > 15 else "medium"
    alert = {"code": "TOOL_INACTIVITY", "urgency": urgency, "blocking": False,
             "message": f"No tool activity for {mins}min — Smith may have stalled or quit."}
    if mins > 15:
        from core.steering import steering_queue, RESUME_REQUIRED
        steering_queue.add_directive(
            code=RESUME_REQUIRED,
            message=(
                f"Smith stalled for {mins}min. "
                "EXECUTE: session(action='recovery') — then continue from EXECUTE_NOW field."
            ),
            priority="high",
            skill=None,
            trigger="TOOL_INACTIVITY",
        )
    return alert


def _check_bulk_marking(entries: list[dict]) -> dict | None:
    cov_entries = [e for e in entries if e.get("type") == "COVERAGE"]
    if not cov_entries:
        return None
    na_untooled = cov_entries[-1].get("na_untooled", 0)
    if na_untooled <= 10:
        return None
    return {"code": "BULK_MARKING", "urgency": "high", "blocking": True,
            "message": f"Bulk-marking detected: {na_untooled} N/A cells have no tested_by tool"}


def _check_coverage_integrity(entries: list[dict]) -> dict | None:
    cov_entries = [e for e in entries if e.get("type") == "COVERAGE"]
    if not cov_entries:
        return None
    untooled = cov_entries[-1].get("untooled", 0)
    if untooled == 0:
        return None
    return {"code": "COVERAGE_INTEGRITY", "urgency": "high", "blocking": True,
            "message": f"Coverage integrity: {untooled} tested/vulnerable cells lack tested_by tool"}


def _check_missing_diagram(findings_data: dict) -> dict | None:
    """Warn early when findings exist but no architecture diagram has been logged."""
    if not findings_data.get("findings"):
        return None
    if findings_data.get("diagrams"):
        return None
    return {"code": "NO_DIAGRAM", "urgency": "medium", "blocking": False,
            "message": "No architecture diagram yet — required before completion. Call report(action='diagram')."}


def _check_no_spider_after_httpx(entries: list[dict]) -> dict | None:
    """Warn if httpx confirmed web targets but spider was never run."""
    tool_names = {e.get("name") for e in entries if e.get("type") == "TOOL"}
    if "httpx" not in tool_names:
        return None
    if any(e.get("type") == "SPIDER" for e in entries):
        return None
    return {"code": "NO_SPIDER", "urgency": "medium", "blocking": False,
            "message": "httpx confirmed web targets but spider never ran — run scan(tool='spider') to crawl the application"}


def _check_endpoint_trigger_gaps(session_data: dict) -> list[dict]:
    """Fire targeted alerts for every pending trigger gate in the session."""
    alerts: list[dict] = []
    gates = session_data.get("gates", [])
    satisfied_skills = {e["skill"] for e in session_data.get("skill_history", [])}
    now = datetime.now(timezone.utc)
    for gate in gates:
        if gate.get("status") == "satisfied":
            continue
        required = gate.get("required_skills", [])
        missing   = [s for s in required if s not in satisfied_skills]
        if not missing:
            continue
        try:
            triggered_at = datetime.fromisoformat(gate["triggered_at"])
            elapsed = int((now - triggered_at).total_seconds() / 60)
        except Exception:
            elapsed = 0
        urgency = "high" if elapsed >= 15 else "medium"
        alerts.append({
            "code":     "ENDPOINT_TRIGGER_GAP",
            "urgency":  urgency,
            "blocking": False,
            "message":  (
                f"Gate '{gate['id']}' open {elapsed}min — "
                f"{gate.get('trigger','?')}. "
                f"Required skills not yet run: {', '.join(f'/{s}' for s in missing)}"
            ),
        })
        if elapsed >= 15:
            for skill in missing:
                from core.steering import steering_queue, CHAIN_REQUIRED
                steering_queue.add_directive(
                    code=CHAIN_REQUIRED,
                    message=(
                        f"Gate '{gate['id']}' open {elapsed}min — "
                        f"invoke /{skill} to satisfy it. "
                        "Use Skill tool: skill='" + skill + "'."
                    ),
                    priority="high",
                    skill=skill,
                    trigger="ENDPOINT_TRIGGER_GAP",
                )
    return alerts


def _check_coverage_gap(coverage_data: dict, session_data: dict) -> list[dict]:
    """Detect high-value endpoint types that appear in coverage but have no skill in history."""
    from core.session import _TRIGGER_MAP
    _TYPE_TO_SKILL: dict[str, str] = {
        ep_type: entry["required_skills"][0]
        for ep_type, entry in _TRIGGER_MAP.items()
        if entry.get("required_skills")
    }

    endpoints = coverage_data.get("endpoints", [])
    if not endpoints:
        return []

    try:
        from core.coverage import classify_endpoint
    except Exception:
        return []

    skill_history_skills = {e["skill"] for e in session_data.get("skill_history", [])}
    missing_by_type: dict[str, list[str]] = {}
    for ep in endpoints:
        path = ep.get("path", "")
        ep_type = classify_endpoint(path)
        if not ep_type or ep_type not in _TYPE_TO_SKILL:
            continue
        required_skill = _TYPE_TO_SKILL[ep_type]
        if required_skill not in skill_history_skills:
            missing_by_type.setdefault(ep_type, []).append(path)

    alerts: list[dict] = []
    for ep_type, paths in missing_by_type.items():
        skill = _TYPE_TO_SKILL[ep_type]
        sample = paths[:3]
        alerts.append({
            "code":     "COVERAGE_GAP",
            "urgency":  "high",
            "blocking": False,
            "message":  (
                f"Coverage gap: {len(paths)} {ep_type} endpoint(s) found "
                f"({', '.join(sample)}) but /{skill} skill not yet run"
            ),
        })
    return alerts


def _check_injection_breadth(coverage_data: dict) -> dict | None:
    """Fire when a text parameter has sqli cells but is missing xss/ssti/ssrf/cmdi cells."""
    _BREADTH_REQUIRED = {"xss", "ssti", "ssrf", "cmdi"}
    _TEXT_PARAM_TYPES = {"query", "body_form", "body_json", "path", "header", "cookie"}

    matrix = coverage_data.get("matrix", [])
    if not matrix:
        return None

    from collections import defaultdict
    by_param: dict[tuple, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    for cell in matrix:
        if cell.get("param_type") in _TEXT_PARAM_TYPES and cell.get("param") != "_endpoint":
            key = (cell["endpoint_id"], cell["param"])
            by_param[key][cell["injection_type"]].append(cell)

    gap_params: list[str] = []
    for (ep_id, param), inj_map in by_param.items():
        if "sqli" not in inj_map:
            continue
        missing = _BREADTH_REQUIRED - set(inj_map.keys())
        if missing:
            gap_params.append(f"{param} (missing: {', '.join(sorted(missing))})")

    if not gap_params:
        return None

    sample = "; ".join(gap_params[:4])
    more = f" (+{len(gap_params) - 4} more)" if len(gap_params) > 4 else ""
    return {
        "code": "INJECTION_BREADTH_GAP",
        "urgency": "high",
        "blocking": False,
        "message": (
            f"Injection breadth gap: {len(gap_params)} param(s) have sqli cells but "
            f"are missing xss/ssti/ssrf/cmdi cells. Re-register these endpoints so all "
            f"injection types are auto-generated, or add the missing cells manually: "
            f"{sample}{more}"
        ),
    }


def _deterministic_qa_checks(
    entries: list[dict],
    findings_data: dict,
    coverage_data: dict,
    session_data: dict,
) -> list[dict]:
    """Rule-based checks over structured state — no text parsing."""
    checks = [
        _check_scope_drift(entries, session_data),
        _check_coverage_stall(coverage_data, entries),
        _check_spider_without_coverage(entries, coverage_data),
        _check_poc_gap(findings_data),
        _check_tool_inactivity(entries),
        _check_bulk_marking(entries),
        _check_coverage_integrity(entries),
        _check_missing_diagram(findings_data),
        _check_no_spider_after_httpx(entries),
        _check_injection_breadth(coverage_data),
    ]
    alerts = [c for c in checks if c is not None]
    alerts.extend(_check_endpoint_trigger_gaps(session_data))
    alerts.extend(_check_coverage_gap(coverage_data, session_data))
    return alerts


# ── State helpers ─────────────────────────────────────────────────────────────

def _session_is_running() -> bool:
    try:
        data = json.loads(_SESSION_FILE.read_text())
        return data.get("status") == "running"
    except Exception:
        return False


def _read_qa_state() -> dict:
    if not _QA_STATE_FILE.exists():
        return {}
    try:
        return json.loads(_QA_STATE_FILE.read_text())
    except Exception:
        return {}


def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text()) if path.exists() else {}
    except Exception:
        return {}


def _deduplicate(new_alerts: list[dict], previous_alerts: list[dict]) -> list[dict]:
    """Return alerts whose code+message changed since last cycle."""
    _URGENCY = {"high": 2, "medium": 1, "low": 0}
    prev_by_code: dict[str, dict] = {}
    for a in previous_alerts:
        code = a.get("code", "")
        if code and (_URGENCY.get(a.get("urgency", ""), 0) >= _URGENCY.get(prev_by_code.get(code, {}).get("urgency", "low"), 0)):
            prev_by_code[code] = a

    result = []
    for a in new_alerts:
        prev = prev_by_code.get(a.get("code", ""))
        if prev and prev.get("message") == a.get("message"):
            continue  # unchanged — skip
        result.append(a)
    return result


def _merge_alerts(unique_alerts: list[dict], all_alerts: list[dict], cap: int = 4) -> list[dict]:
    """Merge changed alerts first, then fill with persistent unchanged ones.

    Fixes the deduplication bug where persistent alerts disappeared whenever
    any new alert fired. Changed alerts take priority; unchanged ones fill
    remaining slots so they stay visible.
    """
    seen_codes: set[str] = set()
    merged: list[dict] = []
    for a in unique_alerts:
        code = a.get("code", "")
        if code not in seen_codes:
            seen_codes.add(code)
            merged.append(a)
    for a in all_alerts:
        code = a.get("code", "")
        if code not in seen_codes:
            seen_codes.add(code)
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
        if not _session_is_running():
            return

        from core.quick_log import quick_log
        entries = quick_log.read_all()
        if not any(e.get("type") in ("TOOL", "SPIDER", "SKILL", "FINDING", "COVERAGE") for e in entries):
            return

        findings_data = _load_json(_FINDINGS_FILE)
        coverage_data = _load_json(_COVERAGE_FILE)
        session_data  = _load_json(_SESSION_FILE)

        determ_alerts = _deterministic_qa_checks(entries, findings_data, coverage_data, session_data)

        existing        = _read_qa_state()
        previous_alerts = existing.get("alerts", [])

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


qa_daemon = QADaemon()
