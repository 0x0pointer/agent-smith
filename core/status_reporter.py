"""
Periodic scan-status reporter — composes a short scan-status update for the
notifier sinks (Telegram / Slack / Discord) on a fixed cadence without
leaking sensitive information.

Composition is intentionally minimal:
  • Finding counts by severity (no titles, no descriptions, no targets)
  • Active skill names (skill identifiers only, no params)
  • Coverage stats (cells tested / pending — no endpoint paths)
  • Activity count (tool calls) over the lifetime of the scan

What we DO NOT include:
  • The target URL / IP / hostname
  • Finding titles, descriptions, evidence, CVE IDs
  • Endpoint paths or parameter names
  • Credentials / cookies / tokens
  • Anything an attacker / shoulder-surfer could use to identify the engagement

Public API:
  • should_emit() -> bool
        True when there's an active running scan worth reporting on.
  • compose_status_message() -> dict | None
        Returns {title, body, code, urgency} or None if not should_emit().
        Caller passes the dict to notifiers.notify(**msg).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from core import session as _session

_log = logging.getLogger(__name__)


# Severities we tally explicitly. Anything not in this list is bucketed
# under "other" — keeps a typo or future severity from going unreported.
_SEVERITIES = ("critical", "high", "medium", "low", "info")


def should_emit() -> bool:
    """True when there's an active scan worth reporting on.

    Idle dashboards stay quiet — the operator already chose this default
    so the status pings don't become background noise."""
    state = _session.get()
    if not state:
        return False
    return state.get("status") == "running"


def compose_status_message() -> dict[str, Any] | None:
    """Build the kwargs for notifiers.notify() — or None when idle.

    Returns a dict ready to splat: notifiers.notify(**compose_status_message()).
    The caller doesn't need to know about severity buckets or coverage.
    """
    state = _session.get()
    if not state or state.get("status") != "running":
        return None

    findings = _safe_findings_summary()
    coverage = _safe_coverage_summary()
    skills_total = _skills_run_count(state)
    skills_recent = _recent_skill_label(state)
    activity = _tool_calls_count(state)
    runtime_min = _elapsed_minutes(state)
    cost = _cost_estimate()

    title = "Scan status update"
    lines = [
        f"Findings: {findings['total']}",
        f"  Critical: {findings['critical']}    High: {findings['high']}",
        f"  Medium:   {findings['medium']}    Low:  {findings['low']}",
        f"  Info:     {findings['info']}",
    ]
    if findings.get("other"):
        lines.append(f"  Other:    {findings['other']}")
    lines.append("")
    lines.append(f"Skills run: {skills_total}")
    if skills_recent:
        lines.append(f"Latest skill: {skills_recent}")
    lines.append("")
    if coverage["total"]:
        pct = int(round(100 * coverage["tested"] / coverage["total"]))
        lines.append(f"Coverage: {coverage['tested']}/{coverage['total']} cells ({pct}%)")
        lines.append(f"Pending cells: {coverage['pending']}")
    else:
        lines.append("Coverage: no endpoints registered yet")
    lines.append("")
    lines.append(f"Activity: {activity} tool calls total")
    lines.append(f"Runtime: {runtime_min}m elapsed")
    if cost is not None:
        lines.append(f"Cost: ${cost:.2f} est.")

    body = "\n".join(lines)
    return {
        "title": title,
        "body": body,
        "urgency": "low",
        # Bucket the code by the wall-clock minute so two consecutive
        # status updates have different dedup keys (otherwise the 30-min
        # dedup window in BaseNotifier would suppress them).
        "code": "STATUS_UPDATE_" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M"),
    }


# ── internals ────────────────────────────────────────────────────────────────


def _safe_findings_summary() -> dict[str, int]:
    """Tally findings by severity. Never returns titles or descriptions."""
    out = {s: 0 for s in _SEVERITIES}
    out["other"] = 0
    try:
        from core import findings as _findings
        data = _findings._load()  # safe internal; we only read counts
    except Exception:
        out["total"] = 0
        return out

    entries = data.get("findings", []) if isinstance(data, dict) else []
    for entry in entries:
        sev = (entry.get("severity") or "").strip().lower()
        if sev in out:
            out[sev] += 1
        else:
            out["other"] += 1
    out["total"] = sum(out[s] for s in _SEVERITIES) + out["other"]
    return out


def _safe_coverage_summary() -> dict[str, int]:
    """Tally coverage cells by status. Never returns endpoint paths."""
    out = {"total": 0, "tested": 0, "pending": 0}
    try:
        from core import coverage as _coverage
        matrix = _coverage._load()
    except Exception:
        return out

    cells: list = []
    if isinstance(matrix, dict):
        for ep in matrix.get("endpoints", []) or []:
            ep_cells = ep.get("cells") or []
            cells.extend(ep_cells)
    out["total"] = len(cells)
    for c in cells:
        status = (c.get("status") or "").strip().lower()
        # Closed states count as "tested" regardless of finding outcome.
        if status in ("tested_clean", "vulnerable", "not_applicable", "skipped"):
            out["tested"] += 1
        else:
            out["pending"] += 1
    return out


def _skills_run_count(state: dict) -> int:
    """Distinct skill identifiers invoked during this scan."""
    history = state.get("skill_history") or []
    return len({entry.get("skill") for entry in history if entry.get("skill")})


def _recent_skill_label(state: dict) -> str:
    """The most recently invoked skill identifier (or empty string)."""
    history = state.get("skill_history") or []
    if not history:
        return ""
    last = history[-1]
    return (last.get("skill") or "").strip()


def _tool_calls_count(state: dict) -> int:
    """Total tool invocations recorded on the session."""
    invocations = state.get("tool_invocations") or []
    if isinstance(invocations, list):
        return len(invocations)
    return 0


def _elapsed_minutes(state: dict) -> int:
    """Wall-clock minutes since session start."""
    started_raw = state.get("started")
    if not started_raw:
        return 0
    try:
        started = datetime.fromisoformat(started_raw)
    except Exception:
        return 0
    delta = datetime.now(timezone.utc) - started
    return max(0, int(delta.total_seconds() // 60))


def _cost_estimate() -> float | None:
    """Returns the current est cost (USD) or None if unavailable."""
    try:
        from core import cost as _cost
        summary = _cost.get_summary()
        return float(summary.get("est_cost_usd", 0.0))
    except Exception:
        return None
