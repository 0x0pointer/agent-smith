"""
QA agent — orchestrator, alert plumbing, and the daemon loop.

``_deterministic_qa_checks`` runs every check in priority order and returns the
combined alert list. ``QADaemon`` reads the quick-log + state files every cycle,
runs the orchestrator (via the package, so tests patching
``core.qa_agent._deterministic_qa_checks`` take effect), dedups against the
previous cycle, persists qa_state.json, and fires high-urgency notifications.
File paths are read through ``core.qa_agent`` so the tests' path patches apply.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import core.qa_agent as _qa
from core import store as _store
from .checks_depth import (
    _check_chain_correlation,
    _check_depth_after_finding,
    _check_oob_unpolled,
    _check_premature_complete,
    _check_stuck_on_target,
    _check_tool_inactivity,
    _check_whitebox_passes,
)
from .checks_coverage import (
    _check_unregistered_findings,
)
from .checks_health import (
    _check_auth_failure,
    _check_budget_limit,
    _check_exploit_escalation,
    _check_repeated_tool_failure,
    _check_target_unreachable,
    _check_zero_endpoints,
)
from .checks_shortcuts import (
    _check_bulk_marking,
    _check_coverage_integrity,
    _check_na_abuse,
    _check_suspicious_speed,
)
from .checks_skills import (
    _check_core_skill_chain,
    _check_missing_skill,
    _check_no_spider_after_httpx,
    _check_post_exploit_depth,
)

_log = logging.getLogger(__name__)


# ── Orchestrator ──────────────────────────────────────────────────────────────

# Declarative check registry, in priority order: blocking → HIR conditions →
# benchmark → active-shortcut → depth → stall → mandatory chain. Each row is
# (check_fn, context-keys it consumes); the orchestrator passes those context
# values positionally and flattens dict|list results. Adding or reordering a
# check is a one-line edit here — the orchestrator loop never changes.
#
# Kept as one ordered table (rather than per-module self-registration) because
# the priority order interleaves modules and decides which alerts survive the
# 4-alert cap in QADaemon._cycle — so order is load-bearing, not cosmetic.
_CHECKS: list[tuple] = [
    # Blocking anti-shortcuts (complete gate)
    (_check_bulk_marking,          ("entries",)),
    (_check_coverage_integrity,    ("entries",)),
    (_check_unregistered_findings, ("findings_data", "coverage_data")),
    (_check_premature_complete,    ("entries", "session_data")),
    # HIR conditions — Smith cannot self-resolve these (suppressed in benchmark mode)
    (_check_auth_failure,          ("entries", "session_data", "previous_alerts")),
    (_check_budget_limit,          ("session_data", "coverage_data")),
    (_check_zero_endpoints,        ("entries", "coverage_data")),
    (_check_target_unreachable,    ("entries",)),
    (_check_repeated_tool_failure, ("entries",)),
    (_check_stuck_on_target,       ("entries", "findings_data", "session_data", "previous_alerts")),
    # Benchmark-only: push exploitation instead of pausing
    (_check_exploit_escalation,    ("entries", "findings_data", "session_data")),
    # Active shortcut detection
    (_check_suspicious_speed,      ("entries",)),
    (_check_na_abuse,              ("coverage_data",)),
    # Depth enforcement
    (_check_depth_after_finding,   ("entries", "findings_data")),
    (_check_chain_correlation,     ("findings_data",)),
    (_check_oob_unpolled,          ("session_data",)),
    (_check_whitebox_passes,       ("entries", "session_data")),
    # Stall detection
    (_check_tool_inactivity,       ("entries",)),
    # Mandatory tool / skill chain (core_skill_chain + missing_skill return lists)
    (_check_no_spider_after_httpx, ("entries",)),
    (_check_core_skill_chain,      ("entries", "session_data", "coverage_data")),
    (_check_missing_skill,         ("coverage_data", "session_data")),
    # Deep post-exploitation: RCE→shell, container escape, real lateral movement
    (_check_post_exploit_depth,    ("session_data",)),
]


def _deterministic_qa_checks(
    entries: list[dict],
    findings_data: dict,
    coverage_data: dict,
    session_data: dict,
    previous_alerts: list[dict] | None = None,
) -> list[dict]:
    """Run every registered check in priority order; flatten dict|list results.

    Behaviour matches the previous hardcoded list exactly: the same checks run
    in the same order, single-alert (dict) results are appended and list
    results (core_skill_chain, missing_skill) are extended.
    """
    ctx = {
        "entries":         entries,
        "findings_data":   findings_data,
        "coverage_data":   coverage_data,
        "session_data":    session_data,
        "previous_alerts": previous_alerts or [],
    }
    alerts: list[dict] = []
    for check, keys in _CHECKS:
        result = check(*(ctx[k] for k in keys))
        if result is None:
            continue
        if isinstance(result, list):
            alerts.extend(result)
        else:
            alerts.append(result)
    return alerts


# ── Helpers ───────────────────────────────────────────────────────────────────

def _session_is_running() -> bool:
    try:
        return json.loads(_qa._SESSION_FILE.read_text()).get("status") == "running"
    except Exception:
        return False


def _read_qa_state() -> dict:
    try:
        return json.loads(_qa._QA_STATE_FILE.read_text()) if _qa._QA_STATE_FILE.exists() else {}
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

        findings_data = _load_json(_qa._FINDINGS_FILE)
        coverage_data = _load_json(_qa._COVERAGE_FILE)
        session_data  = _load_json(_qa._SESSION_FILE)

        existing        = _read_qa_state()
        previous_alerts = existing.get("alerts", [])

        determ_alerts = _qa._deterministic_qa_checks(entries, findings_data, coverage_data, session_data, previous_alerts)

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

        _store.save(_qa._QA_STATE_FILE, {
            "ts":      datetime.now(timezone.utc).isoformat(),
            "alerts":  final_alerts,
            "history": history[-20:],
        }, indent=None)

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
