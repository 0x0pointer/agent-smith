"""
Hard-limit enforcement + context pressure
==========================================
Cost/time/call-count limit checks (`check_limits`, `_stop`), the
dashboard "how much is left" view (`remaining`), and cumulative
context-window pressure tracking (`charge_context`, `get_context_pressure`).

Reaches the mutable session state in the ``core.session`` package namespace
via ``import core.session as _sess`` (``_sess._current`` / ``_sess._flush``),
read at call time so every name stays patchable and no import cycle forms.
"""
from __future__ import annotations

from datetime import datetime, timezone

import core.session as _sess


def check_limits(cost_summary: dict) -> str | None:
    """
    Check all hard limits against current cost/time/call data.
    Returns a stop-message if any limit is exceeded (return this directly
    to Claude as the tool result); returns None if the scan can continue.
    """
    if _sess._current is None or _sess._current["status"] != "running":
        return None

    lim = _sess._current["limits"]

    # ── Cost ──────────────────────────────────────────────────────────────────
    spent = cost_summary.get("est_cost_usd", 0)
    if lim["max_cost_usd"] is not None and spent >= lim["max_cost_usd"]:
        return _sess._stop(
            "limit_reached",
            f"COST LIMIT: ${spent:.4f} spent (limit ${lim['max_cost_usd']:.2f}). "
            "Do not run any more tools. Call complete_scan() and write the final report.",
        )

    # ── Time ──────────────────────────────────────────────────────────────────
    elapsed_min = (
        datetime.now(timezone.utc) - datetime.fromisoformat(_sess._current["started"])
    ).total_seconds() / 60
    if lim["max_time_minutes"] is not None and elapsed_min >= lim["max_time_minutes"]:
        return _sess._stop(
            "limit_reached",
            f"TIME LIMIT: {elapsed_min:.0f} min elapsed (limit {lim['max_time_minutes']} min). "
            "Do not run any more tools. Call complete_scan() and write the final report.",
        )

    # ── Tool calls (0 = unlimited) ────────────────────────────────────────────
    calls = cost_summary.get("tool_calls_total", 0)
    if lim["max_tool_calls"] > 0 and calls >= lim["max_tool_calls"]:
        return _sess._stop(
            "limit_reached",
            f"CALL LIMIT: {calls} tool calls made (limit {lim['max_tool_calls']}). "
            "Do not run any more tools. Call complete_scan() and write the final report.",
        )

    return None


def charge_context(chars: int) -> None:
    """Track cumulative response chars sent to the model."""
    if _sess._current and _sess._current.get("status") == "running":
        _sess._current["context_chars_sent"] = _sess._current.get("context_chars_sent", 0) + chars
        _sess._flush()


def get_context_pressure(profile: dict) -> float:
    """Return context pressure as 0.0-1.0 ratio. Returns 0.0 if no budget set."""
    if _sess._current is None:
        return 0.0
    budget = profile.get("context_budget_chars")
    if not budget:
        return 0.0
    sent = _sess._current.get("context_chars_sent", 0)
    return min(1.0, sent / budget)


def remaining(cost_summary: dict) -> dict:
    """Return how much budget/time/calls are left (for dashboard display)."""
    if _sess._current is None:
        return {}
    lim     = _sess._current["limits"]
    elapsed = (
        datetime.now(timezone.utc) - datetime.fromisoformat(_sess._current["started"])
    ).total_seconds() / 60
    spent   = cost_summary.get("est_cost_usd", 0)
    calls   = cost_summary.get("tool_calls_total", 0)
    max_calls = lim["max_tool_calls"]
    max_cost  = lim["max_cost_usd"]
    max_time  = lim["max_time_minutes"]
    return {
        "cost_remaining_usd":     None if max_cost is None else round(max(0, max_cost - spent), 4),
        "time_remaining_minutes": None if max_time is None else round(max(0, max_time - elapsed), 1),
        "calls_remaining":        max(0, max_calls - calls) if max_calls > 0 else -1,
        "cost_pct":               0 if max_cost is None else min(100, round(spent / max_cost * 100, 1)),
        "time_pct":               0 if max_time is None else min(100, round(elapsed / max_time * 100, 1)),
        "calls_pct":              min(100, round(calls / max_calls * 100, 1)) if max_calls > 0 else 0,
    }


def _stop(status: str, message: str) -> str:
    _sess._reconcile_if_external_write()
    if _sess._current:
        _sess._current["status"]      = status
        _sess._current["stop_reason"] = message
        _sess._current["finished"]    = datetime.now(timezone.utc).isoformat()
        _sess._flush()
    return message
