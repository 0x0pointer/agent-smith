"""
Scan session
============
Defines the target, scope, depth, and hard limits for a pentest run.
A scan ends when Claude calls complete_scan() OR when any hard limit is hit —
whichever comes first.

Depth presets
-------------
  recon    — port scan + subdomains + HTTP probe only
             fast, low-noise, safe to run on most targets
             default limits: $0.10  |  15 min  |  10 tool calls

  standard — recon + nuclei vuln scan + directory fuzzing
             catches the most common issues without being too loud
             default limits: $0.50  |  45 min  |  25 tool calls

  thorough — standard + full Kali toolchain (nikto, sqlmap, testssl, …)
             comprehensive but noisy — confirm authorisation first
             default limits: $2.00  |  120 min  |  unlimited tool calls

Hard limit enforcement
----------------------
Call check_limits(cost_summary) before running any tool.
Returns a stop-message string when a limit is exceeded; None otherwise.
The stop message is returned directly to Claude as the tool result, which
causes it to stop invoking further tools and write the final report.

Output file
-----------
  session.json  (served by core/api_server.py at GET /api/session)
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from core import cost as cost_tracker

# ── Depth presets ─────────────────────────────────────────────────────────────

PRESETS: dict[str, dict] = {
    "recon": {
        "label":       "Recon only",
        "description": "Port scan · subdomain enum · HTTP probe — no active exploitation",
        "max_cost_usd":     0.10,
        "max_time_minutes": 15,
        "max_tool_calls":   10,
    },
    "standard": {
        "label":       "Standard",
        "description": "Recon + nuclei vulnerability scan + directory fuzzing",
        "max_cost_usd":     0.50,
        "max_time_minutes": 45,
        "max_tool_calls":   25,
    },
    "thorough": {
        "label":       "Thorough",
        "description": "Standard + full Kali toolchain (nikto, sqlmap, testssl, …)",
        "max_cost_usd":     2.00,
        "max_time_minutes": 120,
        "max_tool_calls":   0,       # 0 = unlimited — cost and time are the constraints
    },
}

_REPO_ROOT = Path(__file__).parent.parent
_SESSION_FILE = _REPO_ROOT / "session.json"

# ── In-memory state ───────────────────────────────────────────────────────────

_current: dict | None = None


# ── Public API ────────────────────────────────────────────────────────────────

def start(
    target:           str,
    depth:            str        = "standard",
    scope:            list[str]  | None = None,
    out_of_scope:     list[str]  | None = None,
    max_cost_usd:     float | None = None,
    max_time_minutes: int   | None = None,
    max_tool_calls:   int   | None = None,
) -> dict:
    """Initialise a new scan session and write session.json."""
    global _current

    # Reset cost/call counters from any previous session
    cost_tracker.reset()

    preset = PRESETS.get(depth, PRESETS["standard"])
    limits = {
        "max_cost_usd":     max_cost_usd     if max_cost_usd     is not None else preset["max_cost_usd"],
        "max_time_minutes": max_time_minutes  if max_time_minutes is not None else preset["max_time_minutes"],
        "max_tool_calls":   max_tool_calls    if max_tool_calls   is not None else preset["max_tool_calls"],
    }

    _current = {
        "id":           str(uuid.uuid4()),
        "target":       target,
        "depth":        depth,
        "depth_label":  preset["label"],
        "description":  preset["description"],
        "scope":        scope        or [target],
        "out_of_scope": out_of_scope or [],
        "started":      datetime.now(timezone.utc).isoformat(),
        "finished":     None,
        "status":       "running",   # running | limit_reached | complete
        "stop_reason":  None,
        "limits":       limits,
    }
    _flush()
    return _current


def check_limits(cost_summary: dict) -> str | None:
    """
    Check all hard limits against current cost/time/call data.
    Returns a stop-message if any limit is exceeded (return this directly
    to Claude as the tool result); returns None if the scan can continue.
    """
    if _current is None or _current["status"] != "running":
        return None

    lim = _current["limits"]

    # ── Cost ──────────────────────────────────────────────────────────────────
    spent = cost_summary.get("est_cost_usd", 0)
    if spent >= lim["max_cost_usd"]:
        return _stop(
            "limit_reached",
            f"COST LIMIT: ${spent:.4f} spent (limit ${lim['max_cost_usd']:.2f}). "
            "Do not run any more tools. Call complete_scan() and write the final report.",
        )

    # ── Time ──────────────────────────────────────────────────────────────────
    elapsed_min = (
        datetime.now(timezone.utc) - datetime.fromisoformat(_current["started"])
    ).total_seconds() / 60
    if elapsed_min >= lim["max_time_minutes"]:
        return _stop(
            "limit_reached",
            f"TIME LIMIT: {elapsed_min:.0f} min elapsed (limit {lim['max_time_minutes']} min). "
            "Do not run any more tools. Call complete_scan() and write the final report.",
        )

    # ── Tool calls (0 = unlimited) ────────────────────────────────────────────
    calls = cost_summary.get("tool_calls_total", 0)
    if lim["max_tool_calls"] > 0 and calls >= lim["max_tool_calls"]:
        return _stop(
            "limit_reached",
            f"CALL LIMIT: {calls} tool calls made (limit {lim['max_tool_calls']}). "
            "Do not run any more tools. Call complete_scan() and write the final report.",
        )

    return None


def complete(notes: str = "") -> dict:
    """Mark the scan as done (called by Claude when finished)."""
    global _current
    if _current and _current["status"] == "running":
        _current["status"]   = "complete"
        _current["finished"] = datetime.now(timezone.utc).isoformat()
        _current["notes"]    = notes
        _flush()
    return _current or {}


def get() -> dict | None:
    return _current


def remaining(cost_summary: dict) -> dict:
    """Return how much budget/time/calls are left (for dashboard display)."""
    if _current is None:
        return {}
    lim     = _current["limits"]
    elapsed = (
        datetime.now(timezone.utc) - datetime.fromisoformat(_current["started"])
    ).total_seconds() / 60
    spent   = cost_summary.get("est_cost_usd", 0)
    calls   = cost_summary.get("tool_calls_total", 0)
    max_calls = lim["max_tool_calls"]
    return {
        "cost_remaining_usd":     round(max(0, lim["max_cost_usd"] - spent), 4),
        "time_remaining_minutes": round(max(0, lim["max_time_minutes"] - elapsed), 1),
        "calls_remaining":        max(0, max_calls - calls) if max_calls > 0 else -1,
        "cost_pct":               min(100, round(spent / lim["max_cost_usd"] * 100, 1)),
        "time_pct":               min(100, round(elapsed / lim["max_time_minutes"] * 100, 1)),
        "calls_pct":              min(100, round(calls / max_calls * 100, 1)) if max_calls > 0 else 0,
    }


# ── Internal ──────────────────────────────────────────────────────────────────

def _stop(status: str, message: str) -> str:
    global _current
    if _current:
        _current["status"]      = status
        _current["stop_reason"] = message
        _current["finished"]    = datetime.now(timezone.utc).isoformat()
        _flush()
    return message


def _flush() -> None:
    if _current:
        _SESSION_FILE.write_text(json.dumps(_current, indent=2))
