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
             default limits: $100.00  |  8 hours  |  unlimited tool calls

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
        "description": "Standard + full Kali toolchain — runs until complete (no cost/time cap)",
        "max_cost_usd":     None,
        "max_time_minutes": None,
        "max_tool_calls":   0,
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
    skill:            str   | None = None,
    model_profile:    str        = "full",
    scan_mode:        str        = "pentest",
) -> dict:
    """scan_mode: "pentest" (default) — HIR pauses for human decisions on ambiguous situations.
                  "benchmark" — fully autonomous, no HIR triggers, aggressive exploitation."""
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
        "skill":         skill,
        "skill_history": [
            {
                "skill":        skill,
                "reason":       "session start",
                "chained_from": None,
                "timestamp":    datetime.now(timezone.utc).isoformat(),
            }
        ] if skill else [],
        "tools_called":  [],
        "current_step":  None,
        "gates":         [],          # triggered gates that block completion
        "deferred_gates": [],         # gate IDs suppressed while a skill is active
        "spider_failures": {},        # targets where spider failed; cleared on success
        "model_profile": model_profile,
        "scan_mode":     scan_mode,
        "tool_invocations": [],
        "known_assets": {
            "domains": [], "ips": [], "ports": [],
            "technologies": [], "endpoints": [],
        },
        "context_chars_sent": 0,
        "complete_attempts":  0,        # incremented each time session(complete) is called
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
    if lim["max_cost_usd"] is not None and spent >= lim["max_cost_usd"]:
        return _stop(
            "limit_reached",
            f"COST LIMIT: ${spent:.4f} spent (limit ${lim['max_cost_usd']:.2f}). "
            "Do not run any more tools. Call complete_scan() and write the final report.",
        )

    # ── Time ──────────────────────────────────────────────────────────────────
    elapsed_min = (
        datetime.now(timezone.utc) - datetime.fromisoformat(_current["started"])
    ).total_seconds() / 60
    if lim["max_time_minutes"] is not None and elapsed_min >= lim["max_time_minutes"]:
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


def complete(
    notes: str = "",
    stop_reason: str | None = None,
    quality_gate: str | None = None,
) -> dict:
    """Mark the scan as done (called by Claude when finished).

    quality_gate="failed" sets status to "incomplete_with_unresolved_blockers"
    so dashboards and exports can distinguish a force-completed scan from a clean one.
    """
    global _current
    if _current and _current["status"] == "running":
        _current["status"]   = "incomplete_with_unresolved_blockers" if quality_gate == "failed" else "complete"
        _current["finished"] = datetime.now(timezone.utc).isoformat()
        _current["notes"]    = notes
        if quality_gate:
            _current["quality_gate"] = quality_gate
        if stop_reason is not None:
            _current["stop_reason"] = stop_reason
        _flush()
    return _current or {}


def get() -> dict | None:
    return _current


def set_skill(
    skill_name: str,
    reason: str = "",
    chained_from: str = "",
) -> dict | None:
    """Update the active skill (e.g. when chaining skills during a session).

    Each call appends a rich entry to skill_history with the reason for the
    choice and the parent skill when chaining.  Duplicate skill names are
    silently skipped so re-invoking the same skill mid-session is idempotent.
    """
    global _current
    if _current is None or _current["status"] != "running":
        return None
    _current["skill"] = skill_name
    existing_skills = [e["skill"] for e in _current["skill_history"]]
    if skill_name not in existing_skills:
        _current["skill_history"].append({
            "skill":        skill_name,
            "reason":       reason,
            "chained_from": chained_from or None,
            "timestamp":    datetime.now(timezone.utc).isoformat(),
        })
    _flush()
    return _current


def add_tool_called(tool_name: str) -> None:
    """Persist a tool name to the tools_called list in session.json."""
    if _current and _current["status"] == "running":
        tools = _current.setdefault("tools_called", [])
        if tool_name not in tools:
            tools.append(tool_name)
            _flush()


def set_step(step: str) -> dict | None:
    """Update the current workflow step checkpoint (e.g. '5_nuclei_scan')."""
    global _current
    if _current is None or _current["status"] != "running":
        return None
    _current["current_step"] = step
    _flush()
    return _current


# ── Gate tracking ────────────────────────────────────────────────────────────
# Gates are conditions triggered by events (e.g. RCE confirmed, auth service
# detected) that make certain skills mandatory before scan completion.
# Each gate lists required_skills; _do_complete() blocks until all are satisfied.

def trigger_gate(gate_id: str, trigger: str, required_skills: list[str]) -> dict | None:
    """Register a mandatory gate — required skills must run before completion.

    Idempotent: re-triggering the same gate_id is a no-op. If the gate already
    exists but new required_skills are provided that weren't in the original,
    they are merged in.
    """
    global _current
    if _current is None or _current["status"] != "running":
        return None

    gates = _current.setdefault("gates", [])
    for gate in gates:
        if gate["id"] == gate_id:
            # Merge any new required skills into existing gate
            for skill in required_skills:
                if skill not in gate["required_skills"]:
                    gate["required_skills"].append(skill)
                    gate["status"] = "pending"  # re-open if new skills added
            _flush()
            return _current

    gates.append({
        "id":               gate_id,
        "trigger":          trigger,
        "required_skills":  required_skills,
        "satisfied_skills": [],
        "status":           "pending",   # pending | satisfied
        "triggered_at":     datetime.now(timezone.utc).isoformat(),
    })
    _flush()
    return _current


def satisfy_gate(gate_id: str, skill_name: str) -> dict | None:
    """Mark a skill as satisfied within a gate.

    When all required_skills are satisfied, the gate status flips to 'satisfied'.
    """
    global _current
    if _current is None:
        return None
    for gate in _current.get("gates", []):
        if gate["id"] == gate_id:
            if skill_name not in gate["satisfied_skills"]:
                gate["satisfied_skills"].append(skill_name)
            if set(gate["required_skills"]).issubset(set(gate["satisfied_skills"])):
                gate["status"] = "satisfied"
            _flush()
            return _current
    return _current


def pending_gates() -> list[dict]:
    """Return unsatisfied, non-deferred gates."""
    if _current is None:
        return []
    deferred = set(_current.get("deferred_gates", []))
    return [
        g for g in _current.get("gates", [])
        if g.get("status") == "pending" and g.get("id", "") not in deferred
    ]


def defer_gates(gate_ids: list[str]) -> None:
    """Suppress the given gate IDs from pending_gates() until restore_gates() is called."""
    global _current
    if _current is None:
        return
    deferred = _current.setdefault("deferred_gates", [])
    for gid in gate_ids:
        if gid and gid not in deferred:
            deferred.append(gid)
    _flush()


def restore_gates() -> None:
    """Clear all deferred gate IDs so they become visible again."""
    global _current
    if _current is None:
        return
    _current["deferred_gates"] = []
    _flush()


# ── Spider failure gate ───────────────────────────────────────────────────────
# Tracks targets where spider failed to execute.  Any failure blocks all other
# scan tools until spider is retried successfully.  Auto-releases after
# _SPIDER_MAX_RETRIES attempts so a genuinely non-crawlable target doesn't
# loop forever.

_SPIDER_MAX_RETRIES = 3


def record_spider_failure(target: str) -> int:
    """Record a spider failure for this target.  Returns the new retry count."""
    global _current
    if _current is None or _current.get("status") != "running":
        return 0
    failures = _current.setdefault("spider_failures", {})
    entry = failures.get(target, {})
    new_count = entry.get("retry_count", 0) + 1
    failures[target] = {
        "target": target,
        "failed_at": datetime.now(timezone.utc).isoformat(),
        "retry_count": new_count,
    }
    _flush()
    return new_count


def clear_spider_failure(target: str) -> None:
    """Clear spider failure for this target after a successful run."""
    global _current
    if _current is None:
        return
    failures = _current.get("spider_failures")
    if failures and target in failures:
        del failures[target]
        _flush()


def has_spider_failure() -> bool:
    """Return True if any spider has failed and not yet recovered."""
    if _current is None:
        return False
    return bool(_current.get("spider_failures"))


def get_spider_failures() -> dict:
    """Return all current spider failure entries keyed by target URL."""
    if _current is None:
        return {}
    return dict(_current.get("spider_failures", {}))


def spider_max_retries() -> int:
    return _SPIDER_MAX_RETRIES


# ── Endpoint-type trigger gates ───────────────────────────────────────────────
# When an endpoint is registered with a recognised type tag, a mandatory gate
# is opened so the model must invoke the appropriate skill before completing.

_TRIGGER_MAP: dict[str, dict] = {
    "graphql":    {"gate_id": "graphql_coverage",   "required_skills": ["api-security"]},
    "auth":       {"gate_id": "auth_coverage",       "required_skills": ["credential-audit"]},
    "admin":      {"gate_id": "admin_coverage",      "required_skills": ["web-exploit"]},
    "upload":     {"gate_id": "upload_coverage",     "required_skills": ["web-exploit"]},
    "api":        {"gate_id": "api_coverage",        "required_skills": ["api-security"]},
    "financial":  {"gate_id": "financial_coverage",  "required_skills": ["business-logic"]},
    "websocket":  {"gate_id": "websocket_coverage",  "required_skills": ["web-exploit"]},
}


def open_trigger_gate(endpoint_type: str, path: str) -> dict | None:
    """Open a mandatory gate based on endpoint type.

    Called by coverage.add_endpoint() after classifying the endpoint.
    Idempotent — re-triggering the same gate_id with the same skills is a no-op.
    Returns the session state or None if no gate is mapped to this type.
    """
    entry = _TRIGGER_MAP.get(endpoint_type)
    if not entry:
        return None
    trigger_msg = f"{endpoint_type} endpoint discovered at {path}"
    return trigger_gate(entry["gate_id"], trigger_msg, entry["required_skills"])


def add_tool_invocation(tool: str, target: str, summary: str, options_hash: str = "") -> None:
    """Record a tool invocation with summary for dedup and recovery."""
    if not _current or _current.get("status") != "running":
        return
    invocations = _current.setdefault("tool_invocations", [])
    if options_hash and any(i.get("options_hash") == options_hash for i in invocations):
        return  # Duplicate — already recorded
    invocations.append({
        "seq": len(invocations) + 1,
        "tool": tool,
        "target": target,
        "options_hash": options_hash,
        "summary": summary[:200],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    if len(invocations) > 100:
        _current["tool_invocations"] = invocations[-100:]
    _flush()


def _update_ports_assets(assets: dict, items: list) -> None:
    """Deduplicate and append port entries to known_assets['ports']."""
    existing = {(p.get("host", ""), p.get("port", 0)) for p in assets.get("ports", [])}
    for item in items:
        if isinstance(item, dict):
            key = (item.get("host", ""), item.get("port", 0))
            if key not in existing:
                assets.setdefault("ports", []).append(item)
                existing.add(key)


def _update_scalar_assets(assets: dict, asset_type: str, items: list) -> None:
    """Deduplicate and append string/scalar entries to a known_assets list."""
    target_list = assets.setdefault(asset_type, [])
    existing = set(target_list)
    for item in items:
        val = item if isinstance(item, str) else str(item)
        if val and val not in existing:
            target_list.append(val)
            existing.add(val)


def update_known_assets(asset_type: str, items: list) -> None:
    """Accumulate discovered assets into session.json['known_assets']."""
    if not _current or _current.get("status") != "running" or not items:
        return
    assets = _current.setdefault("known_assets", {
        "domains": [], "ips": [], "ports": [],
        "technologies": [], "endpoints": [],
    })
    if asset_type == "ports":
        _update_ports_assets(assets, items)
    else:
        _update_scalar_assets(assets, asset_type, items)
    _flush()


def charge_context(chars: int) -> None:
    """Track cumulative response chars sent to the model."""
    if _current and _current.get("status") == "running":
        _current["context_chars_sent"] = _current.get("context_chars_sent", 0) + chars
        _flush()


def get_context_pressure(profile: dict) -> float:
    """Return context pressure as 0.0-1.0 ratio. Returns 0.0 if no budget set."""
    if _current is None:
        return 0.0
    budget = profile.get("context_budget_chars")
    if not budget:
        return 0.0
    sent = _current.get("context_chars_sent", 0)
    return min(1.0, sent / budget)


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


# ── Human Intervention Required ──────────────────────────────────────────────

def trigger_intervention(
    code: str,
    situation: str,
    tried: list[str],
    options: list[str],
) -> dict:
    """Transition session to intervention_required state.

    Pauses the scan — envelope.py blocks all non-session tool calls while in this state.
    The human responds via the dashboard or session(action='resume').
    """
    global _current
    if not _current:
        return {}
    _current["status"] = "intervention_required"
    _current["intervention"] = {
        "code":         code,
        "situation":    situation,
        "tried":        tried,
        "options":      options,
        "triggered_at": datetime.now(timezone.utc).isoformat(),
        "resolved_at":  None,
        "resolution":   None,
    }
    _flush()
    return _current


def resolve_intervention(choice: str, message: str = "") -> dict:
    """Human responded — transition back to running and record their decision."""
    global _current
    if not _current:
        return {}
    intervention = _current.get("intervention", {})
    if intervention:
        intervention["resolved_at"] = datetime.now(timezone.utc).isoformat()
        intervention["resolution"]  = {"choice": choice, "message": message}
    _current["status"] = "running"
    _current["intervention_history"] = _current.get("intervention_history", [])
    _current["intervention_history"].append(intervention)
    _current["intervention"] = None
    _flush()
    return _current


def get_intervention() -> dict | None:
    """Return current intervention dict if scan is paused, else None."""
    if not _current or _current.get("status") != "intervention_required":
        return None
    return _current.get("intervention")


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
