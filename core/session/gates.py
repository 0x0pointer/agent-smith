"""
Session gate tracking + skill/step bookkeeping.

Gates are conditions (RCE confirmed, auth service detected, an endpoint type
discovered) that make certain skills mandatory before completion. Also here:
the active-skill history, the current-step checkpoint, and the tools-called
list. Every mutator reads/writes session ``_current`` and persists it through
``core.session`` (the ``_sess`` alias) so the file path + cache stay canonical.
"""
from __future__ import annotations

from datetime import datetime, timezone

import core.session as _sess


def trigger_gate(gate_id: str, trigger: str, required_skills: list[str]) -> dict | None:
    """Register a mandatory gate — required skills must run before completion.

    Idempotent: re-triggering the same gate_id is a no-op. If the gate already
    exists but new required_skills are provided that weren't in the original,
    they are merged in.
    """
    _sess._reconcile_if_external_write()
    if _sess._current is None or _sess._current["status"] != "running":
        return None

    gates = _sess._current.setdefault("gates", [])
    for gate in gates:
        if gate["id"] == gate_id:
            # Merge any new required skills into existing gate
            for skill in required_skills:
                if skill not in gate["required_skills"]:
                    gate["required_skills"].append(skill)
                    gate["status"] = "pending"  # re-open if new skills added
            _sess._flush()
            return _sess._current

    gates.append({
        "id":               gate_id,
        "trigger":          trigger,
        "required_skills":  required_skills,
        "satisfied_skills": [],
        "status":           "pending",   # pending | satisfied
        "triggered_at":     datetime.now(timezone.utc).isoformat(),
    })
    _sess._flush()
    return _sess._current


def satisfy_gate(gate_id: str, skill_name: str) -> dict | None:
    """Mark a skill as satisfied within a gate.

    When all required_skills are satisfied, the gate status flips to 'satisfied'.
    """
    _sess._reconcile_if_external_write()
    if _sess._current is None:
        return None
    for gate in _sess._current.get("gates", []):
        if gate["id"] == gate_id:
            if skill_name not in gate["satisfied_skills"]:
                gate["satisfied_skills"].append(skill_name)
            if set(gate["required_skills"]).issubset(set(gate["satisfied_skills"])):
                gate["status"] = "satisfied"
            _sess._flush()
            return _sess._current
    return _sess._current


def pending_gates() -> list[dict]:
    """Return unsatisfied, non-deferred gates."""
    if _sess._current is None:
        return []
    deferred = set(_sess._current.get("deferred_gates", []))
    return [
        g for g in _sess._current.get("gates", [])
        if g.get("status") == "pending" and g.get("id", "") not in deferred
    ]


def defer_gates(gate_ids: list[str]) -> None:
    """Suppress the given gate IDs from pending_gates() until restore_gates() is called."""
    _sess._reconcile_if_external_write()
    if _sess._current is None:
        return
    deferred = _sess._current.setdefault("deferred_gates", [])
    for gid in gate_ids:
        if gid and gid not in deferred:
            deferred.append(gid)
    _sess._flush()


def restore_gates() -> None:
    """Clear all deferred gate IDs so they become visible again."""
    _sess._reconcile_if_external_write()
    if _sess._current is None:
        return
    _sess._current["deferred_gates"] = []
    _sess._flush()


def open_trigger_gate(endpoint_type: str, path: str) -> dict | None:
    """Open a mandatory gate based on endpoint type.

    Called by coverage.add_endpoint() after classifying the endpoint.
    Idempotent — re-triggering the same gate_id with the same skills is a no-op.
    Returns the session state or None if no gate is mapped to this type.
    """
    entry = _sess._TRIGGER_MAP.get(endpoint_type)
    if not entry:
        return None
    trigger_msg = f"{endpoint_type} endpoint discovered at {path}"
    return trigger_gate(entry["gate_id"], trigger_msg, entry["required_skills"])


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
    _sess._reconcile_if_external_write()
    if _sess._current is None or _sess._current["status"] != "running":
        return None
    _sess._current["skill"] = skill_name
    existing_skills = [e["skill"] for e in _sess._current["skill_history"]]
    if skill_name not in existing_skills:
        _sess._current["skill_history"].append({
            "skill":        skill_name,
            "reason":       reason,
            "chained_from": chained_from or None,
            "timestamp":    datetime.now(timezone.utc).isoformat(),
        })
    _sess._flush()
    return _sess._current


def set_step(step: str) -> dict | None:
    """Update the current workflow step checkpoint (e.g. '5_nuclei_scan')."""
    _sess._reconcile_if_external_write()
    if _sess._current is None or _sess._current["status"] != "running":
        return None
    _sess._current["current_step"] = step
    _sess._flush()
    return _sess._current


def add_tool_called(tool_name: str) -> None:
    """Persist a tool name to the tools_called list in session.json."""
    _sess._reconcile_if_external_write()
    if _sess._current and _sess._current["status"] == "running":
        tools = _sess._current.setdefault("tools_called", [])
        if tool_name not in tools:
            tools.append(tool_name)
            _sess._flush()
