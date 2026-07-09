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
            # A skill-chain gate is satisfied only once the skill has actually DONE
            # WORK (a tool call fired while it was active), not on mere declaration —
            # set by add_tool_called, checked by skill_worked/reconcile_worked_gates.
            "worked":       False,
        })
    _sess._flush()
    return _sess._current


def skill_worked(skill_name: str) -> bool:
    """True ONLY when ``skill_name`` was DECLARED (set_skill) AND a tool fired WHILE
    IT WAS THE ACTIVE SKILL — the per-skill ``worked`` flag set by add_tool_called.

    A gate must not clear on bookkeeping. Declaring a skill's name is *not* running
    its workflow: to satisfy the gate the skill has to actually execute (invoke the
    Skill, work its phases, fire tools). Work must be attributable to THIS skill —
    a tool fired while it was active — not "the scan did some work overall".

    Previously this fell back to ``_scan_has_substantive_work()`` — true whenever the
    WHOLE scan had fired >=3 tools total, regardless of whether this skill did
    anything. That let a freshly-declared skill's gate clear instantly as long as
    EARLIER skills had already run tools (recon almost always has), i.e. a pure
    set_skill rubber-stamp cleared the gate. That fallback is removed: each skill now
    earns its own gate by doing its own work. (add_tool_called marks the active
    skill's history entry worked=True, so the proper flow — set_skill then run the
    skill — satisfies it naturally; declare-then-complete does not.)"""
    if _sess._current is None:
        return False
    return any(e.get("skill") == skill_name and e.get("worked")
               for e in _sess._current.get("skill_history", []))


def reconcile_worked_gates() -> None:
    """Satisfy each gate whose required skills have all done real work (see
    skill_worked). Called at completion-evaluation time so a legitimately-worked
    skill chain closes its gates, while a merely-declared one does not."""
    _sess._reconcile_if_external_write()
    if _sess._current is None:
        return
    for gate in _sess._current.get("gates", []):
        for skill in gate.get("required_skills", []):
            if skill_worked(skill) and skill not in gate.get("satisfied_skills", []):
                satisfy_gate(gate["id"], skill)


def set_step(step: str) -> dict | None:
    """Update the current workflow step checkpoint (e.g. '5_nuclei_scan')."""
    _sess._reconcile_if_external_write()
    if _sess._current is None or _sess._current["status"] != "running":
        return None
    _sess._current["current_step"] = step
    _sess._flush()
    return _sess._current


def maybe_advance_phase() -> str | None:
    """Saturation-driven three-phase transition (exploit → coverage → synthesis). Reads the
    live findings + coverage matrix, and if the current phase's goal is genuinely done,
    advances ONE step forward and persists it. Returns the new phase when it transitions,
    else None. Safe to call on any checkpoint (status / recovery / after a finding or cell) —
    it only moves forward and never budget/time-gates. See core/session/phases.py."""
    from core.session import phases as _phases
    _sess._reconcile_if_external_write()
    if _sess._current is None or _sess._current.get("status") != "running":
        return None
    cur = _phases.current_phase(_sess._current)
    try:
        from core import findings as _findings, coverage as _cov
        findings_data = _findings._load()
        matrix = _cov.get_matrix()
    except Exception:
        return None
    nxt = _phases.next_phase(cur, _sess._current, findings_data, matrix)
    if not nxt or nxt == cur:
        return None
    _sess._current["scan_phase"] = nxt
    _sess._flush()
    try:
        from core import logger as _log
        _log.note(f"PHASE_ADVANCE {cur} → {nxt}: {_phases.phase_label(nxt)}")
    except Exception:
        pass
    return nxt


def _mark_active_skill_worked() -> bool:
    """Flag the current active skill's history entry as having done work. Returns True
    if it changed anything (so the caller knows to flush)."""
    active = _sess._current.get("skill")
    if not active:
        return False
    for e in reversed(_sess._current.get("skill_history", [])):
        if e.get("skill") == active:
            if not e.get("worked"):
                e["worked"] = True
                return True
            return False
    return False


def add_tool_called(tool_name: str) -> None:
    """Persist a tool name to the tools_called list in session.json.

    Also marks the ACTIVE skill as having done work (worked=True) — a tool call
    fired while it was current — which is what lets its skill-chain gate be satisfied
    (skill_worked/reconcile_worked_gates), rather than a bare set_skill declaration."""
    _sess._reconcile_if_external_write()
    if not (_sess._current and _sess._current["status"] == "running"):
        return
    tools = _sess._current.setdefault("tools_called", [])
    changed = False
    if tool_name not in tools:
        tools.append(tool_name)
        changed = True
    if _mark_active_skill_worked():
        changed = True
    if changed:
        _sess._flush()
