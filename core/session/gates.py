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
    """Return unsatisfied, non-deferred gates. A gate whose required skill still owes
    its MANUAL layer is annotated with ``deep_requirement_hint`` so the model sees WHY
    it can't clear the gate by, e.g., firing garak alone."""
    if _sess._current is None:
        return []
    deferred = set(_sess._current.get("deferred_gates", []))
    out: list[dict] = []
    for g in _sess._current.get("gates", []):
        if g.get("status") != "pending" or g.get("id", "") in deferred:
            continue
        hints = [h for h in (skill_deep_requirement_hint(s)
                             for s in g.get("required_skills", [])) if h]
        out.append({**g, "deep_requirement_hint": " ; ".join(hints)} if hints else g)
    return out


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


# ── Deep-work requirements ─────────────────────────────────────────────────────
# Skills whose completion gate needs MORE than "any tool fired" — a single automated
# tool is not the assessment. For such a skill the gate clears only when its MANUAL
# layer is attributable to it: the required tool fired under it (A), OR the coverage
# cells that layer produces are actually tested (B). Both paths are dischargeable, so
# the gate always terminates once the manual work is genuinely done.
_SKILL_DEEP_REQUIREMENTS = {
    # ai-redteam's automated half is garak; its manual half is the redteam() attack
    # engine (calibrate/filter_probe/feedback_attack — the k/N reproducibility). Garak
    # alone is NOT the assessment, so the gate needs redteam() to have fired OR the LLM
    # attack cells to be tested — otherwise the agent could fire garak once and leave.
    "ai-redteam": {
        "tool": "redteam",
        "coverage_types": ("jailbreak", "system_prompt_leak", "prompt_injection",
                           "sensitive_info_disclosure"),
        "hint": ("garak is only ai-redteam's automated half — run "
                 "redteam(action='feedback_attack') (the k/N attack engine), or test the "
                 "jailbreak / system_prompt_leak / prompt_injection cells, before this gate clears"),
    },
}


def _skill_did_tool(skill_name: str, tool_name: str) -> bool:
    """True if ``tool_name`` fired while ``skill_name`` was the active skill."""
    if not tool_name or _sess._current is None:
        return False
    return any(e.get("skill") == skill_name and tool_name in (e.get("tools") or [])
               for e in _sess._current.get("skill_history", []))


def _coverage_types_tested(types) -> bool:
    """True if at least one matrix cell of these injection types was actually TESTED
    (tested_clean/vulnerable — not merely deferred/NA). Deferred import + fail-soft so
    a coverage read never breaks gate evaluation."""
    if not types:
        return False
    try:
        import core.coverage as _cov
        cells = _cov._load().get("matrix", [])
    except Exception:
        return False
    tset = set(types)
    return any(c.get("injection_type") in tset and c.get("status") in ("tested_clean", "vulnerable")
               for c in cells)


def _deep_requirement_met(skill_name: str, req: dict) -> bool:
    """The skill's MANUAL layer ran: its required tool fired under it (A), OR the
    coverage cells that layer produces are tested (B)."""
    return (_skill_did_tool(skill_name, req.get("tool", ""))
            or _coverage_types_tested(req.get("coverage_types", ())))


def skill_deep_requirement_hint(skill_name: str) -> str:
    """Why a deep-work skill's gate is still open (for the model/dashboard), or '' if
    the skill has no deep requirement or it is already met."""
    req = _SKILL_DEEP_REQUIREMENTS.get(skill_name)
    if not req or _deep_requirement_met(skill_name, req):
        return ""
    return req.get("hint", "")


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
    earns its own gate by doing its own work.

    A skill in ``_SKILL_DEEP_REQUIREMENTS`` (e.g. ai-redteam) needs MORE than "a tool
    fired": its MANUAL layer must be attributable to it too (see _deep_requirement_met),
    so firing garak once can no longer clear the ai-redteam gate — the redteam() attack
    engine must run, or its LLM attack cells must be tested."""
    if _sess._current is None:
        return False
    if not any(e.get("skill") == skill_name and e.get("worked")
               for e in _sess._current.get("skill_history", [])):
        return False
    req = _SKILL_DEEP_REQUIREMENTS.get(skill_name)
    if req and not _deep_requirement_met(skill_name, req):
        return False
    return True


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
    """Phases are OPERATOR-GATED — this NO LONGER auto-advances. Auto-advancing on a saturation
    check risked a buggy/early check cutting the deep Phase-A pass short (exactly what the operator
    wants to avoid: Phase A should run thorough and unbounded until the human says otherwise). This
    now only computes an ADVISORY hint — whether the current phase LOOKS saturated, i.e. which phase
    the operator COULD advance to — stores it on the session as `phase_advice` for the dashboard,
    and returns None. The phase only changes via advance_phase() (dashboard button / typed
    'advance to phase B' steer). Kept as a callable no-op so its existing callers
    (status / recovery / completion) stay valid without auto-advancing."""
    from core.session import phases as _phases
    _sess._reconcile_if_external_write()
    if _sess._current is None or _sess._current.get("status") != "running":
        return None
    cur = _phases.current_phase(_sess._current)
    try:
        from core import findings as _findings, coverage as _cov
        advice = _phases.next_phase(cur, _sess._current, _findings._load(), _cov.get_matrix())
    except Exception:
        advice = None
    if _sess._current.get("phase_advice") != advice:
        _sess._current["phase_advice"] = advice
        _sess._flush()
    return None   # never auto-advances — the operator decides via advance_phase()


def advance_phase(target: str | None = None) -> dict:
    """OPERATOR-gated phase advance (dashboard button / typed steer). Moves scan_phase FORWARD one
    step (exploit → coverage → synthesis), or directly to `target` if it is forward of the current
    phase. Never backward, never past synthesis. IGNORES saturation — the human decides when Phase
    A's deep pass is done, so nothing can cut it short. Persists + logs PHASE_ADVANCE (operator).
    Returns {ok, from, to} (with `error` when it can't advance)."""
    from core.session import phases as _phases
    _sess._reconcile_if_external_write()
    if _sess._current is None or _sess._current.get("status") != "running":
        return {"ok": False, "error": "no running scan"}
    cur = _phases.current_phase(_sess._current)
    if target:
        alias = {"a": _phases.EXPLOIT, "b": _phases.COVERAGE, "c": _phases.SYNTHESIS,
                 "exploit": _phases.EXPLOIT, "coverage": _phases.COVERAGE, "synthesis": _phases.SYNTHESIS}
        target = alias.get(str(target).strip().lower(), str(target).strip().lower())
        if target not in _phases.PHASES:
            return {"ok": False, "error": f"unknown phase '{target}'", "from": cur, "to": cur}
        if _phases.PHASES.index(target) <= _phases.PHASES.index(cur):
            return {"ok": False, "error": f"phase '{target}' is not forward of '{cur}'",
                    "from": cur, "to": cur}
        nxt = target
    else:
        nxt = _phases.forced_next(cur)
    if not nxt:
        return {"ok": False, "error": "already at the final phase (synthesis)", "from": cur, "to": cur}
    _sess._current["scan_phase"] = nxt
    _sess._current["phase_advice"] = None
    _sess._flush()
    try:
        from core import logger as _log
        _log.note(f"PHASE_ADVANCE {cur} → {nxt} (operator): {_phases.phase_label(nxt)}")
    except Exception:
        pass
    return {"ok": True, "from": cur, "to": nxt}


def _mark_active_skill_worked(tool_name: str = "") -> bool:
    """Flag the current active skill's history entry as having done work, and record
    the tool that fired under it (so a deep-work gate can require a SPECIFIC tool, not
    just "any tool"). Returns True if it changed anything (so the caller knows to flush)."""
    active = _sess._current.get("skill")
    if not active:
        return False
    for e in reversed(_sess._current.get("skill_history", [])):
        if e.get("skill") == active:
            changed = False
            if not e.get("worked"):
                e["worked"] = True
                changed = True
            if tool_name:
                tools = e.setdefault("tools", [])
                if tool_name not in tools:
                    tools.append(tool_name)
                    changed = True
            return changed
    return False


def add_tool_called(tool_name: str, target: str = "") -> None:
    """Persist a tool name to the tools_called list in session.json.

    Also marks the ACTIVE skill as having done work (worked=True) — a tool call
    fired while it was current — which is what lets its skill-chain gate be satisfied
    (skill_worked/reconcile_worked_gates), rather than a bare set_skill declaration.

    ``target`` (PR-C, optional): the tool's target (host/URL/CVE arg). Used ONLY by
    the advisory surface-coverage ledger to attribute per-instance coverage to the
    active skill — it never affects the blocking gate flags above."""
    _sess._reconcile_if_external_write()
    if not (_sess._current and _sess._current["status"] == "running"):
        return
    tools = _sess._current.setdefault("tools_called", [])
    changed = False
    if tool_name not in tools:
        tools.append(tool_name)
        changed = True
    if _mark_active_skill_worked(tool_name):
        changed = True
    if changed:
        _sess._flush()
    # PR-C: advisory per-instance coverage attribution. add_tool_called already knows
    # the active skill; the ledger maps the tool's target to a discovered instance of
    # that skill's unit and marks it covered. NON-BLOCKING + fail-soft — a ledger error
    # must never break a tool call, and this never touches the worked/gate state above.
    try:
        from core.session import surface_ledger as _ledger
        _ledger.attribute_covered(tool_name, target)
    except Exception:
        pass
