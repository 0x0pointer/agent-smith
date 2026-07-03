"""set_skill / set_step / set_codebase / pre_chain / artifact + skill-gate mgmt."""
import asyncio
import json
import os

from core import cost as cost_tracker
from core import findings as findings_store
from core import logger as log

import mcp_server.session_tools as _st


def _do_artifact(opts):
    """Retrieve raw tool output stored by the scan engine."""
    from mcp_server.scan_engine.artifacts import retrieve_artifact
    artifact_id = opts.get("id", "")
    if not artifact_id:
        return "Error: 'id' option is required"
    mode = opts.get("mode", "summary")
    max_chars = opts.get("max_chars", 4000)
    pattern = opts.get("pattern", "")
    return retrieve_artifact(artifact_id, mode=mode, max_chars=max_chars, pattern=pattern)



def _do_pre_chain(opts):
    """Checkpoint state before chaining to a new skill.

    Persists all state to disk so it survives compaction, then returns
    a summary of what the next skill needs to know.
    """
    next_skill = opts.get("next_skill", "")
    if not next_skill:
        return "Error: 'next_skill' option is required"

    current = _st.scan_session.get() or {}
    prev_skill = current.get("skill", "unknown")

    # Persist cost state
    cost_tracker.flush()

    # Calculate context savings estimate
    from core.coverage import get_matrix
    cov = get_matrix()
    meta = cov.get("meta", {})
    data = findings_store._load()

    # Set the new skill and log the chain decision
    chain_reason = f"chained from /{prev_skill}"
    _st.scan_session.set_skill(next_skill, reason=chain_reason, chained_from=prev_skill)
    log.skill_start(next_skill, reason=chain_reason, chained_from=prev_skill)

    result = {
        "action": "pre_chain",
        "previous_skill": prev_skill,
        "next_skill": next_skill,
        "state_persisted": {
            "findings": len(data.get("findings", [])),
            "diagrams": len(data.get("diagrams", [])),
            "coverage_cells": meta.get("total_cells", 0),
            "coverage_tested": meta.get("tested", 0),
            "coverage_pending": sum(1 for c in cov.get("matrix", []) if c["status"] == "pending"),
        },
        "context_recommendation": (
            f"RECOMMEND COMPACTION: The /{prev_skill} skill and its tool results are "
            f"no longer needed in context. All state is persisted to disk "
            f"(session.json, findings.json, coverage_matrix.json). "
            f"Compacting before loading /{next_skill} would free ~50-80k tokens "
            f"(~40% of context window). The /{next_skill} skill can recover "
            f"full state via session(action='recovery')."
        ),
    }

    return json.dumps(result, indent=2)


def _manage_skill_gates(skill_name: str, result: dict) -> list[str]:
    """Satisfy gates requiring skill_name, defer others. Returns list of satisfied gate IDs."""
    satisfied_gates: list[str] = []
    for gate in result.get("gates", []):
        if gate["status"] == "pending" and skill_name in gate["required_skills"]:
            _st.scan_session.satisfy_gate(gate["id"], skill_name)
            satisfied_gates.append(gate["id"])

    # Restore all previously deferred gates, then defer any that don't require THIS skill.
    # This ensures only the one gate relevant to the active skill fires per response.
    _st.scan_session.restore_gates()
    remaining_pending = _st.scan_session.pending_gates()
    gates_to_defer = [
        g["id"] for g in remaining_pending
        if skill_name not in g.get("required_skills", [])
    ]
    if gates_to_defer:
        _st.scan_session.defer_gates(gates_to_defer)
    return satisfied_gates


def _do_set_skill(opts):
    skill_name = opts.get("skill", "")
    reason = opts.get("reason", "")
    chained_from = opts.get("chained_from", "")
    if not skill_name:
        return "Error: 'skill' option is required"

    # Check for resume BEFORE set_skill appends (set_skill deduplicates silently)
    prior = _st.scan_session.get() or {}
    is_resume = skill_name in [
        (e["skill"] if isinstance(e, dict) else e)
        for e in prior.get("skill_history", [])
    ]

    result = _st.scan_session.set_skill(skill_name, reason=reason, chained_from=chained_from)
    if result is None:
        return "No active running session — cannot set skill."

    # SM-1: a loaded skill (30-44 KB) is now resident in the window — tell the
    # context meter so pressure reflects reality (only on a first load, not resume).
    if not is_resume:
        _st.scan_session.charge_skill_context(skill_name)

    satisfied_gates = _manage_skill_gates(skill_name, result)

    log.skill_start(skill_name, reason=reason, chained_from=chained_from)

    # Append SKILL entry to quick_log (fire-and-forget via asyncio)
    try:
        from core.quick_log import quick_log as _qlog
        _t = asyncio.create_task(_qlog.append({
            "type":         "SKILL",
            "name":         skill_name,
            "reason":       reason,
            "chained_from": chained_from or None,
        }))
        _st._background_tasks.add(_t)
        _t.add_done_callback(_st._background_tasks.discard)
    except Exception:
        pass

    # Auto-satisfy any CHAIN_REQUIRED steering directives for this skill
    try:
        from core.steering import steering_queue
        steering_queue.auto_satisfy(skill_name)
    except Exception:
        pass

    # Manual-setup prerequisites: if this skill ships a capabilities.yaml, open a
    # NON-blocking setup gate per declared capability. Absent file → no-op
    # (optimistic default). Fail-soft: a parse/load problem never breaks set_skill.
    setup_note = _enqueue_setup_gates(skill_name)

    # Detect post-compaction resume: skill was already in history before this call
    if is_resume:
        recovery_brief = _st._do_recovery()
        msg = (
            f"RESUME DETECTED: '{skill_name}' was already in skill history — "
            f"post-compaction context likely. Full recovery state follows:\n\n{recovery_brief}"
        )
        if satisfied_gates:
            msg += f"\n\n(satisfied gate(s): {', '.join(satisfied_gates)})"
        return msg + setup_note

    msg = f"Skill '{skill_name}' logged"
    if satisfied_gates:
        msg += f" (satisfied gate(s): {', '.join(satisfied_gates)})"
    return msg + setup_note


def _enqueue_setup_gates(skill_name: str) -> str:
    """Open setup gates from a skill's capabilities.yaml. Returns a note for the
    set_skill response (empty if the skill declares no manual prerequisites)."""
    try:
        from core import capabilities as _caps
        gates, warns = _caps.enqueue_for_skill(skill_name)
        for w in warns:
            log.note(f"capabilities[{skill_name}]: {w}")
        if not gates:
            return ""
        pending = [g["id"] for g in gates if g.get("status") in ("pending_election", "failed")]
        preelected = [g["id"] for g in gates if g.get("status") == "elected_now"]
        parts = []
        if pending:
            parts.append(
                f"MANUAL SETUP REQUIRED for '{skill_name}': {', '.join(pending)}. This skill declares "
                "manual prerequisite(s). For each, elect now/defer/skip via "
                "session(action='setup_gate', options={'action':'elect','id':'<id>','choice':'...'}) then verify "
                "with action='check'. Interactive → ask the operator; headless → default 'defer' (non-blocking)."
            )
        if preelected:
            parts.append(f"Pre-elected from known assets (still run check to verify): {', '.join(preelected)}.")
        return "\n\n" + " ".join(parts)
    # capabilities is opt-in; a load failure must never break set_skill
    except Exception as exc:  # noqa: BLE001
        log.note(f"capabilities load failed for {skill_name}: {exc}")
        return ""


def _do_set_step(opts):
    step = opts.get("step", "")
    if not step:
        return "Error: 'step' option is required"
    result = _st.scan_session.set_step(step)
    if result is None:
        return "No active running session — cannot set step."
    log.note(f"Step checkpoint: {step}")
    return f"Step checkpoint: {step}"


def _do_set_codebase(opts):
    path = opts.get("path", "")
    abs_path = os.path.abspath(path)
    if not os.path.isdir(abs_path):
        return f"Error: '{abs_path}' is not a directory"
    os.environ["PENTEST_TARGET_PATH"] = abs_path
    log.note(f"codebase target set to {abs_path}")
    return f"Codebase target set to: {abs_path}"
