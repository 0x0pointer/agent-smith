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
    result = retrieve_artifact(artifact_id, mode=mode, max_chars=max_chars, pattern=pattern)
    # Make the context meter honest: artifact retrieval bypasses the wrap() path, so
    # without this the pressure gauge is blind to (now-bounded) pulls into the window.
    try:
        _st.scan_session.charge_context(len(result))
    except Exception:
        pass
    return result



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
        # Satisfy only when the skill has actually done work — a bare set_skill
        # declaration must NOT clear a completion gate (enforce-properly). The
        # completion path also runs reconcile_worked_gates() as the backstop.
        if (gate["status"] == "pending" and skill_name in gate["required_skills"]
                and _st.scan_session.skill_worked(skill_name)):
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


# Minimum rationale length for an honest 'not applicable' dismissal — long enough to
# force a real dead-end justification, short enough not to be busywork.
_DISMISS_MIN_RATIONALE = 30


def _do_dismiss_gate(opts):
    """session(action='dismiss_gate') — close a pending skill-chain gate as a documented
    dead-end when its required skill genuinely cannot run on this target (false-positive
    trigger / absent precondition). The honest alternative to re-chaining an un-runnable
    skill forever; NOT a way to skip real work (substantive rationale required, logged,
    operator-reviewable)."""
    gate_id = (opts.get("gate_id") or "").strip()
    rationale = (opts.get("rationale") or "").strip()
    evidence = (opts.get("evidence") or opts.get("evidence_finding_id") or "").strip()
    if not gate_id:
        return "dismiss_gate requires options.gate_id (the pending gate to dismiss)."
    if len(rationale) < _DISMISS_MIN_RATIONALE:
        return (
            "dismiss_gate requires a substantive options.rationale (>=30 chars) documenting WHY the "
            "required skill is not applicable on THIS target — e.g. 'post_exploit_rce was triggered "
            "by a false RCE-confirmed signal; the only related finding is a debug info leak, no "
            "command execution exists, so reverse-shell has nothing to launch'. This records an "
            "honest dead-end; it is not a way to skip work the skill could actually do.")
    gate = _st.scan_session.dismiss_gate(gate_id, rationale, evidence)
    if gate is None:
        existing = {g["id"]: g.get("status") for g in (_st.scan_session.get() or {}).get("gates", [])}
        if gate_id not in existing:
            return f"No gate '{gate_id}'. Current gates: {existing or '(none)'}."
        return (f"Gate '{gate_id}' is '{existing[gate_id]}', not pending — nothing to dismiss "
                "(only a pending gate can be marked not applicable).")
    return (
        f"Gate '{gate_id}' marked NOT APPLICABLE (documented dead-end): {rationale[:160]}. "
        "It no longer blocks completion or appears in the keep-working directive. The operator "
        "can re-open it from the dashboard if this target does warrant the skill. Continue with "
        "the remaining pending coverage/gates.")


# ── Recall reflex (plan 5.1e) — presence-gated per-skill KB nudge ──────────────
# skill → (scope string, what recall pulls for it). Scope tokens are FILTERED against
# kb_status() so the agent is only ever pointed at a tier that actually has content;
# if nothing is set up, no hint is emitted at all (silent for no-KB users).
_TIER_A_KINDS = {"cve", "exploit", "nuclei", "gtfobins", "lolbas", "wstg", "skill_ref", "kb"}
_SCOPE_DOCS_WSTG = "docs+wstg+skill_ref"   # app docs + methodology + our playbooks
_SKILL_RECALL_SCOPES = {
    "pentester":        ("docs+engagements", "the target's own API/architecture/business-rule docs you attached + what prior engagements found"),
    "web-exploit":      (_SCOPE_DOCS_WSTG, "the app's endpoint/API docs + the WSTG procedure and playbooks for this endpoint class"),
    "param-fuzz":       ("wstg+skill_ref+docs", "parameter / mass-assignment testing procedure + any API spec you attached"),
    "business-logic":   ("docs+engagements+skill_ref", "the app's business rules / workflows from attached docs + prior-engagement notes"),
    "api-security":     (_SCOPE_DOCS_WSTG, "the OpenAPI/GraphQL spec you attached + API testing methodology"),
    "ai-redteam":       ("docs+skill_ref", "the app's AI/LLM architecture docs + the LLM red-team playbooks"),
    "analyze-cve":      ("cve+exploit+nuclei", "the NVD entry + ExploitDB/nuclei PoCs for the CVE"),
    "metasploit":       ("cve+exploit", "the CVE detail + exploit modules"),
    "post-exploit":     ("gtfobins+lolbas+skill_ref", "GTFOBins/LOLBAS abuse for any binary you find on the host"),
    "credential-audit": (_SCOPE_DOCS_WSTG, "the app's auth-flow docs + auth / session testing methodology"),
    "network-assess":   ("skill_ref+engagements", "network-recon playbooks + prior-engagement topology"),
    "lateral-movement": ("gtfobins+lolbas+skill_ref", "living-off-the-land binaries + lateral-movement techniques"),
    "cloud-security":   ("docs+skill_ref", "any cloud-account docs you attached + cloud IAM/storage playbooks"),
}
_DEFAULT_RECALL = ("all", "relevant references and any engagement docs you attached")


def _filter_scope(scope: str, status: dict) -> str:
    """Keep only scope tokens whose tier actually has content (per kb_status)."""
    kb_ok, docs_ok, eng_ok = status.get("kb"), status.get("docs"), status.get("engagements")
    available_all = [t for t, ok in (("kb", kb_ok), ("docs", docs_ok), ("engagements", eng_ok)) if ok]
    out: list[str] = []
    for raw in scope.split("+"):
        tok = raw.strip().lower()
        if tok == "all":
            out += available_all
        elif tok in _TIER_A_KINDS and kb_ok:
            out.append(tok)
        elif tok == "docs" and docs_ok:
            out.append("docs")
        elif tok == "engagements" and eng_ok:
            out.append("engagements")
    return "+".join(dict.fromkeys(out))   # de-dup, order-preserving


def _recall_hint(skill_name: str) -> str:
    """Presence-gated recall nudge appended to the set_skill response. Empty when no
    KB/docs are configured (silent for no-KB users) or nothing relevant to this skill
    is available. Fail-soft — never breaks set_skill."""
    try:
        from core.kb import kb_status
        status = kb_status()
        if not status.get("any"):
            return ""
        scope, intent = _SKILL_RECALL_SCOPES.get(skill_name, _DEFAULT_RECALL)
        scope = _filter_scope(scope, status)
        if not scope:
            return ""
        return (
            f"\n\n📚 LOCAL KB AVAILABLE ({status['summary']}). Before web-searching or guessing "
            f"for this skill, RECALL FIRST: report(action='recall', data={{query:'<what you need>', "
            f"scope:'{scope}'}}) — pulls {intent}. Offline + instant; web only on a miss."
        )
    except Exception:
        return ""


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

    # AI red-team always gets the dashboard — auto-start it (idempotent) so the
    # operator has the AI Red Team tab live from the moment the skill is chained,
    # regardless of whether the workflow later calls report(action='dashboard').
    dash_note = _autostart_dashboard() if skill_name == "ai-redteam" else ""

    # Presence-gated recall nudge (plan 5.1e): point the agent at the local KB /
    # engagement docs relevant to THIS skill — empty string when nothing is set up.
    recall_note = _recall_hint(skill_name)

    # Detect post-compaction resume: skill was already in history before this call
    if is_resume:
        recovery_brief = _st._do_recovery()
        msg = (
            f"RESUME DETECTED: '{skill_name}' was already in skill history — "
            f"post-compaction context likely. Full recovery state follows:\n\n{recovery_brief}"
        )
        if satisfied_gates:
            msg += f"\n\n(satisfied gate(s): {', '.join(satisfied_gates)})"
        return msg + setup_note + dash_note + recall_note

    msg = f"Skill '{skill_name}' logged"
    if satisfied_gates:
        msg += f" (satisfied gate(s): {', '.join(satisfied_gates)})"
    return msg + setup_note + dash_note + recall_note


def _autostart_dashboard() -> str:
    """Serve the dashboard (idempotent) and return an operator note with the URL.
    Fire-and-forget: serve() is async and runs as a background task so set_skill
    never blocks. Fail-soft — a serve error never breaks skill selection."""
    try:
        from core import api_server, dashboard_auth
        _t = asyncio.create_task(api_server.serve(7777))
        _st._background_tasks.add(_t)
        _t.add_done_callback(_st._background_tasks.discard)
        tok = ""
        try:
            tok = dashboard_auth.read_token() or ""
        except Exception:
            pass
        url = f"http://127.0.0.1:7777/#k={tok}" if tok else "http://127.0.0.1:7777"
        return (f"\n\n📊 AI Red Team dashboard starting → open {url} and select the "
                f"'AI Red Team' tab (OWASP grid, k/N, garak rates, filter-bypass, calibration). "
                f"It populates as garak / redteam() / coverage run.")
    except Exception:
        return ""


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
