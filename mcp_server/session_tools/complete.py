"""session(action='complete') — completion counters, thorough-depth gate, dispatch."""
import json

from core import cost as cost_tracker
from core import findings as findings_store
from core import logger as log
from core import session as scan_session

import mcp_server.session_tools as _st
from .blocker_response import _build_blocker_response


def _persist_completion_counters() -> dict:
    """Flush attempt/pass counters to session.json and return current session."""
    current = scan_session.get() or {}
    if current:
        current["complete_attempts"] = _st._complete_attempts
        current["analysis_passes"] = _st._analysis_passes
        scan_session._flush()
    return current


async def _autoclose_crosscutting_best_effort() -> None:
    """Propagate app-wide cross-cutting verdicts to their cells before completion.

    The matrix fans cors/csrf/security_headers across every endpoint, but their
    verdict is app-wide — the model files the finding ("Wildcard CORS on all
    endpoints") yet rarely marks the 50+ per-endpoint cells, so the coverage gate
    sees an empty matrix and the scan wedges (the overnight no-progress loop).
    Running the honest propagator here (links the finding, cites a real response,
    marks GET-endpoint CSRF N/A) means a completion attempt automatically reflects
    the work already done. Best-effort + idempotent — only touches pending
    cross-cutting cells and never blocks completion.
    """
    try:
        from core import coverage as _cov
        from mcp_server.report_tools import _do_coverage_auto_crosscutting
        res = await _do_coverage_auto_crosscutting({"type": "auto_crosscutting"}, _cov)
        log.note(f"auto_crosscutting (pre-complete): {str(res)[:200]}")
    except Exception:
        log.note("auto_crosscutting (pre-complete) failed — non-fatal")


def _thorough_keep_working_response(current: dict) -> str:
    """Directive returned to the AGENT when it calls complete() in thorough mode —
    thorough is OPERATOR-TERMINATED, so the agent never ends the scan; it keeps
    working until the operator clicks Complete Scan. PHASE-AWARE: in Phase A it hands back the
    deep hunt (not 'burn cells'), Phase B drains the matrix, Phase C composes — thorough is the
    default depth, so the three-phase ordering must apply here too."""
    from core import session as _sess
    from core.session import phases as _phases
    _sess.maybe_advance_phase()   # thorough progresses through the phases on each complete() call
    phase = _phases.current_phase(_sess.get() or current)
    header = (
        "THOROUGH MODE — the scan does NOT auto-complete; only the OPERATOR ends it (the "
        "dashboard 'Complete Scan' button). Do NOT call session(action='complete') again — no "
        f"cost/time/call limits; keep working. Current phase: {_phases.phase_label(phase)}."
    )
    from .recovery_build import _exploit_hunt_call, _synthesis_call
    if phase == _phases.EXPLOIT:
        return header + "\n\n" + _exploit_hunt_call()
    if phase == _phases.SYNTHESIS:
        return header + "\n\n" + _synthesis_call()
    # COVERAGE (Phase B) — drain the matrix.
    lines = [header]
    try:
        from core.coverage import get_matrix
        pending = sum(1 for c in get_matrix().get("matrix", []) if c.get("status") == "pending")
        if pending:
            lines.append(
                f"  • {pending} coverage cells still pending — burn them down: "
                "report(action='coverage', data={type:'sweep', max_cells:60}) repeatedly, then "
                "report(action='coverage', data={type:'auto_crosscutting'}), then next_batch/bulk_tested.")
    except Exception:
        pass
    gates = [g for g in (current.get("gates") or []) if g.get("status") == "pending"]
    missing = sorted({s for g in gates
                      for s in (set(g.get("required_skills", [])) - set(g.get("satisfied_skills", [])))})
    if missing:
        lines.append(f"  • Skills not yet run: {', '.join(missing)} — chain each applicable one.")
    lines.append("  • Adjudicate each high/critical finding, then go DEEPER — chain confirmed findings "
                 "to maximum impact and re-test at escalating aggression.")
    lines.append("Keep going. The operator will complete the scan when satisfied.")
    return "\n".join(lines)


def _thorough_gate(current: dict) -> str:
    """Thorough completion = 3 enforced re-run passes, THEN unlimited/operator-terminated.

    Each complete() call in thorough mode advances ONE analysis pass. While fewer
    than _min_iterations() passes are done (full=3), it hands back THAT pass's
    escalating deepen brief and requires another complete() after the re-run work —
    so the 3 phases are actually driven, not skipped. Only once the 3-pass floor is
    met does thorough become purely operator-terminated: no auto-complete, no
    cost/time/call caps — the operator ends it via the dashboard.

    Root cause this fixes: _do_complete() used to short-circuit thorough BEFORE
    _apply_thorough_depth_gate, making _THOROUGH_MIN_ITERATIONS dead code — thorough
    enforced neither the 3 passes nor a coverage floor, and even told the agent not
    to call complete() again, so a single call (or none) let the scan be treated as
    finished. This restores the '3 phases + unlimited' contract."""
    _st._analysis_passes += 1
    current["analysis_passes"] = _st._analysis_passes
    _st.scan_session._flush()
    _st.scan_session.maybe_advance_phase()   # thorough progresses through the phases too
    # Evaluate skill-chain gates honestly so unrun mandatory skills surface in the brief.
    _st.scan_session.restore_gates()
    _st.scan_session.reconcile_worked_gates()
    min_passes = _st._min_iterations()
    if _st._analysis_passes < min_passes:
        brief = (
            _st._deepen_brief_whitebox(_st._analysis_passes)
            if _st._is_whitebox_scan()
            else _st._deepen_brief(_st._analysis_passes)
        )
        return (
            f"THOROUGH PASS {_st._analysis_passes}/{min_passes} — the scan is NOT done "
            f"({min_passes - _st._analysis_passes} more mandatory pass(es) after this). "
            "Execute EVERY step below (re-run tools + skills at escalating aggression, "
            "burn down pending coverage, chain confirmed findings), THEN call "
            "session(action='complete') again to advance to the next pass:\n\n" + brief
        )
    # 3-pass floor met — thorough is now unlimited + operator-terminated.
    return _thorough_keep_working_response(current)


def _do_complete():
    current0 = _st.scan_session.get() or {}
    # THOROUGH = 3 mandatory re-run passes, THEN unlimited/operator-terminated. The
    # AGENT can never end a thorough scan (only the operator's dashboard Complete Scan
    # → scan_session.complete() does), but it MUST be driven through the 3 escalating
    # passes first (_thorough_gate). We handle thorough separately and do NOT touch
    # _complete_attempts, so this never trips HIR_FORCE_COMPLETE.
    if str(current0.get("depth", "")).lower() == "thorough":
        return _thorough_gate(current0)
    _st._complete_attempts += 1

    data = findings_store._load()
    current = _persist_completion_counters()

    # Skill-chain gates must be EVALUATED honestly at completion:
    #  - restore_gates() un-defers gates the per-response throttle parked, so a
    #    deferred gate can no longer leak past the terminal check (they were both
    #    non-blocking AND invisible to recovery).
    #  - reconcile_worked_gates() satisfies each gate whose required skills actually
    #    DID work — a merely-declared skill (set_skill without running the workflow)
    #    does not clear its gate. Together: thorough mode genuinely requires the
    #    applicable skills to run before it can complete.
    _st.scan_session.restore_gates()
    _st.scan_session.reconcile_worked_gates()

    effective = _st._effective_tools()
    blockers = _st._collect_completion_blockers(data, effective)

    # Progress-aware HIR (condensed profiles): blockers are surfaced one at a
    # time, so a model clearing them across several complete() calls is making
    # progress, not stalling. When the count DROPS, refund the attempt budget so
    # serialized fixing doesn't trip the 8-attempt HIR; HIR still fires when the
    # count is stuck (genuine inability to progress).
    if _st._condensed_directives() and blockers:
        n = len(blockers)
        if _st._last_blocker_count is not None and n < _st._last_blocker_count:
            _st._complete_attempts = 1
        _st._last_blocker_count = n
    elif not blockers:
        _st._last_blocker_count = None

    if blockers:
        # Log the adjudication directive whenever the gate fires so the Activity
        # tab reflects that a review pass is owed.
        try:
            from core.adjunction import pending_findings
            from core.adjunction.log import log_directive
            pending = pending_findings(data)
            if pending:
                log_directive(pending)
        except Exception:
            pass
        return _build_blocker_response(blockers)

    _st._complete_attempts = 0
    _st._analysis_passes = 0

    # Only the human operator can mark a scan complete.
    # Smith passes all quality gates here — the scan is ready — but completion
    # is deliberately reserved for the human via the dashboard "Complete Scan"
    # button or the Instruct Smith panel.
    log.note(
        f"complete() called by Smith (attempt {_st._complete_attempts}) — "
        "all quality gates passed; awaiting human completion via dashboard."
    )

    # Inject any active steering directives directly into this response so
    # Smith sees them immediately without needing another tool call.
    # (session() bypasses the envelope pipeline, so directives won't reach
    # Smith otherwise if it stops making scan tool calls here.)
    try:
        from core.steering import steering_queue
        active = steering_queue.get_active()
        if active:
            directive_lines = "\n".join(
                f"  ⚠ STEERING [{d.priority.upper()}]: {d.message}" for d in active
            )
            steering_queue.mark_injected(active[0].id)
            return (
                "COMPLETION HELD — human sign-off required via dashboard.\n"
                "Do NOT summarise findings. Do NOT explain the situation to the user.\n"
                "EXECUTE NOW: act on the pending human instructions below, then call "
                "session(action='status') to check for more directives.\n\n"
                f"{directive_lines}"
            )
    except Exception:
        pass

    return (
        "COMPLETION HELD — human sign-off required via dashboard.\n"
        "Do NOT summarise findings. Do NOT explain the situation to the user. "
        "Do NOT call session(action='complete') again.\n"
        "EXECUTE NOW: call session(action='status') to check for pending QA alerts "
        "and steering directives, then act on them. Keep making tool calls."
    )


def _record_metrics(findings_data: dict, completion_blockers: list[str], force_completed: bool) -> None:
    try:
        import core.metrics as metrics_mod
        from core.quick_log import quick_log
        from core.steering import steering_queue
        from core.coverage import get_matrix
        metrics_mod.record(
            session=scan_session.get() or {},
            cost_summary=cost_tracker.get_summary(),
            findings_data=findings_data,
            coverage=get_matrix(),
            force_completed=force_completed,
            completion_blockers=completion_blockers,
            quick_log_entries=quick_log.read_all(),
            steering_history=steering_queue.get_history(),
        )
    except Exception:
        pass
