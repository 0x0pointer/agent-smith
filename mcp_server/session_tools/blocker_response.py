"""Blocked-completion response builder + pending-steering surfacing."""
import json

from core import logger as log
from core import session as scan_session

import mcp_server.session_tools as _st


def _pending_steer_block() -> str:
    """Return a formatted block of pending steering directives, or ''.

    session() responses bypass the envelope wrapper, which is where
    steering directives are normally injected. When Smith is stuck in a
    complete()→HIR→resume loop, it never makes an envelope-wrapped tool
    call, so HUMAN_STEER messages from the dashboard pile up in
    steering_queue.json with status='pending' and are never seen.
    This helper surfaces them inline so the blocked path delivers them
    too. mark_injected is called so the envelope's nag mode picks up
    from here on the next non-session tool call.
    """
    try:
        from core.steering import steering_queue
        active = steering_queue.get_active()
        if not active:
            return ""
        # Prioritise HUMAN_STEER messages — those are the human waiting
        # for a reply. Other directives (QA-emitted) come below.
        human = [d for d in active if d.trigger == "HUMAN_STEER"]
        other = [d for d in active if d.trigger != "HUMAN_STEER"]
        lines = []
        for d in human:
            lines.append(f"  ⚠ HUMAN MESSAGE [{d.priority.upper()}]: {d.message}")
            steering_queue.mark_injected(d.id)
        for d in other:
            lines.append(f"  ⚠ STEERING [{d.priority.upper()}]: {d.message}")
            steering_queue.mark_injected(d.id)
        nag = (
            "REPLY TO THE HUMAN NOW so they see your response on the dashboard: "
            "call session(action='qa_reply', options={message: '<your reply>'}). "
            "Without this call your reply never reaches the human."
        ) if human else (
            "Acknowledge with session(action='qa_reply', options={message: '<your reply>'}) "
            "after acting on these directives."
        )
        return "\n\nPENDING DIRECTIVES (act on these BEFORE retrying complete()):\n" + \
               "\n".join(lines) + "\n" + nag
    except Exception:
        # Steering failures must never break tool dispatch.
        return ""


# Priority for surfacing ONE blocker at a time under condensed (small/medium)
# profiles — lower number = fix first. Concrete data prerequisites and required
# verdicts come before the "re-run deeper" iteration brief.
_BLOCKER_PRIORITY = (
    ("QA BLOCKER", 0),
    ("GATE [", 1),
    ("EMPTY COVERAGE MATRIX", 2),
    ("LOW COVERAGE", 2),
    ("INJECTION BREADTH", 3),
    ("INTEGRITY", 3),
    ("ADJUDICATION REQUIRED", 4),
    ("NO POC FILES", 5),
    ("FINDING QUALITY", 5),
    ("PENDING LEADS", 6),
    ("NO SPIDER", 7),
    ("NO DIAGRAM", 8),
    ("ITERATION GATE", 9),
)


def _blocker_priority(b: str) -> int:
    for key, pri in _BLOCKER_PRIORITY:
        if key in b:
            return pri
    return 5


def _build_blocker_response(blockers: list) -> str:
    """Build the blocked-completion response string or HIR JSON."""
    steer_block = _pending_steer_block()
    if _st._complete_attempts >= _st._MAX_COMPLETE_ATTEMPTS:
        attempts = _st._complete_attempts
        log.note(f"HIR triggered after {attempts} blocked complete() attempts. Blockers: {'; '.join(b[:80] for b in blockers)}")
        # Reframed situation text: blockers-first, options-are-for-human.
        # Earlier copy emphasised SKIP_CELLS / ACCEPT_PARTIAL which Smith
        # interpreted as "easy out" options for itself rather than human
        # override switches, leading to the 29-attempt cascade where
        # Smith picked the cheap "retry complete" path instead of doing
        # the actual blocker-fix work.
        scan_session.trigger_intervention(
            code="HIR_FORCE_COMPLETE",
            situation=(
                f"{len(blockers)} real quality-gate blocker(s) require actual work, "
                f"not retries. Smith called complete() {attempts} times instead of "
                "addressing them. The options below are HUMAN OVERRIDES — Smith "
                "should keep doing blocker work (re-test cells, chain required "
                "skills, file missing artifacts) until you tell it otherwise."
            ),
            tried=[f"complete() attempt {i+1}/{attempts}" for i in range(min(attempts, 5))],
            options=[
                "CONTINUE: Give Smith specific instructions to resolve the remaining blockers and it will retry (recommended)",
                "SKIP_CELLS: Tell Smith which specific cells or endpoint types to mark as skipped",
                "REDUCE_SCOPE: Specify which checks to drop (e.g. 'skip all rate_limit cells')",
                "ACCEPT_PARTIAL: Force-complete with current coverage; unresolved items flagged in the report",
            ],
        )
        payload = {
            "status": "HUMAN_INTERVENTION_REQUIRED",
            "code": "HIR_FORCE_COMPLETE",
            "situation": (
                f"complete() BLOCKED by {len(blockers)} real quality gates after "
                f"{attempts} attempts. DO NOT retry — address the blockers first. "
                "If a pending HUMAN MESSAGE is present, REPLY first via qa_reply."
            ),
            "blockers": blockers[:5],
            "options": [
                "CONTINUE — human gives specific blocker-fix instructions (recommended)",
                "SKIP_CELLS — specify cells/endpoint types to skip",
                "REDUCE_SCOPE — drop specific checks",
                "ACCEPT_PARTIAL — force-complete with documented gaps",
            ],
            "how_to_respond": "Use the dashboard 'Send to Smith' panel, or call session(action='resume', options={choice: '...', message: '...'})",
            "scan_paused": True,
        }
        result = json.dumps(payload, indent=2)
        if steer_block:
            result = result + steer_block
        return result
    depth = (scan_session.get() or {}).get("depth", "")
    total = len(blockers)
    if _st._condensed_directives() and total > 1:
        # Serialize: surface only the highest-priority blocker so it fits a small
        # context window. The progress-aware counter in _do_complete refunds the
        # attempt budget as the count drops, so one-per-call fixing won't trip HIR.
        shown = [min(blockers, key=_blocker_priority)]
        header = (
            f"complete BLOCKED — {total} blockers remain; fixing them ONE AT A TIME so each "
            f"fits your context. Fix THIS one, then call session(action='complete') again for "
            f"the next:\n\n"
        )
    elif depth == "thorough" and _st._analysis_passes < _st._min_iterations():
        shown = blockers
        _mi = _st._min_iterations()
        header = (
            f"complete BLOCKED — thorough scan requires {_mi} analysis passes "
            f"(quality-clean passes: {_st._analysis_passes}/{_mi}):\n\n"
        )
    else:
        shown = blockers
        header = f"complete BLOCKED (attempt {_st._complete_attempts}/{_st._MAX_COMPLETE_ATTEMPTS}) — fix the following first:\n\n"
    msg = header + "\n\n".join(f"  [{i+1}] {b}" for i, b in enumerate(shown))
    if steer_block:
        msg = msg + steer_block
    log.note(
        f"complete blocked (attempt {_st._complete_attempts}, analysis_passes={_st._analysis_passes}, "
        f"blockers={total}, shown={len(shown)}): {'; '.join(b[:80] for b in blockers)}"
    )
    return msg
