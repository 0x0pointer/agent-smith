"""qa_reply acknowledgment + HIR resume / manual-intervene actions."""
import json

from core import logger as log
from core import session as scan_session


async def _do_qa_reply(opts):
    """Log Smith's response to a QA steering directive and acknowledge it.

    Optionally references a specific directive_id to acknowledge. If omitted,
    the most recently injected directive is acknowledged automatically.
    """
    from core.quick_log import quick_log
    from core.steering import steering_queue
    message = str(opts.get("message", "")).strip()
    directive_id = str(opts.get("directive_id", "")).strip()
    if not message:
        return "qa_reply requires a non-empty message= option."

    ack_id: str | None = None
    if directive_id:
        if steering_queue.acknowledge(directive_id, message):
            ack_id = directive_id
    else:
        ack_id = steering_queue.acknowledge_latest_injected(message)

    await quick_log.append({
        "type":         "QA_REPLY",
        "message":      message,
        "directive_id": ack_id,
    })

    if ack_id:
        return f"QA reply logged. Directive {ack_id} acknowledged."
    return "QA reply logged. (No active directive to acknowledge — reply recorded for audit trail.)"

def _do_resume(opts: dict) -> str:
    """Human responded to a HUMAN_INTERVENTION_REQUIRED event.

    Transitions the scan back to 'running', records the human's choice,
    and injects a steering directive so Smith immediately knows what to do.
    """
    from core.steering import steering_queue, RESUME_REQUIRED
    choice  = str(opts.get("choice", "")).strip()
    message = str(opts.get("message", "")).strip()
    if not choice and not message:
        return (
            "resume requires choice= and/or message=. "
            "Example: session(action='resume', options={choice: 'ACCEPT_PARTIAL', message: 'Complete with documented gaps'})"
        )
    current = scan_session.get() or {}
    if current.get("status") not in ("intervention_required", "running"):
        return f"No active intervention to resolve. Current status: {current.get('status', 'none')}"

    scan_session.resolve_intervention(choice, message)
    human_instruction = f"Human resolved HIR with choice='{choice}'" + (f": {message}" if message else "")
    log.note(f"HIR resolved by human: {human_instruction}")
    steering_queue.add_directive(
        code=RESUME_REQUIRED,
        message=(
            f"HUMAN RESPONSE: {human_instruction}. "
            "Act on this instruction now, then call session(action='complete') when ready."
        ),
        priority="high",
        skill=None,
        trigger="HIR_RESOLVED",
    )
    return json.dumps({
        "status": "resumed",
        "message": "Scan resumed. Human instruction injected as steering directive.",
        "choice": choice,
        "instruction": message,
        "next": "Call session(action='recovery') to get your current position, then follow the steering directive.",
    }, indent=2)


def _do_intervene(opts: dict) -> str:
    """Manually trigger a HUMAN_INTERVENTION_REQUIRED event.

    Useful for QA checks that detect conditions warranting human review
    (repeated tool failure, auth expiry, etc.).
    """
    code      = str(opts.get("code", "HIR_MANUAL")).strip()
    situation = str(opts.get("situation", "Manual intervention requested.")).strip()
    tried     = opts.get("tried", [])
    options   = opts.get("options", [
        "CONTINUE — provide instructions to proceed",
        "ABORT — stop the scan",
    ])
    current = scan_session.get() or {}
    if not current or current.get("status") != "running":
        return f"No running scan to pause. Status: {current.get('status', 'none')}"
    scan_session.trigger_intervention(code, situation, tried, options)
    log.note(f"HIR manually triggered: {code} — {situation}")
    return json.dumps({
        "status": "HUMAN_INTERVENTION_REQUIRED",
        "code":      code,
        "situation": situation,
        "options":   options,
        "scan_paused": True,
        "how_to_respond": "session(action='resume', options={choice: '...', message: '...'})",
    }, indent=2)
