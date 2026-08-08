"""
P5.6 steering directives, P5.7 duplicate-call warning, and P5 QA-alert injection.
"""
from __future__ import annotations

import json

from mcp_server.scan_engine.envelope._common import Envelope, _qa_alert_last_shown, _QA_ALERT_DEDUP_SECONDS


# ---------------------------------------------------------------------------
# P5.6 — Steering directive injection
# ---------------------------------------------------------------------------

def _inject_steering_directives(env: Envelope) -> bool:
    """Inject pending QA steering directives into the envelope.

    High-priority directives are prepended to the summary so the model sees them
    immediately. All directives appear in warnings for the audit trail.
    Each directive is marked injected after surfacing.

    Returns True if any directive was injected (used to suppress QA alert prepend).
    """
    try:
        from core.steering import steering_queue
        pending = steering_queue.get_pending()
        injected = False
        for directive in pending:
            env.warnings.append(f"[QA STEER {directive.priority.upper()}] {directive.message}")
            if directive.priority == "high":
                is_human = directive.trigger == "HUMAN_STEER"
                ack_reminder = (
                    "REPLY TO THE HUMAN NOW so they see your response on the dashboard: "
                    "call session(action='qa_reply', options={message: '<your reply>'}). "
                    "Without this call your terminal output never reaches the human."
                ) if is_human else (
                    "Acknowledge with session(action='qa_reply', options={message: '<your reply>'}) "
                    "after acting on this directive."
                )
                env.summary = (
                    f"⚠ QA STEERING: {directive.message}\n"
                    f"(Act on this before continuing. {ack_reminder})\n\n"
                    + env.summary
                )
            steering_queue.mark_injected(directive.id)
            injected = True

        # Nag mode: even after a directive is "injected", keep reminding Smith
        # about unacknowledged HUMAN_STEER messages on every tool call until
        # it actually calls qa_reply. Otherwise Smith reads the reminder once,
        # acts on the substance, and the human never sees a reply.
        active = steering_queue.get_active()  # pending + injected
        unanswered_human = [
            d for d in active
            if d.trigger == "HUMAN_STEER" and d.status == "injected"
        ]
        if unanswered_human and not injected:
            messages = "; ".join(f'"{d.message[:120]}"' for d in unanswered_human)
            env.warnings.append(
                f"UNANSWERED HUMAN STEER ({len(unanswered_human)}): {messages}"
            )
            env.summary = (
                f"⚠ UNANSWERED HUMAN STEER ({len(unanswered_human)}): "
                f"the human is waiting for a reply. "
                f"CALL NOW: session(action='qa_reply', options={{message: '<your reply>'}}). "
                f"Pending: {messages}\n\n"
                + env.summary
            )
            injected = True

        return injected
    except Exception:
        return False  # steering failures must never break tool dispatch


def _inject_duplicate_warning(env: Envelope, tool: str) -> None:
    """Inject a recovery reminder when the same tool+params were already run."""
    from core import session as scan_session
    try:
        invocations = (scan_session.get() or {}).get("tool_invocations", [])
        seq = next(
            (i.get("seq") for i in reversed(invocations) if i.get("tool") == tool),
            "?",
        )
        env.warnings.append(
            f"DUPLICATE_TOOL_CALL: {tool} was already run with these exact parameters "
            f"(invocation #{seq}). You may be post-compaction. "
            "Call session(action='recovery') to verify where you left off."
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# P5 — QA alert injection
# ---------------------------------------------------------------------------

def _inject_qa_alerts_into_envelope(env: Envelope, suppress_summary_prepend: bool = False) -> None:
    """Read qa_state.json and inject high-urgency alerts into the envelope.

    High urgency  → appended to env.warnings AND (unless suppressed) prepended to
                    env.summary. Summary prepend is suppressed when a steering directive
                    already owns that slot — one ⚠ header at a time.
    Medium urgency → skipped (dashboard-only; not model-facing).
    Low urgency   → skipped (dashboard-only; not model-facing).

    Dedup strategy:
      1. Timestamp gate: skip the whole qa_state.json tick if its `ts` hasn't moved.
      2. Per-alert content dedup: even within a fresh tick, suppress any alert
         whose (code, message) was already shown within _QA_ALERT_DEDUP_SECONDS.
         This stops Smith answering the same "X cells lack tested_by" message
         every 120s. Cooldown resets when the message content changes.
    """
    import mcp_server.scan_engine.envelope as _env
    try:
        if not _env._QA_STATE_FILE.is_file():
            return
        state = json.loads(_env._QA_STATE_FILE.read_text(encoding="utf-8"))
        ts = state.get("ts", "")
        if not ts or ts <= _env._last_qa_shown_ts:
            return
        high = [a for a in state.get("alerts", []) if a.get("urgency") == "high"]
        if not high:
            _env._last_qa_shown_ts = ts
            return
        _env._last_qa_shown_ts = ts

        # Per-alert content dedup
        fresh = _filter_qa_alerts_by_dedup(high, ts)
        if not fresh:
            return  # everything is stale-dup; no point injecting

        for a in fresh:
            env.warnings.append(f"[QA HIGH] {a['message']}")

        if not suppress_summary_prepend:
            alert_text = " | ".join(a["message"] for a in fresh)
            env.summary = (
                f"⚠ QA ALERT: {alert_text}\n"
                f"(Address before continuing or call session(action='status') to review.)\n\n"
                + env.summary
            )
    except Exception:
        pass  # never break tool dispatch


def _filter_qa_alerts_by_dedup(alerts: list[dict], current_ts: str) -> list[dict]:
    """Return only alerts not shown within the cooldown window.

    Fingerprint = (code, message). When the message text changes (e.g. count
    grew from 553 to 612 cells), the fingerprint changes too and the alert
    re-fires. Identical repeats are suppressed for _QA_ALERT_DEDUP_SECONDS.
    """
    from datetime import datetime, timezone
    try:
        now_dt = datetime.fromisoformat(current_ts.replace("Z", "+00:00"))
    except Exception:
        # Falls back to no dedup if we can't parse the timestamp.
        return alerts

    fresh: list[dict] = []
    for a in alerts:
        fp = (a.get("code", ""), a.get("message", ""))
        last = _qa_alert_last_shown.get(fp)
        if last:
            try:
                last_dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
                if (now_dt - last_dt).total_seconds() < _QA_ALERT_DEDUP_SECONDS:
                    continue  # dedup
            except Exception:
                pass
        fresh.append(a)
        _qa_alert_last_shown[fp] = current_ts
    return fresh
