"""
Scan gate — short-circuit tool calls when the scan is paused (HIR) or terminal.
"""
from __future__ import annotations

import json

from mcp_server.scan_engine.envelope._common import _log


def _check_scan_gate(tool: str) -> str | None:
    """Return a blocking JSON string if this tool call should be short-circuited, else None.

    Checks (in order):
    1. Scan is paused for human intervention — all tools except session() blocked.
    2. Scan reached a terminal state — all tools except session() blocked.
    """
    if tool == "session":
        return None
    try:
        from core import session as _sess
        iv = _sess.get_intervention()
        if iv:
            return json.dumps({
                "status": "HUMAN_INTERVENTION_REQUIRED",
                "code":   iv.get("code", "HIR_UNKNOWN"),
                "situation": iv.get("situation", ""),
                "options":   iv.get("options", []),
                "scan_paused": True,
                "how_to_respond": (
                    "The scan is paused. Respond via the dashboard 'Send to Smith' panel, "
                    "or call: session(action='resume', options={choice: '...', message: '...'})"
                ),
            }, indent=2)
    except (ImportError, AttributeError, OSError) as e:
        _log.warning("intervention check failed: %s", e)
    try:
        from core import session as _sess
        current = _sess.get() or {}
        scan_status = current.get("status", "")
        if scan_status in (
            "complete", "incomplete_with_unresolved_blockers", "limit_reached",
        ) and not current.get("triage_requested"):
            # A terminal scan normally blocks every tool but session(). The one
            # exception is an operator-triggered TRIAGE pass on a stopped scan:
            # while triage_requested is set, Smith must be able to call report()
            # (to record verdicts) and re-verify findings (http/kali) before the
            # gate slams shut again. The injected steering directive keeps the
            # pass scoped to adjudication; once every finding has a verdict the
            # flag clears (see /api/session self-heal) and this gate resumes
            # blocking all tools.
            return json.dumps({
                "status": "SCAN_COMPLETED",
                "scan_status": scan_status,
                "message": (
                    f"This scan has been marked '{scan_status}' by the human operator "
                    "via the dashboard (or a budget/time limit was reached). Stop "
                    "calling tools. Write one final brief summary message — "
                    "do NOT make any further tool calls — and end your turn."
                ),
                "how_to_resume": (
                    "If the human wants more testing they will start a fresh scan via "
                    "session(action='start') — do not call that yourself."
                ),
            }, indent=2)
    except (ImportError, AttributeError, OSError) as e:
        _log.warning("terminal-status check failed: %s", e)
    return None
