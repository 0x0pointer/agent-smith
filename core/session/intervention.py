"""
Human Intervention Required (HIR)
=================================
Pause/resume of a scan pending an operator decision: `trigger_intervention`
transitions to ``intervention_required`` (envelope.py then blocks all
non-session tool calls), `resolve_intervention` records the human's choice and
returns to ``running``, and `get_intervention` is the dedup-safe read used by
every HIR-triggering path.

Reaches the mutable session state in the ``core.session`` package namespace via
``import core.session as _sess`` (``_sess._current`` / ``_sess._flush`` /
``_sess._reconcile_if_external_write``), read at call time so every name stays
patchable and no import cycle forms.
"""
from __future__ import annotations

from datetime import datetime, timezone

import core.session as _sess


def trigger_intervention(
    code: str,
    situation: str,
    tried: list[str],
    options: list[str],
) -> dict:
    """Transition session to intervention_required state.

    Pauses the scan — envelope.py blocks all non-session tool calls while in this state.
    The human responds via the dashboard or session(action='resume').
    """
    _sess._reconcile_if_external_write()
    if not _sess._current:
        return {}
    _sess._current["status"] = "intervention_required"
    _sess._current["intervention"] = {
        "code":         code,
        "situation":    situation,
        "tried":        tried,
        "options":      options,
        "triggered_at": datetime.now(timezone.utc).isoformat(),
        "resolved_at":  None,
        "resolution":   None,
    }
    _sess._flush()
    # Out-of-band notification (Telegram etc.) — optional, fire-and-forget.
    # No-op when nothing is configured in .env. Wrapped so a notifier import
    # error never breaks the HIR fire path itself.
    try:
        from core.notifiers import notify as _notify
        _notify(
            title=code,
            body=situation,
            urgency="high",
            code=code,
            options=options,
        )
    except Exception:
        pass
    return _sess._current


def resolve_intervention(choice: str, message: str = "") -> dict:
    """Human responded — transition back to running and record their decision.

    Idempotent: if there is no active intervention (already resolved), only
    the running-status flip is applied. Previously this path was appending
    a None entry to intervention_history every time it was called twice in
    a row (e.g. operator clicks REAUTH then watchdog also calls us), which
    broke the dashboard renderer that iterated history without null checks.
    """
    _sess._reconcile_if_external_write()
    if not _sess._current:
        return {}
    intervention = _sess._current.get("intervention")
    history = _sess._current.setdefault("intervention_history", [])
    # Sanitize legacy entries: drop any None left from earlier bug.
    if any(h is None for h in history):
        history[:] = [h for h in history if h is not None]
    resolved_code = ""
    if intervention:
        resolved_code = intervention.get("code", "")
        intervention["resolved_at"] = datetime.now(timezone.utc).isoformat()
        intervention["resolution"]  = {"choice": choice, "message": message}
        history.append(intervention)
        _sess._current["intervention"] = None
    # Only return to 'running' if we weren't already in a terminal state.
    # complete / incomplete_with_unresolved_blockers / limit_reached are
    # definitive end-states; resolving a stale intervention should not undo
    # the human's Complete Scan click or a budget/time stop.
    if _sess._current.get("status") not in (
        "complete", "incomplete_with_unresolved_blockers", "limit_reached",
    ):
        _sess._current["status"] = "running"
    _sess._flush()
    # Reset Smith's complete()-attempts counter when an HIR_FORCE_COMPLETE
    # was just resolved. The counter lives in mcp_server.session_tools as a
    # module global; it only zeroed on session.start or a no-blocker
    # success, which meant once it crossed _MAX_COMPLETE_ATTEMPTS (8) the
    # very next complete() call would re-fire the HIR — turning a single
    # blocked scan into the 11→15→17→19→21→24→29 cascade the user saw.
    # Each human resolution should grant Smith a fresh 8-attempt budget to
    # try again with the new instructions. Imported lazily to avoid an
    # import cycle (mcp_server imports core.session).
    if resolved_code == "HIR_FORCE_COMPLETE":
        try:
            from mcp_server import session_tools as _st
            _st._complete_attempts = 0
        except Exception:
            # Test contexts may not have mcp_server importable; resetting
            # is a quality-of-life win, not a correctness invariant.
            pass
    return _sess._current


def get_intervention() -> dict | None:
    """Return current intervention dict if scan is paused, else None.

    Reconciles against disk first because this is the dedup-check used by
    every HIR-triggering path. If a previous HIR fired and flushed to disk
    but our cached _current hasn't observed that flush yet (the dashboard
    process and MCP server keep separate _current caches; same family of
    cross-process desync we fixed for Clear All in PR #111), the dedup
    check returns None and a duplicate HIR fires. _reconcile_if_external_write
    only pays for a disk read when session.json's mtime is newer than our
    last local write, so the steady-state cost is near zero.
    """
    _sess._reconcile_if_external_write()
    if not _sess._current or _sess._current.get("status") != "intervention_required":
        return None
    return _sess._current.get("intervention")
