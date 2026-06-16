"""
Adjudication directive
======================
Assembles the completion-time blocker text that re-prompts the driving model
into the senior-reviewer pass: persona + jobs + output contract + the canonical
rubric + the concrete list of findings still awaiting a verdict.

Returned as a plain string so it rides the existing completion-blocker channel
(mcp_server.session_tools._build_blocker_response) — no envelope, no LLM call,
identical across Claude Code / opencode / Codex.
"""
from __future__ import annotations

from core.adjunction.persona import persona_block
from core.adjunction.rubric import rubric_text, validate_severity_vs_impact

# Cap how many findings we spell out inline to keep the directive bounded; the
# count line still tells the model the true total so nothing is hidden.
_MAX_LISTED = 25


def _finding_line(idx: int, f: dict) -> str:
    sev = str(f.get("severity", "")).lower()
    title = f.get("title", "(untitled)")
    target = f.get("target", "")
    line = f"  [{idx}] id={f.get('id', '?')}  [{sev.upper()}]  {title}"
    if target:
        line += f"  ({target})"
    ok, hint = validate_severity_vs_impact(sev, f.get("description", ""))
    if not ok and hint:
        line += f"\n        ⚠ {hint}"
    return line


def build_adjudication_directive(pending: list[dict]) -> str:
    """Build the senior-reviewer directive for the findings awaiting a verdict."""
    total = len(pending)
    listed = pending[:_MAX_LISTED]
    finding_lines = "\n".join(_finding_line(i + 1, f) for i, f in enumerate(listed))
    more = f"\n  (+{total - _MAX_LISTED} more — review every one)" if total > _MAX_LISTED else ""

    return (
        f"ADJUDICATION REQUIRED — {total} finding(s) need a final senior-review verdict "
        "before this scan can complete.\n\n"
        f"{persona_block()}\n\n"
        f"{rubric_text()}\n\n"
        "FINDINGS AWAITING YOUR VERDICT:\n"
        f"{finding_lines}{more}\n\n"
        "Work through them one by one. Completion stays blocked until every finding "
        "above carries an adjudication verdict."
    )
