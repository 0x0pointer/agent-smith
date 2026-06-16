"""
Adjudication completion gate
============================
Selects the findings that must carry a senior-review verdict before a scan may
complete, and emits the adjudication directive as a completion blocker.

Scope defaults to high/critical (matches mcp_server.session_tools
._finding_quality_blockers) — that's where over-estimation and false positives
hurt most. Widen via ADJUDICATION_SEVERITIES if ever needed; no config flag,
adjudication is always on.

Force-complete / limit-hit terminations are handled by NOT mutating findings
here: an un-reviewed finding simply never gains an `adjudication` object, so it
stays explicitly un-adjudicated rather than being silently confirmed.

Pure functions — no I/O.
"""
from __future__ import annotations

from core.adjunction.directive import build_adjudication_directive
from core.adjunction.verdict import is_adjudicated

# Severities subject to the gate. Tuple, so it's trivially widened later.
ADJUDICATION_SEVERITIES: tuple[str, ...] = ("critical", "high")


def _in_scope(finding: dict) -> bool:
    return str(finding.get("severity", "")).strip().lower() in ADJUDICATION_SEVERITIES


def pending_findings(data: dict) -> list[dict]:
    """In-scope findings that have not yet been adjudicated."""
    findings = data.get("findings", []) if isinstance(data, dict) else []
    return [f for f in findings if _in_scope(f) and not is_adjudicated(f)]


def adjudication_blockers(data: dict) -> list[str]:
    """Return [directive] if any in-scope finding still needs a verdict, else []."""
    pending = pending_findings(data)
    if not pending:
        return []
    return [build_adjudication_directive(pending)]
