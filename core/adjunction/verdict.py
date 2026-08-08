"""
Adjudication verdict + audit trail
==================================
A finding is "adjudicated" once it carries an `adjudication` audit-trail object —
the marker that the senior-reviewer pass actually examined it. Storing the object
(not merely flipping `status`) makes every severity change, especially a downgrade,
explainable rather than silent.

Audit-trail shape:
  {
    "reproducible":      bool,
    "artifact_id":       "<id of the artifact proving reproduction; required if reproducible=true>",
    "original_severity": "critical|high|medium|low|info",
    "revised_severity":  "critical|high|medium|low|info",
    "rationale":         "<non-empty reviewer reasoning>",
  }

Pure functions — no I/O. These check only the *presence* of artifact_id; the
*disk-existence* check is enforced at the report_tools boundary (mirroring how
coverage validates artifacts), keeping this layer side-effect-free.
"""
from __future__ import annotations

from core.adjunction.rubric import SEVERITIES, chain_terminal_severity, severity_rank


def is_adjudicated(finding: dict) -> bool:
    """True once a finding carries a non-empty adjudication audit trail.

    The rationale is stripped before the emptiness check so a whitespace-only
    string (e.g. "   ") does NOT satisfy the gate — this keeps is_adjudicated
    consistent with coerce_adjudication (which also strips and refuses a hollow
    rationale). Otherwise a blank verdict would slip a finding past
    pending_findings(), and the dashboard "Complete Scan" path would silently
    complete the scan with an un-reviewed finding.

    A verdict claiming ``reproducible: true`` additionally requires a non-empty
    ``artifact_id`` — a self-attested "it reproduces" with no proving artifact
    is not enough to clear the gate (the disk-existence of that artifact is
    enforced earlier, at the report_tools boundary).
    """
    adj = finding.get("adjudication")
    if not isinstance(adj, dict) or not str(adj.get("rationale") or "").strip():
        return False
    if adj.get("reproducible") is True and not str(adj.get("artifact_id") or "").strip():
        return False
    return True


def _norm_sev(value, fallback: str | None = None) -> str | None:
    sev = str(value or "").strip().lower()
    return sev if sev in SEVERITIES else fallback


def coerce_adjudication(raw, finding: dict | None = None) -> dict | None:
    """Normalise a model-supplied adjudication object into the stored shape.

    Tolerant by design — it cleans rather than rejects, so a slightly-off payload
    still produces a usable audit trail (callers should not fail the whole
    update over a malformed sub-object). Returns None only when there is nothing
    usable (no rationale at all), so the caller can decline to store a hollow
    marker that would wrongly satisfy the gate.

    `finding` (optional) supplies the current severity as the default
    original_severity when the model omits it.
    """
    if not isinstance(raw, dict):
        return None

    rationale = str(raw.get("rationale", "")).strip()
    if not rationale:
        # No reasoning → not a real verdict. Refuse so the gate stays closed.
        return None

    current_sev = (finding or {}).get("severity")
    original = _norm_sev(raw.get("original_severity"), _norm_sev(current_sev))
    revised = _norm_sev(raw.get("revised_severity"), original)

    # Terminal-blast-radius rule: if the finding carries a PROVEN escalation
    # chain to a worse terminal (done lead + recorded result), re-rate it at the
    # terminal impact — chains compose, they never average. Only ever raises.
    chain_sev = chain_terminal_severity(finding or {})
    chain_escalated_from = None
    if chain_sev and severity_rank(chain_sev) > severity_rank(revised or "info"):
        chain_escalated_from = revised
        revised = chain_sev

    reproducible = raw.get("reproducible")
    if not isinstance(reproducible, bool):
        # Coerce common truthy/falsey encodings; default True (kept finding).
        reproducible = str(reproducible).strip().lower() not in ("false", "0", "no", "")

    # Carry the reproduction artifact_id through if supplied. Presence +
    # disk-existence of this artifact for a reproducible verdict is enforced at
    # the report_tools boundary (which can emit an actionable REJECTED message);
    # is_adjudicated() is the gate-level backstop. Keeping coerce side-effect-free
    # and refusing only a hollow rationale preserves its single responsibility.
    artifact_id = str(raw.get("artifact_id", "")).strip()

    out: dict = {
        "reproducible": reproducible,
        "rationale": rationale,
    }
    if artifact_id:
        out["artifact_id"] = artifact_id
    if original:
        out["original_severity"] = original
    if revised:
        out["revised_severity"] = revised
    if chain_escalated_from and chain_escalated_from != revised:
        out["chain_escalated_from"] = chain_escalated_from
    return out
