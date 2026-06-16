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
    "original_severity": "critical|high|medium|low|info",
    "revised_severity":  "critical|high|medium|low|info",
    "rationale":         "<non-empty reviewer reasoning>",
  }

Pure functions — no I/O.
"""
from __future__ import annotations

from core.adjunction.rubric import SEVERITIES


def is_adjudicated(finding: dict) -> bool:
    """True once a finding carries a non-empty adjudication audit trail.

    The rationale is stripped before the emptiness check so a whitespace-only
    string (e.g. "   ") does NOT satisfy the gate — this keeps is_adjudicated
    consistent with coerce_adjudication (which also strips and refuses a hollow
    rationale). Otherwise a blank verdict would slip a finding past
    pending_findings(), and the dashboard "Complete Scan" path would silently
    complete the scan with an un-reviewed finding.
    """
    adj = finding.get("adjudication")
    return isinstance(adj, dict) and bool(str(adj.get("rationale") or "").strip())


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

    reproducible = raw.get("reproducible")
    if not isinstance(reproducible, bool):
        # Coerce common truthy/falsey encodings; default True (kept finding).
        reproducible = str(reproducible).strip().lower() not in ("false", "0", "no", "")

    out: dict = {
        "reproducible": reproducible,
        "rationale": rationale,
    }
    if original:
        out["original_severity"] = original
    if revised:
        out["revised_severity"] = revised
    return out
