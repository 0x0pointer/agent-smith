"""
Finding actions: create / update / delete, plus finding hygiene
(trace validation, cross-run dedup, coverage auto-linking, adjudication).
"""
import asyncio

from ._common import (
    findings_store,
    log,
    scan_session,
    _background_tasks,
    _norm_text,
    _norm_target,
)
from .gates import _auto_trigger_finding_gates
from .adjudication import _coerce_finding_adjudication, _log_adjudication_verdict


def _validate_trace_field(data: dict) -> str | None:
    """REJECTED message if data carries an invalid/unresolved trace[], else None.

    Fires only when a trace is present — black-box findings (no source) are
    untouched. When a codebase is pinned, this resolves each cited file:line
    against disk, so a hallucinated source location is rejected at the boundary.
    """
    trace = data.get("trace")
    if trace is None:
        return None
    from core.findings_validate import validate_finding_trace
    ok, errors = validate_finding_trace(trace)
    if ok:
        return None
    return (
        "REJECTED: finding 'trace' has invalid or unresolved source citations — fix these "
        "before filing (omit 'trace' for black-box findings that have no source location):\n  - "
        + "\n  - ".join(errors)
    )


def _find_duplicate(title: str, target: str, severity: str) -> dict | None:
    """Return an existing finding with the same target+title+severity, if any.

    The cross-run/within-run dedup key. Gated on status (NEVER a bare title
    match): a finding previously adjudicated ``false_positive`` does NOT
    suppress a fresh one — re-discovering a was-FP-now-real issue must be
    allowed. Severity is part of the key so a later, higher-severity re-rating
    of the same issue is treated as an escalation (allowed), not a duplicate.
    """
    nt, ntg, nsev = _norm_text(title), _norm_target(target), _norm_text(severity)
    if not nt:
        return None
    for f in findings_store._load().get("findings", []):
        if (
            _norm_text(f.get("title")) == nt
            and _norm_target(f.get("target")) == ntg
            and _norm_text(f.get("severity")) == nsev
            and _norm_text(f.get("status")) != "false_positive"
        ):
            return f
    return None


def _dedup_message(existing: dict) -> str:
    eid = existing.get("id", "?")
    return (
        f"DUPLICATE — a finding with the same target + title + severity is already on record "
        f"(id={eid}). Not filed again, to keep findings.json and the adjudication gate clean "
        "across runs. If this is a GENUINELY DISTINCT issue (different endpoint/parameter/"
        "component), re-file with a more specific title. To revise the existing finding, use "
        f"report(action='update_finding', data={{'id': '{eid}', ...}})."
    )


# Map a finding's title/description to the coverage injection_type it evidences.
# Ordered specific-first so e.g. "SSTI" wins over a stray "script" match.
_FINDING_INJECTION_PATTERNS = (
    ("sqli", ("sql inject", "sqli", "union select", "union-based", "boolean-based", "error-based sql")),
    ("ssti", ("template inject", "ssti", "{{7*7}}")),
    ("cmdi", ("command inject", "os command", "shell inject")),
    ("ssrf", ("ssrf", "server-side request forg")),
    ("traversal", ("path travers", "directory travers", "local file inclusion", "lfi")),
    ("xxe", ("xxe", "xml external entit")),
    ("nosqli", ("nosql inject", "nosqli")),
    ("mass_assignment", ("mass assign",)),
    ("prototype", ("prototype pollut",)),
    ("idor", ("idor", "insecure direct object", "broken object level", "bola")),
    ("redirect", ("open redirect",)),
    ("crlf", ("crlf inject", "http response splitt")),
    ("xss", ("cross-site script", "xss")),
)


def _infer_injection_type(title: str, description: str) -> str | None:
    text = f"{title} {description}".lower()
    for inj, pats in _FINDING_INJECTION_PATTERNS:
        if any(p in text for p in pats):
            return inj
    return None


async def _autolink_finding_to_cell(finding_id: str, title: str, description: str,
                                    target: str, artifact_id: str) -> str | None:
    """Reflect a freshly-filed finding in the coverage matrix immediately.

    Filing a finding and marking its cell were two decoupled calls — the model
    reliably did the first and skipped the second, so the matrix never reflected
    what was exploited. This closes that gap structurally: when a finding is filed
    we mark its matching cell vulnerable. Conservative + honest — needs the
    finding's real proof artifact, a clear injection type, and an endpoint match;
    marks exactly ONE best-match cell (preferring the param named in the finding).
    Best-effort: never raises, never blocks the finding.
    """
    if not artifact_id:
        return None
    inj = _infer_injection_type(title, description)
    if not inj:
        return None
    try:
        from urllib.parse import urlparse

        from core import coverage as cov
        matrix = cov.get_matrix()
        norm = cov._normalize_path(urlparse(target).path or "/")
        ep_ids = {e["id"] for e in matrix.get("endpoints", []) if e.get("_normalized") == norm}
        if not ep_ids:
            return None
        cells = [c for c in matrix.get("matrix", [])
                 if c.get("endpoint_id") in ep_ids
                 and c.get("injection_type") == inj
                 and c.get("status") == "pending"]
        if not cells:
            return None
        ftext = f"{title} {description}".lower()
        cell = next((c for c in cells
                     if c.get("param") and c.get("param") != "_endpoint"
                     and c["param"].lower() in ftext), cells[0])
        res = await cov.update_cell(
            cell["id"], "vulnerable",
            notes=f"Auto-linked from finding: {title[:80]}",
            finding_id=finding_id, artifact_id=artifact_id,
        )
        updated = res is True or (isinstance(res, str) and not res.startswith("REJECTED"))
        return cell["id"] if updated else None
    except Exception:
        return None


async def _do_finding(data):
    severity = data.get("severity", "").lower()
    if severity not in ("critical", "high", "medium", "low", "info"):
        return f"Invalid severity '{severity}'. Use: critical, high, medium, low, info"
    title = data.get("title", "")
    target = data.get("target", "")

    # Reject hallucinated/invalid source citations before anything is stored.
    trace_reject = _validate_trace_field(data)
    if trace_reject:
        return trace_reject

    # Cross-run dedup: don't re-file an issue already on record (the app-wide
    # misconfig that used to re-appear every run and re-block the gate).
    dup = _find_duplicate(title, target, severity)
    if dup:
        log.note(f"finding deduplicated against {dup.get('id')} — {title}")
        return _dedup_message(dup)

    # Link the proof artifact: explicit artifact_id if the model passed one,
    # else the session's most-recent tool artifact (the call that produced this
    # finding). Adjudication reuses it so the attack never has to be re-run.
    evidence_artifact_id = (data.get("artifact_id") or "").strip()
    if not evidence_artifact_id:
        evidence_artifact_id = (scan_session.get() or {}).get("last_artifact_id", "") or ""

    entry = await findings_store.add_finding(
        title=title, severity=severity, target=target,
        description=data.get("description", ""),
        evidence=data.get("evidence", ""),
        tool_used=data.get("tool_used", ""),
        cve=data.get("cve", ""),
        business_impact=data.get("business_impact", ""),
        reproduction=data.get("reproduction"),
        escalation_leads=data.get("escalation_leads"),
        trace=data.get("trace"),
        evidence_artifact_id=evidence_artifact_id,
    )
    log.finding(severity, title, target)

    # Structural: reflect the exploit in the coverage matrix NOW — mark the
    # finding's matching cell vulnerable instead of relying on the model to
    # remember a separate report(action='coverage') call (which it skips).
    linked_cell = None
    if severity in ("critical", "high", "medium", "low"):
        linked_cell = await _autolink_finding_to_cell(
            entry.get("id", ""), title, data.get("description", ""), target, evidence_artifact_id,
        )

    # Append FINDING entry to quick_log
    try:
        from core.quick_log import quick_log as _qlog
        _t = asyncio.create_task(_qlog.append({
            "type":     "FINDING",
            "severity": severity,
            "title":    title,
            "target":   target,
        }))
        _background_tasks.add(_t)
        _t.add_done_callback(_background_tasks.discard)
    except Exception:
        pass

    # ── Auto-trigger gates based on finding content ──────────────────────────
    gates_triggered = _auto_trigger_finding_gates(title, severity, data.get("description", ""), data.get("cve", ""))
    msg = f"Finding logged: [{severity.upper()}] {title}"
    if linked_cell:
        msg += f"\n\nMATRIX UPDATED: cell {linked_cell} auto-marked vulnerable (linked to this finding)."
    if gates_triggered:
        msg += f"\n\nGATE(S) TRIGGERED: {', '.join(gates_triggered)}. These skills are now mandatory before completion."
    return msg


async def _do_update_finding(data):
    finding_id = data.get("id", "")
    if not finding_id:
        return "Missing required field: id"
    fields = {k: v for k, v in data.items() if k != "id"}
    if not fields:
        return "No fields to update. Provide severity, title, description, evidence, status, etc."

    # Validate an updated trace[] the same way as on create — a corrected trace
    # must still resolve against the codebase.
    if "trace" in fields:
        trace_reject = _validate_trace_field(fields)
        if trace_reject:
            return trace_reject

    adjudication_dropped, adjudication_drop_msg = False, ""
    if "adjudication" in fields:
        adjudication_dropped, adjudication_drop_msg = _coerce_finding_adjudication(finding_id, fields)

    # If the dropped adjudication was the only field, there's nothing left to
    # persist — surface the reject/drop guidance directly instead of a
    # misleading "Finding not found".
    if not fields and adjudication_dropped:
        return f"Finding {finding_id}: adjudication not stored.{adjudication_drop_msg}"

    updated = await findings_store.update_finding(finding_id, **fields)
    if updated:
        msg = f"Finding updated: {finding_id} — fields: {', '.join(fields.keys())}"
        if adjudication_dropped:
            msg += adjudication_drop_msg
        else:
            _log_adjudication_verdict(finding_id, updated, fields)
        return msg
    return f"Finding not found: {finding_id}"


async def _do_delete_finding(data):
    finding_id = data.get("id", "")
    if not finding_id:
        return "Missing required field: id"
    archived = await findings_store.delete_finding(finding_id)
    if archived:
        return f"Finding archived: {finding_id} — moved to archived[] in findings.json"
    return f"Finding not found: {finding_id}"
