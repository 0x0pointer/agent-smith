"""
Finding actions: create / update / delete / list, plus finding hygiene
(trace validation, cross-run dedup, coverage auto-linking, adjudication).
"""
import asyncio
import re

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
        "across runs. You ALREADY HAVE WHAT YOU NEED: to CHAIN this finding, pass "
        f"'{eid}' directly as from_finding_id / to_finding_id in report(action='chain') — do NOT "
        "re-file just to obtain an id. To revise it, use "
        f"report(action='update_finding', data={{'id': '{eid}', ...}}). If this is a GENUINELY "
        "DISTINCT issue (different endpoint/parameter/component), re-file with a more specific "
        "title. See every finding's id with report(action='list_findings')."
    )


# Generic verbs/prepositions that distinguish wording but not the underlying issue — dropped
# when comparing titles for NEAR-duplicate detection so "leaks X" and "exposes X" look alike.
_TITLE_STOPWORDS = frozenset({
    "the", "a", "an", "of", "in", "on", "to", "via", "and", "or", "with", "for", "is", "are",
    "exposes", "leaks", "allows", "enables", "reveals", "discloses", "exposed", "leaking",
    "that", "this", "full", "endpoint",
})


def _title_tokens(title) -> set:
    """Significant word tokens of a title (lowercased, stopwords + <3-char noise removed)."""
    return {t for t in re.findall(r"[a-z0-9]+", _norm_text(title))
            if t not in _TITLE_STOPWORDS and len(t) > 2}


def _near_duplicate(title: str, target: str, severity: str) -> dict | None:
    """Best existing finding that LOOKS like a near-duplicate (same target + severity, high
    title-token Jaccard) but is not an exact dup. Used ONLY for a NON-BLOCKING hint — we never
    auto-suppress on a fuzzy match, because wrongly dropping a genuinely distinct vuln is far
    worse than two similar findings the operator can merge."""
    toks = _title_tokens(title)
    if len(toks) < 3:
        return None
    ntg, nsev = _norm_target(target), _norm_text(severity)
    best, best_j = None, 0.0
    for f in findings_store._load().get("findings", []):
        if _norm_target(f.get("target")) != ntg or _norm_text(f.get("severity")) != nsev:
            continue
        ft = _title_tokens(f.get("title"))
        if not ft:
            continue
        j = len(toks & ft) / len(toks | ft)
        if j > best_j:
            best, best_j = f, j
    return best if 0.5 <= best_j < 1.0 else None


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

    # NON-BLOCKING near-duplicate check (computed BEFORE filing, against existing findings):
    # surfaces a likely dup as a hint in the response, never suppresses.
    near = _near_duplicate(title, target, severity)

    # Link the proof artifact: explicit artifact_id if the model passed one,
    # else the session's most-recent tool artifact (the call that produced this
    # finding). Adjudication reuses it so the attack never has to be re-run.
    evidence_artifact_id = (data.get("artifact_id") or "").strip()
    if not evidence_artifact_id:
        evidence_artifact_id = (scan_session.get() or {}).get("last_artifact_id", "") or ""

    # Compositional-chaining primitives: explicit provides/requires, validated
    # drop-unknown so a taxonomy typo never rejects a good finding.
    from core.graph import primitives as _prim
    capabilities = {
        "provides": _prim.coerce_primitive_list(data.get("provides")),
        "requires": _prim.coerce_primitive_list(data.get("requires")),
    }
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
        capabilities=capabilities,
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

    # smith-event: finding event (training-data Plane A) — fire-and-forget, fail-soft
    try:
        from mcp_server.scan_engine.smith_events import emit_finding
        emit_finding(data, entry.get("id", ""), evidence_artifact_id)
    except Exception:
        pass

    # ── Auto-trigger gates based on finding content ──────────────────────────
    gates_triggered = _auto_trigger_finding_gates(title, severity, data.get("description", ""), data.get("cve", ""))
    return _finding_filed_message(entry, severity, title, linked_cell, gates_triggered, near)


def _finding_filed_message(entry: dict, severity: str, title: str,
                           linked_cell, gates_triggered, near) -> str:
    """Assemble the response for a successfully filed finding (id echo + matrix/gate/near-dup
    notes). Split out of _do_finding to keep that function's cognitive complexity bounded."""
    msg = f"Finding logged: [{severity.upper()}] {title} (id={entry.get('id','?')})"
    if linked_cell:
        msg += f"\n\nMATRIX UPDATED: cell {linked_cell} auto-marked vulnerable (linked to this finding)."
    if gates_triggered:
        msg += f"\n\nGATE(S) TRIGGERED: {', '.join(gates_triggered)}. These skills are now mandatory before completion."
    if near is not None:
        msg += (
            f"\n\n⚠ POSSIBLE DUPLICATE of id={near.get('id')} (\"{(near.get('title') or '')[:60]}\") — "
            "same target + severity, very similar title. If it is the SAME issue, prefer "
            f"report(action='update_finding', data={{'id': '{near.get('id')}', ...}}) or chain to it, "
            "rather than keeping two. Filed anyway (never auto-suppressed — that could drop a real "
            "distinct finding); review with report(action='list_findings')."
        )
    return msg


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _finding_matches(f: dict, sev_filter: str, query: str) -> bool:
    """True if finding f passes the list_findings filters (empty filters match all)."""
    if sev_filter and _norm_text(f.get("severity")) != sev_filter:
        return False
    if query and query not in _norm_text(f.get("title")) and query not in _norm_text(f.get("description")):
        return False
    return True


def _finding_list_row(f: dict) -> str:
    sev = (f.get("severity") or "?")[:4]
    status = f.get("status")
    st = f" [{status}]" if status and _norm_text(status) != "open" else ""
    return f"  {f.get('id','?')}  [{sev:<4}] {(f.get('title') or '')[:74]}{st}"


def _do_list_findings(data):
    """List findings on record WITH their IDs so the agent can retrieve the UUIDs it needs to
    compose exploit chains (report(action='chain')) without re-filing — re-filing hits the dedup
    guard and strands the agent, which is exactly how a chain-filing phase wedges. Optional
    filters: severity (exact), query (substring of title/description)."""
    sev_filter = _norm_text(data.get("severity", ""))
    query = _norm_text(data.get("query", ""))
    rows = [f for f in findings_store._load().get("findings", [])
            if _finding_matches(f, sev_filter, query)]
    if not rows:
        suffix = " matching that filter" if (sev_filter or query) else ""
        return f"No findings on record{suffix}."
    rows.sort(key=lambda f: _SEV_ORDER.get(_norm_text(f.get("severity")), 5))
    lines = [f"{len(rows)} finding(s) on record — use the id directly in "
             "report(action='chain') / update_finding:"]
    lines.extend(_finding_list_row(f) for f in rows)
    return "\n".join(lines)


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
