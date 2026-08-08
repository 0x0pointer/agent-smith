"""
Adjudication audit-trail handling for finding updates.
"""
from ._common import findings_store


def _log_adjudication_verdict(finding_id, updated, fields):
    """Best-effort: append the senior-review verdict to the adjudication log.

    Extracted from _do_update_finding to keep that function's cognitive
    complexity in check. A no-op when there's no adjudication payload; never
    raises (logging must not fail the update).
    """
    adj = fields.get("adjudication")
    if not adj:
        return
    try:
        from core.adjunction.log import log_verdict
        log_verdict(
            finding_id=finding_id,
            title=updated.get("title", finding_id),
            original_severity=str(adj.get("original_severity", "")),
            revised_severity=str(adj.get("revised_severity", "")),
            reproducible=adj.get("reproducible", ""),
            rationale=str(adj.get("rationale", "")),
        )
    except Exception:
        pass


def _coerce_finding_adjudication(finding_id: str, fields: dict) -> tuple[bool, str]:
    """Normalise/validate the adjudication audit trail in ``fields`` (mutates it).

    Returns ``(dropped, message)``. ``dropped=True`` means the adjudication was
    removed — no rationale, or a reproducible verdict with no on-disk artifact —
    and ``message`` explains why (it must not falsely satisfy the completion-time
    adjudication gate). ``dropped=False`` means it was normalised and stored.
    """
    from core.adjunction import coerce_adjudication
    from mcp_server.scan_engine.artifacts import artifact_exists
    current = next(
        (f for f in findings_store._load().get("findings", []) if f.get("id") == finding_id),
        None,
    )
    coerced = coerce_adjudication(fields.get("adjudication"), current)
    if coerced is None:
        fields.pop("adjudication", None)
        return True, (
            "\n\nNOTE: adjudication was ignored — it needs a non-empty 'rationale'. "
            "Re-send with adjudication={reproducible, original_severity, revised_severity, "
            "rationale} for it to count toward completion."
        )
    if coerced.get("reproducible") and not artifact_exists(coerced.get("artifact_id", "")):
        # The supplied artifact is missing/absent — but the proof was already
        # captured when the finding was filed. Reuse that linked evidence
        # artifact so the model doesn't re-run the attack just to regenerate an
        # artifact_id it lost to context compaction.
        linked = (current or {}).get("evidence_artifact_id", "")
        if linked and artifact_exists(linked):
            coerced["artifact_id"] = linked
        else:
            # A reproducible verdict must be backed by an artifact that exists on
            # disk — mirrors the coverage layer's artifact-existence rule.
            fields.pop("adjudication", None)
            _aid = coerced.get("artifact_id", "")
            _why = "no artifact_id was provided" if not _aid else f"artifact_id '{_aid}' does not exist on disk"
            return True, (
                f"\n\nREJECTED: adjudication claims reproducible=true but {_why}, and the finding "
                "has no linked evidence artifact to fall back on. Re-run the attack that proves "
                "the finding reproduces, capture the artifact_id from that tool response, and "
                "re-send the adjudication with it. (Set reproducible=false to mark it a false "
                "positive instead.)"
            )
    fields["adjudication"] = coerced
    return False, ""
