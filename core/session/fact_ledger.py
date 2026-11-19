"""
Durable fact ledger (#1)
========================
A structured, session-persisted record of what the agent actually KNOWS, split
into three buckets so a fresh context (compaction / restart) builds on evidence
instead of re-deriving — and never inherits a phantom as if it were truth:

    CONFIRMED   evidence-backed primitives / facts — the authoritative set.
                A confirmed entry MUST carry an evidence reference (an artifact
                id, a finding id, a tool-result id). A "confirmed" with no
                evidence is demoted to HYPOTHESIS — this split is the whole point.
    HYPOTHESIS  unverified leads ("maybe a second password exists"). NON-
                authoritative: surfaced as leads to test, never as established
                fact, so a misread never propagates across restarts.
    RULED_OUT   tried-and-failed negatives ("user_id=1 → 404, no such user").
                Carried forward so a respawned context does not re-walk a dead
                end — the single most expensive restart tax in the XBEN failures.

Why a dedicated ledger (vs findings): findings capture confirmed VULNS; this
captures sub-finding facts (a cracked key, a reflected header, a mapped filter)
and — uniquely — the NEGATIVES. Advisory, non-blocking, fail-soft: a ledger
error can never break a tool call. Mirrors surface_ledger's session pattern.

State (session.json)::

    fact_ledger = {
        "confirmed":  [{"text", "evidence", "ts"}, ...],
        "hypothesis": [{"text", "ts"}, ...],
        "ruled_out":  [{"text", "reason", "ts"}, ...],
    }
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

import core.session as _sess

_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_MAX_PER_BUCKET = 60          # bound the session file; oldest-trimmed past this
_MAX_TEXT = 300               # a fact is a short statement, not a transcript
_BUCKETS = ("confirmed", "hypothesis", "ruled_out")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clean(text: object) -> str:
    s = _CTRL.sub(" ", str(text or "")).strip()
    return s[:_MAX_TEXT]


def _norm(text: str) -> str:
    """Dedup key: lowercase, collapse whitespace."""
    return re.sub(r"\s+", " ", text.lower()).strip()


def _ledger() -> dict | None:
    if not _sess._current:
        return None
    fl = _sess._current.get("fact_ledger")
    if not isinstance(fl, dict):
        fl = {b: [] for b in _BUCKETS}
        _sess._current["fact_ledger"] = fl
    for b in _BUCKETS:
        fl.setdefault(b, [])
    return fl


def _dedup_key(text: str) -> str:
    return _norm(text)


def _remove_from(fl: dict, bucket: str, key: str) -> dict | None:
    """Drop and return any entry in ``bucket`` whose text matches ``key``."""
    kept, hit = [], None
    for e in fl.get(bucket, []):
        if _norm(e.get("text", "")) == key:
            hit = e
        else:
            kept.append(e)
    fl[bucket] = kept
    return hit


def _append(fl: dict, bucket: str, entry: dict) -> None:
    key = _dedup_key(entry["text"])
    # a fact can live in only ONE bucket — remove any prior copy across buckets
    for b in _BUCKETS:
        _remove_from(fl, b, key)
    fl[bucket].append(entry)
    if len(fl[bucket]) > _MAX_PER_BUCKET:
        fl[bucket] = fl[bucket][-_MAX_PER_BUCKET:]


def record_confirmed(text: str, evidence: str | None = None) -> dict:
    """Record an evidence-backed fact. Without evidence it is demoted to a
    HYPOTHESIS (the authoritative/non-authoritative split). Returns a status
    dict; never raises."""
    try:
        fl = _ledger()
        text = _clean(text)
        if fl is None or not text:
            return {"ok": False, "reason": "no session or empty text"}
        evidence = _clean(evidence) or None
        if not evidence:
            _append(fl, "hypothesis", {"text": text, "ts": _now()})
            _sess._flush()
            return {"ok": True, "bucket": "hypothesis",
                    "note": "no evidence reference → recorded as HYPOTHESIS, not CONFIRMED. "
                            "Re-record with evidence (artifact_id/finding_id) once proven."}
        _append(fl, "confirmed", {"text": text, "evidence": evidence, "ts": _now()})
        _sess._flush()
        return {"ok": True, "bucket": "confirmed"}
    except Exception:
        return {"ok": False, "reason": "ledger error (non-fatal)"}


def record_hypothesis(text: str) -> dict:
    try:
        fl = _ledger()
        text = _clean(text)
        if fl is None or not text:
            return {"ok": False, "reason": "no session or empty text"}
        _append(fl, "hypothesis", {"text": text, "ts": _now()})
        _sess._flush()
        return {"ok": True, "bucket": "hypothesis"}
    except Exception:
        return {"ok": False, "reason": "ledger error (non-fatal)"}


def record_ruled_out(text: str, reason: str = "") -> dict:
    try:
        fl = _ledger()
        text = _clean(text)
        if fl is None or not text:
            return {"ok": False, "reason": "no session or empty text"}
        _append(fl, "ruled_out", {"text": text, "reason": _clean(reason), "ts": _now()})
        _sess._flush()
        return {"ok": True, "bucket": "ruled_out"}
    except Exception:
        return {"ok": False, "reason": "ledger error (non-fatal)"}


def promote(text: str, evidence: str) -> dict:
    """Promote a hypothesis to CONFIRMED when evidence arrives (requires evidence)."""
    evidence = _clean(evidence)
    if not evidence:
        return {"ok": False, "reason": "promotion requires an evidence reference"}
    return record_confirmed(text, evidence)


def overview(max_each: int = 12) -> dict:
    """Compact view for the recovery brief. Empty dict when nothing recorded."""
    try:
        fl = _ledger()
        if fl is None:
            return {}
        out: dict = {}
        conf = fl.get("confirmed", [])
        hyp = fl.get("hypothesis", [])
        ruled = fl.get("ruled_out", [])
        if conf:
            out["confirmed"] = [{"fact": e["text"], "evidence": e.get("evidence")}
                                for e in conf[-max_each:]]
        if hyp:
            out["hypothesis_unverified"] = [e["text"] for e in hyp[-max_each:]]
        if ruled:
            out["ruled_out_do_not_retry"] = [
                (f"{e['text']} — {e['reason']}" if e.get("reason") else e["text"])
                for e in ruled[-max_each:]]
        return out
    except Exception:
        return {}


def counts() -> dict:
    fl = _ledger()
    if fl is None:
        return {b: 0 for b in _BUCKETS}
    return {b: len(fl.get(b, [])) for b in _BUCKETS}
