"""AI red-team summarizer (garak: probe-based LLM scanning).

This parses the structured output the garak handler appends to the raw tool
stdout (garak's report.jsonl) and surfaces per-probe HITS as anomalies,
recommending a finding + closing the matching LLM coverage cell, so a confirmed
jailbreak is no longer lost in clipped console text. Success detection is
best-effort/heuristic — the skill must still verify before filing — but a parse
failure degrades to a useful summary, never a crash.
"""
from __future__ import annotations

import json

from ._common import SummaryResult


def _section_after(raw: str, marker: str) -> str:
    """Return the slice of `raw` after the first occurrence of `marker`, or ''."""
    idx = raw.find(marker)
    return raw[idx + len(marker):] if idx != -1 else ""


def _parse_garak_evals(section: str) -> list[dict]:
    """Parse garak report.jsonl lines → the 'eval'-type entries only."""
    evals: list[dict] = []
    for line in section.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        if d.get("entry_type") == "eval":
            evals.append(d)
    return evals


def _collect_garak_hits(evals: list[dict], result: SummaryResult) -> list[dict]:
    """Append a per-probe fact line to `result` for each eval; return the ones with hits.

    garak 0.15.0 eval entries carry an explicit ``fails`` count and
    ``total_evaluated`` (NOT ``total``). We prefer those; a missing ``fails``
    falls back to ``total - passed`` so older/simpler shapes still parse. Using
    ``e.get("total")`` alone silently reported 0 hits on real 0.15.0 output — a
    false negative that hid genuine garak findings.
    """
    hits: list[dict] = []
    for e in evals:
        probe    = e.get("probe", "?")
        detector = e.get("detector", "?")
        total    = e.get("total_evaluated", e.get("total", 0)) or 0
        passed   = e.get("passed", 0) or 0
        failed   = e.get("fails")
        if failed is None:
            failed = (total - passed) if total else 0
        failed = failed or 0
        result.facts.append(f"{probe}/{detector}: {failed}/{total} hit(s)")
        if failed > 0:
            hits.append({"probe": probe, "detector": detector, "failed": failed, "total": total})
    result.facts = result.facts[:20]
    return hits


def _summarize_garak(raw: str, _ctx: dict) -> SummaryResult:
    """Parse garak's report.jsonl eval entries for per-probe attack hits."""
    result = SummaryResult()
    section = _section_after(raw, "=== GARAK REPORT JSONL ===")
    evals = _parse_garak_evals(section)

    if not evals:
        result.summary = ("garak ran — no eval entries parsed. Likely an INCOMPLETE run "
                          "(timeout on a slow real LLM endpoint — cut probes or use -g 1) or "
                          "the REST config never reached the target (check response_field).")
        result.facts = [l.strip()[:200] for l in raw.strip().splitlines()[:5] if l.strip()]
        result.evidence = {"eval_entries": 0}
        result.recommended.append(
            "Verify the garak REST config reached the target (response_field set?); inspect the artifact"
        )
        return result

    hits = _collect_garak_hits(evals, result)
    autofiled = _ctx.get("autofiled") or []

    if hits:
        result.summary = f"garak: {len(hits)} probe(s) with hits across {len(evals)} eval(s)"
        for h in hits[:10]:
            result.anomalies.append(f"garak hit: {h['probe']}/{h['detector']} {h['failed']}/{h['total']}")
        if autofiled:
            result.facts.append(f"auto-filed {len(autofiled)} finding(s) tagged tool_used='garak'")
            result.recommended.append(
                f"{len(autofiled)} garak finding(s) were auto-filed (tool_used='garak'). VERIFY each "
                "transcript, adjudicate severity, then close the matching LLM coverage cell vulnerable "
                "with its finding_id + this artifact_id"
            )
        else:
            result.recommended.append(
                "File report(action='finding') per garak hit, then close the matching LLM coverage "
                "cell vulnerable with this artifact_id"
            )
    else:
        result.summary = f"garak: no hits across {len(evals)} eval(s) — model resisted all probes"
    result.evidence = {"eval_entries": len(evals), "hits": hits[:20], "autofiled": autofiled}
    return result

