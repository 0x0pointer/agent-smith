"""AI red-team summarizers (garak / promptfoo / pyrit / fuzzyai).

These parse the structured output the AI scan handlers now append to the raw
tool stdout (garak's report.jsonl, promptfoo's results JSON) or the printed
transcript (pyrit/fuzzyai). They surface per-probe/plugin HITS as anomalies
and recommend filing a finding + closing the matching LLM coverage cell, so a
confirmed jailbreak is no longer lost in clipped console text. Success
detection is best-effort/heuristic — the skill must still verify before
filing — but a parse failure degrades to a useful summary, never a crash.
"""
from __future__ import annotations

import json

from ._common import SummaryResult


def _section_after(raw: str, marker: str) -> str:
    """Return the slice of `raw` after the first occurrence of `marker`, or ''."""
    idx = raw.find(marker)
    return raw[idx + len(marker):] if idx != -1 else ""


def _summarize_garak(raw: str, ctx: dict) -> SummaryResult:
    """Parse garak's report.jsonl eval entries for per-probe attack hits."""
    result = SummaryResult()
    section = _section_after(raw, "=== GARAK REPORT JSONL ===")
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

    if not evals:
        result.summary = "garak ran — no structured eval entries parsed (check artifact / REST config)"
        result.facts = [l.strip()[:200] for l in raw.strip().splitlines()[:5] if l.strip()]
        result.evidence = {"eval_entries": 0}
        result.recommended.append(
            "Verify the garak REST config reached the target (response_field set?); inspect the artifact"
        )
        return result

    hits: list[dict] = []
    for e in evals:
        probe    = e.get("probe", "?")
        detector = e.get("detector", "?")
        total    = e.get("total", 0) or 0
        passed   = e.get("passed", 0) or 0
        failed   = total - passed if total else 0
        result.facts.append(f"{probe}/{detector}: {failed}/{total} hit(s)")
        if failed > 0:
            hits.append({"probe": probe, "detector": detector, "failed": failed, "total": total})
    result.facts = result.facts[:20]

    if hits:
        result.summary = f"garak: {len(hits)} probe(s) with hits across {len(evals)} eval(s)"
        for h in hits[:10]:
            result.anomalies.append(f"garak hit: {h['probe']}/{h['detector']} {h['failed']}/{h['total']}")
        result.recommended.append(
            "File report(action='finding') per garak hit, then close the matching LLM coverage "
            "cell vulnerable with this artifact_id"
        )
    else:
        result.summary = f"garak: no hits across {len(evals)} eval(s) — model resisted all probes"
    result.evidence = {"eval_entries": len(evals), "hits": hits[:20]}
    return result


def _summarize_promptfoo(raw: str, ctx: dict) -> SummaryResult:
    """Parse promptfoo's results JSON; a failed assertion = attack succeeded."""
    result = SummaryResult()
    section = _section_after(raw, "=== PROMPTFOO RESULTS JSON ===").strip()
    data = None
    if section.startswith("{"):
        try:
            data = json.loads(section)
        except json.JSONDecodeError:
            data = None

    if not isinstance(data, dict):
        result.summary = "promptfoo ran — could not parse results JSON (check artifact)"
        result.facts = [l.strip()[:200] for l in raw.strip().splitlines()[:5] if l.strip()]
        result.evidence = {"parsed": False}
        result.recommended.append(
            "Verify promptfoo redteam config + attacker_provider (needs an attacker-LLM key); inspect the artifact"
        )
        return result

    res = data.get("results", data)
    stats = res.get("stats", {}) if isinstance(res, dict) else {}
    items = res.get("results", []) if isinstance(res, dict) else []
    if not isinstance(items, list):
        items = []
    # In a redteam eval, success=False means the safety assertion failed → the
    # attack got through.
    failed = [r for r in items if isinstance(r, dict) and r.get("success") is False]

    if isinstance(stats, dict) and stats:
        result.facts.append(
            f"passed={stats.get('successes')} failed/attacks-through={stats.get('failures')}"
        )
    result.summary = (
        f"promptfoo: {len(failed)} failing test(s) — attack got through"
        if failed else
        f"promptfoo: {len(items)} test(s), no failures parsed"
    )
    for r in failed[:10]:
        plugin = "?"
        tc = r.get("testCase") if isinstance(r.get("testCase"), dict) else {}
        meta = tc.get("metadata") if isinstance(tc.get("metadata"), dict) else {}
        plugin = meta.get("pluginId") or meta.get("strategyId") or "?"
        result.anomalies.append(f"promptfoo hit: plugin/strategy={plugin}")
    if failed:
        result.recommended.append(
            "File a finding per promptfoo failure, then close the matching LLM cell vulnerable with this artifact_id"
        )
    result.evidence = {"total": len(items), "failed": len(failed), "stats": stats if isinstance(stats, dict) else {}}
    return result


_PYRIT_SUCCESS_KEYS = (
    "score: true", "objective achieved", "true_false: true", "result: true", "achieved: true",
)


def _summarize_pyrit(raw: str, ctx: dict) -> SummaryResult:
    """Surface PyRIT's attack-result line, scorer verdict, and any degradation.

    Handles both single-objective runs and batch runs (a --payloads-file fans the
    same single-turn attack over a variant family, e.g. role-confusion). Batch
    output is delimited by '=== PAYLOAD i/N ===' markers; we attribute success per
    payload and report the hit count for one-cell-from-one-artifact closure.
    """
    import re
    result = SummaryResult()
    lines = raw.strip().splitlines()
    attack = ctx.get("attack", "?")

    degraded = [
        l.strip() for l in lines
        if "falling back" in l.lower() or "attacker llm unavailable" in l.lower()
        or "no attacker-llm" in l.lower() or "substringscorer fallback" in l.lower()
    ]
    if degraded:
        result.anomalies.append(
            "PyRIT degraded to a fallback (no attacker-LLM key or orchestrator API mismatch) — see artifact"
        )

    # ── Batch mode (role-confusion variant family etc.) ──────────────────────
    blocks = re.split(r"=== PAYLOAD \d+/\d+ ===", raw)
    if len(blocks) > 1:
        bodies = blocks[1:]  # blocks[0] is the runner preamble
        total = len(bodies)
        hit_idx = [i for i, b in enumerate(bodies, 1)
                   if any(k in b.lower() for k in _PYRIT_SUCCESS_KEYS)]
        hits = len(hit_idx)
        success = hits > 0
        pset = ctx.get("payload_set") or attack
        result.summary = f"pyrit {pset} batch: {hits}/{total} payload(s) achieved the objective"
        result.facts.append(f"payloads_hit={hit_idx}" if hit_idx else f"0/{total} payloads scored a success")
        result.facts += degraded[:2]
        if success:
            result.anomalies.append(
                f"PyRIT {pset} batch: {hits}/{total} payloads bypassed — likely role-confusion injection"
            )
            result.recommended.append(
                "File a finding and close the cot_forgery / role_prefix_spoofing cell vulnerable with this artifact_id"
            )
        result.evidence = {"attack": attack, "payload_set": ctx.get("payload_set", ""),
                           "batch": True, "payloads": total, "hits": hits,
                           "degraded": bool(degraded), "objective_achieved": success, "lines": len(lines)}
        return result

    # ── Single-objective mode ────────────────────────────────────────────────
    low = raw.lower()
    result_lines = [l.strip() for l in lines if "attack result:" in l.lower()]
    success = any(k in low for k in _PYRIT_SUCCESS_KEYS)

    result.summary = f"pyrit {attack}: " + (result_lines[0] if result_lines else "attack ran")
    if result_lines:
        result.facts += result_lines[:3]
    if degraded:
        result.facts += degraded[:2]
    if success:
        result.anomalies.append("PyRIT scorer indicated the objective was achieved — likely injection/jailbreak success")
        result.recommended.append(
            "File a finding and close the prompt_injection/jailbreak cell vulnerable with this artifact_id"
        )
    result.evidence = {"attack": attack, "degraded": bool(degraded), "objective_achieved": success, "lines": len(lines)}
    if not result.facts:
        result.facts = [l[:200] for l in lines[:5] if l]
    return result


def _summarize_fuzzyai(raw: str, ctx: dict) -> SummaryResult:
    """Surface FuzzyAI jailbreak/bypass success signals (heuristic)."""
    result = SummaryResult()
    lines = raw.strip().splitlines()
    attack = ctx.get("attack", ctx.get("_tool", "?"))
    hit_lines = [
        l.strip() for l in lines
        if any(k in l.lower() for k in ("jailbroken", "jailbreak success", "bypassed", "vulnerable", "success: true"))
    ]
    result.summary = (
        f"fuzzyai {attack}: {len(hit_lines)} success/jailbreak signal(s)"
        if hit_lines else
        f"fuzzyai {attack}: ran ({len(lines)} lines), no explicit success signal"
    )
    result.facts = hit_lines[:10] or [l[:200] for l in lines[:5] if l]
    if hit_lines:
        result.anomalies.append("FuzzyAI reported a jailbreak/bypass — verify and file a finding")
        result.recommended.append(
            "Reproduce via http(action='request'), then close the jailbreak cell vulnerable with the artifact_id"
        )
    result.evidence = {"attack": attack, "hit_signals": len(hit_lines)}
    return result
