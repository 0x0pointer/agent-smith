"""Feedback-guided attack loop (PAIR/TAP-style) + k/N reproducibility.

Instead of firing one payload and calling it, the loop hill-climbs on the oracle
score:

  phase 1 (breadth): try each technique family once (plaintext) and score it;
  phase 2 (depth):   take the best-scoring families and stack bypass encodings /
                     escalate, keeping only improvements — until the judge says
                     the target complied, or the attempt budget / saturation hits.

The judge (oracles) supplies the gradient, so the search actually pushes toward
compliance rather than wandering randomly. `reproduce()` re-runs a confirmed
attack N times for a k/N rate (LLM outputs are non-deterministic).
"""
from __future__ import annotations

import random
from typing import Callable

from mcp_server.transforms import encode as _tencode
from mcp_server.transforms.generators import mutate as _mutate

from .oracles import Verdict, llm_judge
from .techniques import TECHNIQUES, render, render_variant, technique_pool

_DEFAULT_TECHS = ["direct", "authority", "roleplay", "hypothetical",
                  "refusal_suppression", "repeat_above", "payload_split",
                  "virtualization", "cot_forgery", "bad_likert", "crescendo"]
_DEFAULT_TFS = ["base64", "leetspeak", "unicode_tags", "rot13"]


def _result(jailbroken, best, transcript, attempts):
    v, tname, tf, payload = best
    return {
        "jailbroken": jailbroken,
        "best": {"technique": tname, "transform": tf, "score": v.score,
                 "label": v.label, "rationale": v.rationale,
                 "payload": payload if isinstance(payload, str) else " | ".join(payload)},
        "attempts": attempts,
        "transcript": transcript,
    }


def feedback_attack(goal: str,
                    send_fn: Callable[..., str],
                    success_markers: list[str] | None = None,
                    model=None,
                    transforms: list[str] | None = None,
                    techniques_order: list[str] | None = None,
                    max_attempts: int = 24,
                    seed: int = 0) -> dict:
    """Drive the target toward `goal`. `send_fn(message, conversation_id=None) -> str`.
    `success_markers` (e.g. a secret) make the oracle decisive; `model` (callable)
    enables the semantic LLM-judge, else a heuristic gradient is used."""
    techs = techniques_order or technique_pool(seed=seed, creative=True)
    tfs = transforms if transforms is not None else _DEFAULT_TFS
    rng = random.Random(seed)
    # Budget split: reserve room for depth (transform stacking) + mutation so the
    # 81-technique breadth sweep can't consume the whole budget. Breadth still runs
    # the tuned core + a creative PITAX slice; depth is where encoded bypasses land.
    depth_reserve = max(8, max_attempts // 3)
    breadth_cap = max(len(TECHNIQUES), max_attempts - depth_reserve)
    transcript: list[dict] = []
    attempts = 0

    def judge(text: str) -> Verdict:
        return llm_judge(text, goal, model=model, success_markers=success_markers)

    def deliver(payload) -> str:
        if isinstance(payload, list):                      # multi-turn technique
            cid = f"fa-{rng.getrandbits(30)}"
            last = ""
            for turn in payload:
                last = send_fn(turn, cid)
            return last
        return send_fn(payload, None)

    best = (Verdict(False, -1.0, "refused"), "none", None, goal)

    # phase 1 — breadth: one attempt per technique across the breadth slice
    for tname in techs[:breadth_cap]:
        if attempts >= max_attempts:
            break
        payload = render_variant(tname, goal, rng.randint(0, 3))
        try:
            resp = deliver(payload)
        except Exception as e:
            resp = f"[send error: {e}]"
        v = judge(resp)
        attempts += 1
        sent = payload if isinstance(payload, str) else " ⟶ ".join(payload)
        transcript.append({"phase": 1, "technique": tname, "transform": None,
                           "sent": sent[:240], "score": v.score, "label": v.label, "resp": resp[:220]})
        if v.score > best[0].score:
            best = (v, tname, None, payload)
        if v.complied:
            return _result(True, best, transcript, attempts)

    # phase 2 — depth: hill-climb from the top families, stacking bypass encodings
    top = sorted({t["technique"] for t in transcript},
                 key=lambda tn: max(x["score"] for x in transcript if x["technique"] == tn),
                 reverse=True)[:3]
    for tname in top:
        for tf in tfs:
            if attempts >= max_attempts:
                break
            base = render_variant(tname, goal, rng.randint(0, 3))
            try:
                payload = [_tencode(x, [tf]) for x in base] if isinstance(base, list) else _tencode(base, [tf])
                resp = deliver(payload)
            except Exception as e:
                resp = f"[send error: {e}]"
            v = judge(resp)
            attempts += 1
            sent = payload if isinstance(payload, str) else " ⟶ ".join(payload)
            transcript.append({"phase": 2, "technique": tname, "transform": tf,
                               "sent": sent[:240], "score": v.score, "label": v.label, "resp": resp[:220]})
            if v.score > best[0].score:
                best = (v, tname, tf, payload)
            if v.complied:
                return _result(True, best, transcript, attempts)

    # phase 3 — creative mutation: obfuscate the strongest plaintext payload with
    # random multi-transform chains (homoglyph / zero-width / base64 combos) the
    # single-transform sweep never reaches, so the attack stays unpredictable.
    base_payload = best[3]
    if not best[0].complied and attempts < max_attempts and isinstance(base_payload, str):
        for m in _mutate(base_payload, count=min(max_attempts - attempts, 6), seed=seed):
            if attempts >= max_attempts:
                break
            try:
                resp = deliver(m["payload"])
            except Exception as e:
                resp = f"[send error: {e}]"
            v = judge(resp)
            attempts += 1
            label = "+".join(m["chain"]) or "mutate"
            transcript.append({"phase": 3, "technique": best[1], "transform": label,
                               "sent": m["payload"][:240], "score": v.score,
                               "label": v.label, "resp": resp[:220]})
            if v.score > best[0].score:
                best = (v, best[1], label, m["payload"])
            if v.complied:
                return _result(True, best, transcript, attempts)

    return _result(best[0].complied, best, transcript, attempts)


def reproduce(attack_callable: Callable[[], object], n: int = 10) -> dict:
    """Run an attack `n` times → k/N rate. `attack_callable()` returns a Verdict or
    a bool (True == success). LLM non-determinism means 0/1 or 1/1 is not evidence;
    0/N and k/N are."""
    hits = 0
    results = []
    for _ in range(n):
        r = attack_callable()
        ok = r.complied if isinstance(r, Verdict) else bool(r)
        hits += ok
        results.append(ok)
    return {"k": hits, "n": n, "rate": round(hits / n, 3) if n else 0.0, "results": results}
