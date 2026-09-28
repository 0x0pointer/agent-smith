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


def _make_deliver(send_fn: Callable[..., str], rng: random.Random):
    """Return a deliver(payload)->reply that handles single- and multi-turn payloads."""
    def deliver(payload):
        if isinstance(payload, list):                      # multi-turn technique
            cid = f"fa-{rng.getrandbits(30)}"
            last = ""
            for turn in payload:
                last = send_fn(turn, cid)
            return last
        return send_fn(payload, None)
    return deliver


def _encode_variant(tname: str, goal: str, tf: str, rng: random.Random):
    """Render a creative variant of `tname` and stack bypass encoding `tf` on it."""
    base = render_variant(tname, goal, rng.randint(0, 3))
    try:
        return [_tencode(x, [tf]) for x in base] if isinstance(base, list) else _tencode(base, [tf])
    except Exception as e:
        return f"[encode error: {e}]"


class _Run:
    """Mutable state for one feedback_attack: keeps the transcript, attempt count and
    running best, and scores a single payload — so the phase loops stay flat."""

    def __init__(self, judge, deliver, max_attempts: int, goal: str):
        self._judge = judge
        self._deliver = deliver
        self._max = max_attempts
        self.transcript: list[dict] = []
        self.attempts = 0
        self.best = (Verdict(False, -1.0, "refused"), "none", None, goal)

    def exhausted(self) -> bool:
        return self.attempts >= self._max

    def jailbroken(self) -> bool:
        return self.best[0].complied

    def top_techniques(self, k: int) -> list[str]:
        return sorted({t["technique"] for t in self.transcript},
                      key=lambda tn: max(x["score"] for x in self.transcript if x["technique"] == tn),
                      reverse=True)[:k]

    def attempt(self, payload, phase: int, tname: str, tf) -> bool:
        """Deliver + judge one payload; record it and update best. Returns complied."""
        try:
            resp = self._deliver(payload)
        except Exception as e:
            resp = f"[send error: {e}]"
        v = self._judge(resp)
        self.attempts += 1
        sent = payload if isinstance(payload, str) else " ⟶ ".join(payload)
        self.transcript.append({"phase": phase, "technique": tname, "transform": tf,
                                "sent": sent[:240], "score": v.score, "label": v.label,
                                "resp": resp[:220]})
        if v.score > self.best[0].score:
            self.best = (v, tname, tf, payload)
        return v.complied

    def result(self) -> dict:
        return _result(self.jailbroken(), self.best, self.transcript, self.attempts)


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

    def judge(text: str) -> Verdict:
        return llm_judge(text, goal, model=model, success_markers=success_markers)

    run = _Run(judge, _make_deliver(send_fn, rng), max_attempts, goal)

    # phase 1 — breadth: one attempt per technique across the breadth slice
    for tname in techs[:breadth_cap]:
        if run.exhausted():
            break
        if run.attempt(render_variant(tname, goal, rng.randint(0, 3)), 1, tname, None):
            return run.result()

    # phase 2 — depth: hill-climb from the top families, stacking bypass encodings
    for tname in run.top_techniques(3):
        for tf in tfs:
            if run.exhausted():
                break
            if run.attempt(_encode_variant(tname, goal, tf, rng), 2, tname, tf):
                return run.result()

    # phase 3 — creative mutation: obfuscate the strongest plaintext payload with
    # random multi-transform chains (homoglyph / zero-width / base64 combos) the
    # single-transform sweep never reaches, so the attack stays unpredictable.
    base_payload = run.best[3]
    if not run.jailbroken() and not run.exhausted() and isinstance(base_payload, str):
        for m in _mutate(base_payload, count=min(max_attempts - run.attempts, 6), seed=seed):
            if run.exhausted():
                break
            if run.attempt(m["payload"], 3, run.best[1], "+".join(m["chain"]) or "mutate"):
                return run.result()

    return run.result()


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
