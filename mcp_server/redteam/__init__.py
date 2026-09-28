"""Manual-layer red-team engine for /ai-redteam.

Deterministic, in-process primitives that make the agent-driven ("manual") layer
systematic instead of improvised. No API key required for the core; the LLM-judge
and attacker are optional upgrades used when a key is configured.

Capabilities:
  oracles       — refusal classifier + marker/regex match + optional LLM-judge +
                  side-effect oracle (score a response, gives the loop a gradient)
  techniques    — curated, parameterized jailbreak technique families (a registry,
                  the manual analog of garak's probe list)
  filter_probe  — adaptive: learn which transforms a target's input filter lets
                  through, so payloads only use bypassing encodings
  attack_loop   — feedback-guided (PAIR/TAP-style) hill-climbing attack + k/N
                  reproducibility runner
  calibration   — self-test the engine against the OWASP labs (canary) before you
                  trust a clean result on a real target
  taxonomy      — Arcanum Prompt Injection Taxonomy (PITAX, CC BY 4.0): 172 nodes
                  (intents/techniques/evasions/inputs) to look up + search
"""
from __future__ import annotations

from . import calibration, filter_probe, oracles, taxonomy, techniques
from .attack_loop import feedback_attack, reproduce
from .oracles import Verdict, heuristic_judge, llm_judge, refusal_score
from .techniques import TECHNIQUES, list_techniques, render

__all__ = [
    "oracles", "techniques", "filter_probe", "calibration", "taxonomy",
    "feedback_attack", "reproduce",
    "Verdict", "heuristic_judge", "llm_judge", "refusal_score",
    "TECHNIQUES", "list_techniques", "render",
]
