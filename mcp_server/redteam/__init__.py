"""Manual-layer red-team engine for /ai-redteam.

Deterministic, in-process primitives that make the agent-driven ("manual") layer
systematic instead of improvised. No API key required for the core; the LLM-judge
and attacker are optional upgrades used when a key is configured.

Capabilities:
  oracles       — refusal classifier + marker/regex match + optional LLM-judge +
                  side-effect oracle + structured (JSONPath) oracle for integrity
                  objectives + system-prompt-leak oracle (LLM07: detects a dumped
                  prompt by shape, scores severity from leaked secrets — no canary
                  needed) — score a response, gives the loop a gradient
  techniques    — curated, parameterized jailbreak technique families (a registry,
                  the manual analog of garak's probe list)
  indirect      — document/indirect-injection attack for integrity objectives:
                  embed an instruction in a carrier (prefix/suffix/inline/steg),
                  judged by a structured JSONPath present/absent predicate
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

from . import calibration, filter_probe, indirect, jsonpath, oracles, taxonomy, techniques
from .attack_loop import feedback_attack, reproduce
from .indirect import embed, indirect_attack, make_oracle
from .oracles import (
    Verdict,
    find_secrets,
    heuristic_judge,
    leak_verdict,
    llm_judge,
    refusal_score,
    structured_verdict,
    transport_status,
)
from .techniques import TECHNIQUES, list_techniques, render

__all__ = [
    "oracles", "techniques", "filter_probe", "calibration", "taxonomy",
    "indirect", "jsonpath",
    "feedback_attack", "reproduce",
    "indirect_attack", "embed", "make_oracle",
    "Verdict", "heuristic_judge", "llm_judge", "refusal_score",
    "structured_verdict", "leak_verdict", "find_secrets", "transport_status",
    "TECHNIQUES", "list_techniques", "render",
]
