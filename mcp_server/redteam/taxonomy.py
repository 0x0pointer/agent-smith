"""Arcanum Prompt Injection Taxonomy (PITAX) — a queryable reference in the engine.

Vendored from Arcanum-Sec/arc_pi_taxonomy (CC BY 4.0 — see data/ATTRIBUTION.md).
172 nodes across four pillars, giving the manual layer a standardized vocabulary,
worked example prompts, and cross-refs (OWASP / MITRE ATLAS / NIST / garak) to
reason from instead of improvising:

  intents    (PIT-I, 27) — what the attacker wants (the goal)
  techniques (PIT-T, 70) — the method that manipulates the model
  evasions   (PIT-E, 63) — how the payload is obfuscated past filters
  inputs     (PIT-N, 12) — where the payload enters

The `transform()` engine implements many PIT-E evasions; the `techniques` library
mirrors PIT-T families (each Technique carries its `pit` code). This module surfaces
the whole taxonomy for lookup/search so a tester can pivot from a category to a
concrete, example-backed attack.
"""
from __future__ import annotations

import functools
import json
from pathlib import Path

_DATA = Path(__file__).parent / "data" / "arc_pi_taxonomy.json"

# pillar name -> (code prefix, human question it answers)
PILLARS = {
    "intents":    ("PIT-I", "what the attacker is trying to achieve"),
    "techniques": ("PIT-T", "the method that manipulates the model"),
    "evasions":   ("PIT-E", "how the payload is obfuscated past filters"),
    "inputs":     ("PIT-N", "where the payload enters"),
}


@functools.lru_cache(maxsize=1)
def _load() -> dict:
    try:
        d = json.loads(_DATA.read_text())
        return {p: d.get(p, []) for p in PILLARS}
    except Exception:
        return {p: [] for p in PILLARS}


def _brief(node: dict) -> dict:
    return {
        "code": node.get("code", ""),
        "id": node.get("id", ""),
        "title": node.get("title", ""),
        "description": node.get("description", ""),
        "delivery": node.get("delivery", ""),
        "aliases": node.get("aliases", []),
    }


def pillars() -> dict:
    """Overview: per-pillar code prefix, the question it answers, and node count."""
    d = _load()
    return {p: {"code_prefix": pre, "answers": q, "count": len(d.get(p, []))}
            for p, (pre, q) in PILLARS.items()}


def nodes(pillar: str) -> list[dict]:
    """Brief rows for one pillar (intents|techniques|evasions|inputs)."""
    return [_brief(n) for n in _load().get(pillar, [])]


def full(pillar: str) -> list[dict]:
    """Full nodes for a pillar, incl. ``ideas`` + ``examples`` — the raw material
    the executable technique bridge (techniques.py) renders goal-parameterized
    attacks from."""
    return list(_load().get(pillar, []))


def lookup(code_or_id: str) -> dict | None:
    """Full node (incl. ideas + example prompts) by PIT code or id; None if absent."""
    q = (code_or_id or "").strip().lower()
    if not q:
        return None
    for pillar, items in _load().items():
        for n in items:
            if n.get("code", "").lower() == q or n.get("id", "").lower() == q:
                return {"pillar": pillar, **n}
    return None


def search(query: str, limit: int = 25) -> list[dict]:
    """Substring search across title/description/ideas/aliases of every node."""
    q = (query or "").strip().lower()
    if not q:
        return []
    out: list[dict] = []
    for pillar, items in _load().items():
        for n in items:
            hay = " ".join([
                n.get("title", ""), n.get("description", ""),
                " ".join(n.get("ideas", []) or []),
                " ".join(n.get("aliases", []) or []),
            ]).lower()
            if q in hay:
                out.append({"pillar": pillar, **_brief(n)})
    return out[:limit]
