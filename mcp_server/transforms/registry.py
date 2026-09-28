"""Central transform registry — merges every sub-module into one table and
exposes the encode/decode/chain primitives the MCP tool calls.
"""
from __future__ import annotations

from . import encodings, homoglyphs, invisible, scripts

TRANSFORMS: dict[str, dict] = {}
for _mod in (encodings, homoglyphs, invisible, scripts):
    for _name, _spec in _mod.TRANSFORMS.items():
        TRANSFORMS[_name] = _spec  # names are unique across modules; last wins if not

CATEGORIES = sorted({spec["category"] for spec in TRANSFORMS.values()})

# Reversible == has a working decode (participates in the universal decoder).
REVERSIBLE = {n for n, s in TRANSFORMS.items() if s["reversible"] and s.get("decode")}

# Transforms safe to stack per-word for mutation fuzzing (visually legible,
# don't require the whole string as one blob).
RANDOMIZABLE = [
    "leetspeak", "fullwidth", "bold", "italic", "script", "circled",
    "greek", "cyrillic", "strikethrough", "underline", "monospace",
    "reverse", "vaporwave", "alternating_case",
]


def list_transforms(category: str | None = None) -> list[dict]:
    out = []
    for name, spec in sorted(TRANSFORMS.items()):
        if category and spec["category"] != category:
            continue
        out.append({"name": name, "category": spec["category"], "reversible": spec["reversible"]})
    return out


def encode(text: str, names: list[str]) -> str:
    """Apply transforms left-to-right (chaining)."""
    for name in names:
        spec = TRANSFORMS.get(name)
        if not spec:
            raise KeyError(f"unknown transform '{name}'")
        text = spec["encode"](text)
    return text


def decode(text: str, names: list[str]) -> str:
    """Reverse a known chain: apply each transform's decode in reverse order."""
    for name in reversed(names):
        spec = TRANSFORMS.get(name)
        if not spec:
            raise KeyError(f"unknown transform '{name}'")
        fn = spec.get("decode")
        if not fn:
            raise ValueError(f"transform '{name}' is not reversible")
        text = fn(text)
    return text
