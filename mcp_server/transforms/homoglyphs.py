"""Unicode homoglyph / styled-font substitutions (the "confusables" class).

Maps ASCII letters/digits to visually similar glyphs from the Mathematical
Alphanumeric Symbols, Enclosed Alphanumerics, and lookalike (Greek/Cyrillic)
blocks. Red-team purpose: defeat exact-string and token-level safety matching
while the text stays human- and model-legible.

Maps are built programmatically from Unicode block offsets (with the documented
"holes" where a styled letter lives in the Letterlike Symbols block instead), so
no fragile literal glyphs are pasted into source. Every map is injective and
case-preserving unless marked ``reversible: False``; decode reverses it.
"""
from __future__ import annotations


def _styled(upper0: int, lower0: int, digit0: int | None = None,
            exc: dict[str, int] | None = None) -> dict[str, str]:
    exc = exc or {}
    m: dict[str, str] = {}
    for i in range(26):
        U, L = chr(65 + i), chr(97 + i)
        m[U] = chr(exc[U]) if U in exc else chr(upper0 + i)
        m[L] = chr(exc[L]) if L in exc else chr(lower0 + i)
    if digit0 is not None:
        for i in range(10):
            m[chr(48 + i)] = chr(digit0 + i)
    return m


def _fullwidth() -> dict[str, str]:
    return {chr(c): chr(c + 0xFEE0) for c in range(0x21, 0x7F)}


def _circled() -> dict[str, str]:
    m = _styled(0x24B6, 0x24D0)              # A→Ⓐ, a→ⓐ
    m["0"] = chr(0x24EA)
    for i in range(1, 10):
        m[str(i)] = chr(0x2460 + i - 1)      # 1→①
    return m


# Small manual lookalike maps (partial coverage; unmapped chars pass through).
_GREEK = {"a": "α", "b": "β", "e": "ε", "i": "ι", "k": "κ", "n": "η", "o": "ο",
          "p": "ρ", "t": "τ", "u": "υ", "x": "χ", "y": "γ", "w": "ω",
          "A": "Α", "B": "Β", "E": "Ε", "H": "Η", "I": "Ι", "K": "Κ", "M": "Μ",
          "N": "Ν", "O": "Ο", "P": "Ρ", "T": "Τ", "X": "Χ", "Y": "Υ", "Z": "Ζ"}
_CYRILLIC = {"a": "а", "c": "с", "e": "е", "o": "о", "p": "р", "x": "х", "y": "у",
             "A": "А", "B": "В", "C": "С", "E": "Е", "H": "Н", "K": "К", "M": "М",
             "O": "О", "P": "Р", "T": "Т", "X": "Х", "Y": "У"}

_STYLE_MAPS: dict[str, dict[str, str]] = {
    "fullwidth":     _fullwidth(),
    "monospace":     _styled(0x1D670, 0x1D68A, 0x1D7F6),
    "bold":          _styled(0x1D400, 0x1D41A, 0x1D7CE),
    "italic":        _styled(0x1D434, 0x1D44E, exc={"h": 0x210E}),
    "bold_italic":   _styled(0x1D468, 0x1D482),
    "script":        _styled(
        0x1D49C, 0x1D4B6,
        exc={"B": 0x212C, "E": 0x2130, "F": 0x2131, "H": 0x210B, "I": 0x2110,
             "L": 0x2112, "M": 0x2133, "R": 0x211B,
             "e": 0x212F, "g": 0x210A, "o": 0x2134}),
    "fraktur":       _styled(
        0x1D504, 0x1D51E,
        exc={"C": 0x212D, "H": 0x210C, "I": 0x2111, "R": 0x211C, "Z": 0x2128}),
    "double_struck": _styled(
        0x1D538, 0x1D552, 0x1D7D8,
        exc={"C": 0x2102, "H": 0x210D, "N": 0x2115, "P": 0x2119, "Q": 0x211A,
             "R": 0x211D, "Z": 0x2124}),
    "circled":       _circled(),
    "greek":         _GREEK,
    "cyrillic":      _CYRILLIC,
}


def _make_pair(m: dict[str, str]):
    rev = {v: k for k, v in m.items()}

    def enc(t: str, _m=m) -> str:
        return "".join(_m.get(c, c) for c in t)

    def dec(t: str, _r=rev) -> str:
        return "".join(_r.get(c, c) for c in t)

    return enc, dec


# Combining-mark overlays (strikethrough / underline). Decode strips the mark.
def _overlay(mark: str):
    def enc(t: str) -> str:
        return "".join(c + mark for c in t)

    def dec(t: str) -> str:
        return t.replace(mark, "")

    return enc, dec


TRANSFORMS: dict[str, dict] = {}
for _name, _m in _STYLE_MAPS.items():
    _e, _d = _make_pair(_m)
    TRANSFORMS[_name] = {"encode": _e, "decode": _d, "category": "homoglyph", "reversible": True}

for _name, _mark in (("strikethrough", "̶"), ("underline", "̲")):
    _e, _d = _overlay(_mark)
    TRANSFORMS[_name] = {"encode": _e, "decode": _d, "category": "homoglyph", "reversible": True}
