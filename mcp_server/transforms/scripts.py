"""Cosmetic scripts, constructed alphabets, and word/case manglers.

These round out full P4RS3LT0NGV3 parity. Some are exact-reversible substitution
alphabets (braille, runes, roman numerals, the PUA constructed scripts); the
word/case manglers (leetspeak, pig-latin, case styles, emoji-speak, vaporwave)
are intentionally lossy and expose ``encode`` only (``decode`` is None), so the
universal decoder never tries to invert them. Constructed-script glyphs in the
Unicode Private Use Area render as tofu in most fonts — they exist for
robustness/tokenizer-perturbation testing, not readability.
"""
from __future__ import annotations

import random
import unicodedata

# ── Exact-reversible substitution alphabets ──────────────────────────────────

_BRAILLE = {
    "a": 0x2801, "b": 0x2803, "c": 0x2809, "d": 0x2819, "e": 0x2811, "f": 0x280B,
    "g": 0x281B, "h": 0x2813, "i": 0x280A, "j": 0x281A, "k": 0x2805, "l": 0x2807,
    "m": 0x280D, "n": 0x281D, "o": 0x2815, "p": 0x280F, "q": 0x281F, "r": 0x2817,
    "s": 0x280E, "t": 0x281E, "u": 0x2825, "v": 0x2827, "w": 0x283A, "x": 0x282D,
    "y": 0x283D, "z": 0x2835,
}


def _offset_map(base: int) -> dict[str, str]:
    # lowercase-only; _subst_pair lowercases on encode, so this stays injective
    # (a folded upper+lower map would make decode ambiguous).
    return {chr(97 + i): chr(base + i) for i in range(26)}


_SUBST_MAPS: dict[str, dict[str, str]] = {
    "braille": {k: chr(v) for k, v in _BRAILLE.items()},
    "runic":   {chr(97 + i): chr(0x16A0 + i) for i in range(26)},   # Elder Futhark block (approx.)
    "ogham":   {chr(97 + i): chr(0x1681 + i) for i in range(26)},   # Ogham block (approx.)
    "tengwar": _offset_map(0xE000),   # PUA — constructed
    "quenya":  _offset_map(0xE180),   # PUA — constructed
    "aurebesh": _offset_map(0xE080),  # PUA — constructed
    "dovahzul": _offset_map(0xE100),  # PUA — constructed
    "klingon": _offset_map(0xF8D0),   # PUA (pIqaD ConScript registry)
}


def _subst_pair(m: dict[str, str]):
    rev = {v: k for k, v in m.items()}

    def enc(t: str, _m=m) -> str:
        return "".join(_m.get(c.lower(), c) for c in t)

    def dec(t: str, _r=rev) -> str:
        return "".join(_r.get(c, c) for c in t)

    return enc, dec


# Roman numerals (operates on digit runs; letters pass through).
_ROMAN = [(1000, "M"), (900, "CM"), (500, "D"), (400, "CD"), (100, "C"),
          (90, "XC"), (50, "L"), (40, "XL"), (10, "X"), (9, "IX"),
          (5, "V"), (4, "IV"), (1, "I")]


def _int_to_roman(n: int) -> str:
    out = ""
    for val, sym in _ROMAN:
        while n >= val:
            out += sym
            n -= val
    return out


def _roman_to_int(s: str) -> int:
    vals = {"I": 1, "V": 5, "X": 10, "L": 50, "C": 100, "D": 500, "M": 1000}
    total, prev = 0, 0
    for ch in reversed(s):
        v = vals[ch]
        total += -v if v < prev else v
        prev = v
    return total


def _roman_encode(t: str) -> str:
    import re
    return re.sub(r"\d+", lambda m: _int_to_roman(int(m.group())) or "0", t)


def _roman_decode(t: str) -> str:
    import re
    return re.sub(r"[MDCLXVI]+", lambda m: str(_roman_to_int(m.group())), t)


# ── Zalgo (deterministic: seeded by the input) ───────────────────────────────
_COMBINING = [chr(0x0300 + i) for i in range(0, 0x30)]


def _zalgo_encode(t: str) -> str:
    rng = random.Random(hash(t) & 0xFFFFFFFF)
    out = []
    for c in t:
        out.append(c)
        if not unicodedata.combining(c) and c.strip():
            for _ in range(rng.randint(1, 3)):
                out.append(rng.choice(_COMBINING))
    return "".join(out)


def _zalgo_decode(t: str) -> str:
    return "".join(c for c in t if not unicodedata.combining(c))


# ── Lossy word / case manglers (encode-only) ─────────────────────────────────
_LEET = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7", "l": "1", "g": "9"}


def _leet(t: str) -> str:
    return "".join(_LEET.get(c.lower(), c) for c in t)


def _disemvowel(t: str) -> str:
    return "".join(c for c in t if c.lower() not in "aeiou")


def _pig_latin(t: str) -> str:
    out = []
    for word in t.split(" "):
        if not word or not word[0].isalpha():
            out.append(word)
            continue
        if word[0].lower() in "aeiou":
            out.append(word + "way")
        else:
            i = next((j for j, c in enumerate(word) if c.lower() in "aeiou"), len(word))
            out.append(word[i:] + word[:i] + "ay")
    return " ".join(out)


def _alternating(t: str) -> str:
    out, i = [], 0
    for c in t:
        if c.isalpha():
            out.append(c.upper() if i % 2 == 0 else c.lower())
            i += 1
        else:
            out.append(c)
    return "".join(out)


def _random_case(t: str) -> str:
    rng = random.Random(hash(t) & 0xFFFFFFFF)
    return "".join(rng.choice([c.upper(), c.lower()]) if c.isalpha() else c for c in t)


def _snake(t: str) -> str:
    return "_".join(t.split())


def _kebab(t: str) -> str:
    return "-".join(t.split())


def _camel(t: str) -> str:
    parts = t.split()
    return (parts[0].lower() + "".join(p.capitalize() for p in parts[1:])) if parts else t


def _vaporwave(t: str) -> str:
    return " ".join(chr(ord(c) + 0xFEE0) if 0x21 <= ord(c) <= 0x7E else c for c in t)


_EMOJI = {"a": "🅰️", "b": "🅱️", "o": "⭕", "i": "ℹ️", "s": "💲", "e": "📧", "x": "❌"}


def _emoji_speak(t: str) -> str:
    return "".join(_EMOJI.get(c.lower(), c) for c in t)


TRANSFORMS: dict[str, dict] = {}
for _name, _m in _SUBST_MAPS.items():
    _e, _d = _subst_pair(_m)
    TRANSFORMS[_name] = {"encode": _e, "decode": _d, "category": "script", "reversible": True}

TRANSFORMS.update({
    "roman_numerals": {"encode": _roman_encode, "decode": _roman_decode, "category": "script", "reversible": True},
    "zalgo":          {"encode": _zalgo_encode, "decode": _zalgo_decode, "category": "script", "reversible": True},
    "reverse":        {"encode": lambda t: t[::-1], "decode": lambda t: t[::-1], "category": "word", "reversible": True},
    "reverse_words":  {"encode": lambda t: " ".join(t.split(" ")[::-1]),
                       "decode": lambda t: " ".join(t.split(" ")[::-1]), "category": "word", "reversible": True},
    "leetspeak":      {"encode": _leet, "decode": None, "category": "word", "reversible": False},
    "disemvowel":     {"encode": _disemvowel, "decode": None, "category": "word", "reversible": False},
    "pig_latin":      {"encode": _pig_latin, "decode": None, "category": "word", "reversible": False},
    "alternating_case": {"encode": _alternating, "decode": None, "category": "case", "reversible": False},
    "random_case":    {"encode": _random_case, "decode": None, "category": "case", "reversible": False},
    "snake_case":     {"encode": _snake, "decode": None, "category": "case", "reversible": False},
    "kebab_case":     {"encode": _kebab, "decode": None, "category": "case", "reversible": False},
    "camel_case":     {"encode": _camel, "decode": None, "category": "case", "reversible": False},
    "upside_down":    {"encode": lambda t: "".join("ɐqɔpǝɟƃɥᴉɾʞlɯuodbɹsʇnʌʍxʎz"[ord(c) - 97] if "a" <= c <= "z" else c for c in t)[::-1],
                       "decode": None, "category": "word", "reversible": False},
    "vaporwave":      {"encode": _vaporwave, "decode": None, "category": "word", "reversible": False},
    "emoji_speak":    {"encode": _emoji_speak, "decode": None, "category": "word", "reversible": False},
})
