"""Zero-width / invisible Unicode smuggling and steganography.

The highest-value evasion class for *indirect* prompt injection (LLM01) and MCP
intent subversion (MCP06): instructions that render as nothing to a human
reviewer and slip past naive text filters, yet whose bytes still reach the
tokenizer. Reimplemented from public technique descriptions (Unicode Tags block,
variation-selector steg) — no third-party code copied.
"""
from __future__ import annotations

# Zero-width bit encoding: two invisible code points stand for 0 and 1.
_ZW0 = "​"  # ZERO WIDTH SPACE
_ZW1 = "‌"  # ZERO WIDTH NON-JOINER


def zero_width_encode(t: str) -> str:
    bits = "".join(format(b, "08b") for b in t.encode("utf-8"))
    return "".join(_ZW1 if b == "1" else _ZW0 for b in bits)


def zero_width_decode(t: str) -> str:
    bits = "".join("1" if c == _ZW1 else "0" for c in t if c in (_ZW0, _ZW1))
    if not bits:
        return ""
    raw = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - len(bits) % 8, 8))
    return raw.decode("utf-8", "replace")


# Unicode Tags block (U+E0000–E007F): a byte-for-byte invisible mirror of ASCII.
_TAG_BASE = 0xE0000


def tags_encode(t: str) -> str:
    return "".join(chr(_TAG_BASE + ord(c)) if ord(c) < 0x80 else c for c in t)


def tags_decode(t: str) -> str:
    out = []
    for c in t:
        o = ord(c)
        if _TAG_BASE <= o <= _TAG_BASE + 0x7F:
            out.append(chr(o - _TAG_BASE))
        else:
            out.append(c)
    return "".join(out)


# Variation-selector steganography: hide arbitrary bytes as VS code points
# trailing a visible carrier glyph (e.g. an emoji).
_DEFAULT_CARRIER = "\U0001F600"  # 😀


def _byte_to_vs(b: int) -> str:
    return chr(0xFE00 + b) if b < 16 else chr(0xE0100 + (b - 16))


def _vs_to_byte(cp: int) -> int | None:
    if 0xFE00 <= cp <= 0xFE0F:
        return cp - 0xFE00
    if 0xE0100 <= cp <= 0xE01EF:
        return cp - 0xE0100 + 16
    return None


def steg_hide(text: str, carrier: str = _DEFAULT_CARRIER) -> str:
    return carrier + "".join(_byte_to_vs(b) for b in text.encode("utf-8"))


def steg_reveal(text: str) -> str:
    out = bytearray()
    for c in text:
        b = _vs_to_byte(ord(c))
        if b is not None:
            out.append(b)
    return out.decode("utf-8", "replace")


def contains_hidden(text: str) -> bool:
    """True if the string carries any zero-width / tag / variation-selector
    payload — used by the universal decoder to flag smuggled content."""
    for c in text:
        o = ord(c)
        if c in (_ZW0, _ZW1) or _TAG_BASE <= o <= _TAG_BASE + 0x7F or _vs_to_byte(o) is not None:
            return True
    return False


def extract_hidden(text: str) -> dict[str, str]:
    """Return every hidden channel found, keyed by technique."""
    found = {}
    if any(c in (_ZW0, _ZW1) for c in text):
        found["zero_width"] = zero_width_decode(text)
    if any(_TAG_BASE <= ord(c) <= _TAG_BASE + 0x7F for c in text):
        found["unicode_tags"] = tags_decode("".join(c for c in text if _TAG_BASE <= ord(c) <= _TAG_BASE + 0x7F))
    if any(_vs_to_byte(ord(c)) is not None for c in text):
        found["variation_selector"] = steg_reveal(text)
    return found


TRANSFORMS: dict[str, dict] = {
    "zero_width":         {"encode": zero_width_encode, "decode": zero_width_decode,
                           "category": "invisible", "reversible": True},
    "unicode_tags":       {"encode": tags_encode, "decode": tags_decode,
                           "category": "invisible", "reversible": True},
    "variation_selector": {"encode": lambda t: steg_hide(t), "decode": steg_reveal,
                           "category": "invisible", "reversible": True},
}
