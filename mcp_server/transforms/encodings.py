"""Base encodings, classic ciphers, and radio/signalling codes.

Clean-room reimplementation of the *techniques* popularised by
Arcanum-Sec/P4RS3LT0NGV3 (that project is AGPL-3.0; none of its code or lookup
tables are copied here — these are all public-domain encodings implemented from
their specifications). Every transform is a self-contained pair of pure
functions following the registry contract:

    {name: {"encode": fn(str)->str, "decode": fn(str)->str|None,
            "category": str, "reversible": bool}}

Red-team purpose: obfuscate a jailbreak / prompt-injection payload into a form
a capable model still understands but an input filter / safety classifier no
longer pattern-matches, then (optionally) decode the model's encoded reply.
"""
from __future__ import annotations

import base64 as _b64
import binascii
import codecs
import html
import string
import urllib.parse

# ── Base / numeric encodings ────────────────────────────────────────────────


def _b64_encode(t: str) -> str:
    return _b64.b64encode(t.encode("utf-8")).decode("ascii")


def _b64_decode(t: str) -> str:
    return _b64.b64decode(t.strip().encode("ascii")).decode("utf-8", "replace")


def _b64url_encode(t: str) -> str:
    return _b64.urlsafe_b64encode(t.encode("utf-8")).decode("ascii").rstrip("=")


def _b64url_decode(t: str) -> str:
    s = t.strip()
    s += "=" * (-len(s) % 4)
    return _b64.urlsafe_b64decode(s.encode("ascii")).decode("utf-8", "replace")


def _b32_encode(t: str) -> str:
    return _b64.b32encode(t.encode("utf-8")).decode("ascii")


def _b32_decode(t: str) -> str:
    return _b64.b32decode(t.strip().encode("ascii")).decode("utf-8", "replace")


def _b85_encode(t: str) -> str:
    return _b64.a85encode(t.encode("utf-8")).decode("ascii")


def _b85_decode(t: str) -> str:
    return _b64.a85decode(t.strip().encode("ascii")).decode("utf-8", "replace")


def _hex_encode(t: str) -> str:
    return t.encode("utf-8").hex(" ")


def _hex_decode(t: str) -> str:
    cleaned = t.replace(" ", "").replace("\n", "").strip()
    return bytes.fromhex(cleaned).decode("utf-8", "replace")


def _binary_encode(t: str) -> str:
    return " ".join(format(b, "08b") for b in t.encode("utf-8"))


def _binary_decode(t: str) -> str:
    bits = t.split()
    return bytes(int(b, 2) for b in bits).decode("utf-8", "replace")


# base58 (Bitcoin alphabet) / base62 — implemented from spec.
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B62 = string.digits + string.ascii_uppercase + string.ascii_lowercase


def _base_n_encode(t: str, alphabet: str) -> str:
    raw = t.encode("utf-8")
    n = int.from_bytes(raw, "big") if raw else 0
    base = len(alphabet)
    out = ""
    while n > 0:
        n, rem = divmod(n, base)
        out = alphabet[rem] + out
    pad = len(raw) - len(raw.lstrip(b"\x00"))
    return alphabet[0] * pad + (out or alphabet[0])


def _base_n_decode(t: str, alphabet: str) -> str:
    base = len(alphabet)
    s = t.strip()
    n = 0
    for ch in s:
        n = n * base + alphabet.index(ch)
    pad = len(s) - len(s.lstrip(alphabet[0]))
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return (b"\x00" * pad + raw).decode("utf-8", "replace")


def _b58_encode(t: str) -> str:
    return _base_n_encode(t, _B58)


def _b58_decode(t: str) -> str:
    return _base_n_decode(t, _B58)


def _b62_encode(t: str) -> str:
    return _base_n_encode(t, _B62)


def _b62_decode(t: str) -> str:
    return _base_n_decode(t, _B62)


# base45 (RFC 9285)
_B45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"


def _b45_encode(t: str) -> str:
    raw = t.encode("utf-8")
    out = []
    for i in range(0, len(raw), 2):
        chunk = raw[i:i + 2]
        if len(chunk) == 2:
            n = chunk[0] * 256 + chunk[1]
            c, n = n % 45, n // 45
            d, e = n % 45, n // 45
            out += [_B45[c], _B45[d], _B45[e]]
        else:
            n = chunk[0]
            c, d = n % 45, n // 45
            out += [_B45[c], _B45[d]]
    return "".join(out)


def _b45_decode(t: str) -> str:
    s = t.strip()
    raw = bytearray()
    for i in range(0, len(s), 3):
        group = s[i:i + 3]
        if len(group) == 3:
            n = _B45.index(group[0]) + _B45.index(group[1]) * 45 + _B45.index(group[2]) * 45 * 45
            raw += bytes([n // 256, n % 256])
        elif len(group) == 2:
            n = _B45.index(group[0]) + _B45.index(group[1]) * 45
            raw += bytes([n])
    return raw.decode("utf-8", "replace")


def _a1z26_encode(t: str) -> str:
    words = []
    for word in t.split(" "):
        toks = []
        for ch in word:
            if ch.isalpha():
                toks.append(str(ord(ch.lower()) - 96))
            else:
                toks.append(ch)
        words.append("-".join(toks))
    return " ".join(words)


def _a1z26_decode(t: str) -> str:
    words = []
    for word in t.split(" "):
        chars = []
        for tok in word.split("-"):
            if tok.isdigit() and 1 <= int(tok) <= 26:
                chars.append(chr(int(tok) + 96))
            else:
                chars.append(tok)
        words.append("".join(chars))
    return " ".join(words)


def _url_encode(t: str) -> str:
    return urllib.parse.quote(t, safe="")


def _url_decode(t: str) -> str:
    return urllib.parse.unquote(t)


def _html_encode(t: str) -> str:
    return "".join(f"&#{ord(c)};" for c in t)


def _html_decode(t: str) -> str:
    return html.unescape(t)


# ── Classic ciphers ─────────────────────────────────────────────────────────


def _shift_alpha(t: str, n: int) -> str:
    out = []
    for ch in t:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + n) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + n) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def _caesar_encode(t: str) -> str:
    return _shift_alpha(t, 3)


def _caesar_decode(t: str) -> str:
    return _shift_alpha(t, -3)


def _rot13(t: str) -> str:
    return codecs.encode(t, "rot_13")


def _rot5(t: str) -> str:
    return "".join(str((int(c) + 5) % 10) if c.isdigit() else c for c in t)


def _rot18(t: str) -> str:
    return _rot5(_rot13(t))


def _rot47(t: str) -> str:
    out = []
    for ch in t:
        o = ord(ch)
        if 33 <= o <= 126:
            out.append(chr(33 + (o - 33 + 47) % 94))
        else:
            out.append(ch)
    return "".join(out)


def _atbash(t: str) -> str:
    out = []
    for ch in t:
        if "a" <= ch <= "z":
            out.append(chr(219 - ord(ch)))       # atbash reflects a<->z around code point 219
        elif "A" <= ch <= "Z":
            out.append(chr(155 - ord(ch)))       # atbash reflects A<->Z around code point 155
        else:
            out.append(ch)
    return "".join(out)


def _affine(t: str, a: int, b: int) -> str:
    out = []
    for ch in t:
        if ch.isalpha():
            base = 97 if ch.islower() else 65
            out.append(chr((a * (ord(ch) - base) + b) % 26 + base))
        else:
            out.append(ch)
    return "".join(out)


def _affine_encode(t: str) -> str:
    return _affine(t, 5, 8)


def _affine_decode(t: str) -> str:
    a_inv = pow(5, -1, 26)
    out = []
    for ch in t:
        if ch.isalpha():
            base = 97 if ch.islower() else 65
            out.append(chr((a_inv * (ord(ch) - base - 8)) % 26 + base))
        else:
            out.append(ch)
    return "".join(out)


_VIG_KEY = "KEY"


def _vigenere(t: str, decrypt: bool = False) -> str:
    out, ki = [], 0
    for ch in t:
        if ch.isalpha():
            base = 97 if ch.islower() else 65
            k = ord(_VIG_KEY[ki % len(_VIG_KEY)].upper()) - 65
            if decrypt:
                k = -k
            out.append(chr((ord(ch) - base + k) % 26 + base))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def _vigenere_encode(t: str) -> str:
    return _vigenere(t, decrypt=False)


def _vigenere_decode(t: str) -> str:
    return _vigenere(t, decrypt=True)


# Baconian — 26 distinct 5-bit A/B codes.
_BACON = {chr(97 + i): format(i, "05b").replace("0", "A").replace("1", "B") for i in range(26)}
_BACON_REV = {v: k for k, v in _BACON.items()}


def _bacon_encode(t: str) -> str:
    words = []
    for word in t.lower().split(" "):
        words.append(" ".join(_BACON.get(c, c) for c in word))
    return "  ".join(words)


def _bacon_decode(t: str) -> str:
    words = []
    for word in t.split("  "):
        words.append("".join(_BACON_REV.get(tok, tok) for tok in word.split(" ")))
    return " ".join(words)


def _railfence_encode(t: str, rails: int = 3) -> str:
    if rails < 2:
        return t
    fence = [[] for _ in range(rails)]
    r, step = 0, 1
    for ch in t:
        fence[r].append(ch)
        if r == 0:
            step = 1
        elif r == rails - 1:
            step = -1
        r += step
    return "".join("".join(row) for row in fence)


def _railfence_decode(t: str, rails: int = 3) -> str:
    if rails < 2:
        return t
    n = len(t)
    pattern, r, step = [], 0, 1
    for _ in range(n):
        pattern.append(r)
        if r == 0:
            step = 1
        elif r == rails - 1:
            step = -1
        r += step
    counts = [pattern.count(i) for i in range(rails)]
    rows, idx = [], 0
    for c in counts:
        rows.append(list(t[idx:idx + c]))
        idx += c
    pos = [0] * rails
    out = []
    for r in pattern:
        out.append(rows[r][pos[r]])
        pos[r] += 1
    return "".join(out)


# ── Radio / signalling codes ────────────────────────────────────────────────

_MORSE = {
    "a": ".-", "b": "-...", "c": "-.-.", "d": "-..", "e": ".", "f": "..-.",
    "g": "--.", "h": "....", "i": "..", "j": ".---", "k": "-.-", "l": ".-..",
    "m": "--", "n": "-.", "o": "---", "p": ".--.", "q": "--.-", "r": ".-.",
    "s": "...", "t": "-", "u": "..-", "v": "...-", "w": ".--", "x": "-..-",
    "y": "-.--", "z": "--..", "0": "-----", "1": ".----", "2": "..---",
    "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...",
    "8": "---..", "9": "----.", ".": ".-.-.-", ",": "--..--", "?": "..--..",
    "!": "-.-.--", "/": "-..-.", "'": ".----.", "@": ".--.-.",
}
_MORSE_REV = {v: k for k, v in _MORSE.items()}


def _morse_encode(t: str) -> str:
    words = []
    for word in t.lower().split(" "):
        words.append(" ".join(_MORSE.get(c, c) for c in word))
    return " / ".join(words)


def _morse_decode(t: str) -> str:
    words = []
    for word in t.split(" / "):
        words.append("".join(_MORSE_REV.get(tok, tok) for tok in word.split(" ")))
    return " ".join(words)


_NATO = {
    "a": "Alfa", "b": "Bravo", "c": "Charlie", "d": "Delta", "e": "Echo",
    "f": "Foxtrot", "g": "Golf", "h": "Hotel", "i": "India", "j": "Juliett",
    "k": "Kilo", "l": "Lima", "m": "Mike", "n": "November", "o": "Oscar",
    "p": "Papa", "q": "Quebec", "r": "Romeo", "s": "Sierra", "t": "Tango",
    "u": "Uniform", "v": "Victor", "w": "Whiskey", "x": "Xray", "y": "Yankee",
    "z": "Zulu", "0": "Zero", "1": "One", "2": "Two", "3": "Three", "4": "Four",
    "5": "Five", "6": "Six", "7": "Seven", "8": "Eight", "9": "Nine",
}
_NATO_REV = {v.lower(): k for k, v in _NATO.items()}


def _nato_encode(t: str) -> str:
    return " ".join(_NATO.get(c, c) for c in t.lower() if c != " ")


def _nato_decode(t: str) -> str:
    return "".join(_NATO_REV.get(tok.lower(), tok) for tok in t.split(" "))


# Tap code (Polybius square, C shares with K).
_TAP_SQUARE = "abcdefghiklmnopqrstuvwxyz"  # no 'j'


def _tap_encode(t: str) -> str:
    out = []
    for ch in t.lower():
        c = "k" if ch == "j" else ch
        if c in _TAP_SQUARE:
            i = _TAP_SQUARE.index(c)
            out.append("." * (i // 5 + 1) + " " + "." * (i % 5 + 1))
        elif ch == " ":
            out.append("/")
    return "  ".join(out)


def _tap_decode(t: str) -> str:
    out = []
    for grp in t.split("  "):
        if grp == "/":
            out.append(" ")
            continue
        parts = grp.split(" ")
        if len(parts) == 2 and all(p and set(p) == {"."} for p in parts):
            row, col = len(parts[0]) - 1, len(parts[1]) - 1
            out.append(_TAP_SQUARE[row * 5 + col])
    return "".join(out)


TRANSFORMS: dict[str, dict] = {
    "base64":       {"encode": _b64_encode,   "decode": _b64_decode,   "category": "base", "reversible": True},
    "base64url":    {"encode": _b64url_encode, "decode": _b64url_decode, "category": "base", "reversible": True},
    "base32":       {"encode": _b32_encode,   "decode": _b32_decode,   "category": "base", "reversible": True},
    "base85":       {"encode": _b85_encode,   "decode": _b85_decode,   "category": "base", "reversible": True},
    "base58":       {"encode": _b58_encode,   "decode": _b58_decode,   "category": "base", "reversible": True},
    "base62":       {"encode": _b62_encode,   "decode": _b62_decode,   "category": "base", "reversible": True},
    "base45":       {"encode": _b45_encode,   "decode": _b45_decode,   "category": "base", "reversible": True},
    "hex":          {"encode": _hex_encode,   "decode": _hex_decode,   "category": "base", "reversible": True},
    "binary":       {"encode": _binary_encode, "decode": _binary_decode, "category": "base", "reversible": True},
    "a1z26":        {"encode": _a1z26_encode, "decode": _a1z26_decode, "category": "base", "reversible": True},
    "url":          {"encode": _url_encode,   "decode": _url_decode,   "category": "base", "reversible": True},
    "html_entities": {"encode": _html_encode, "decode": _html_decode,  "category": "base", "reversible": True},
    "caesar":       {"encode": _caesar_encode, "decode": _caesar_decode, "category": "cipher", "reversible": True},
    "rot13":        {"encode": _rot13,        "decode": _rot13,        "category": "cipher", "reversible": True},
    "rot5":         {"encode": _rot5,         "decode": _rot5,         "category": "cipher", "reversible": True},
    "rot18":        {"encode": _rot18,        "decode": _rot18,        "category": "cipher", "reversible": True},
    "rot47":        {"encode": _rot47,        "decode": _rot47,        "category": "cipher", "reversible": True},
    "atbash":       {"encode": _atbash,       "decode": _atbash,       "category": "cipher", "reversible": True},
    "affine":       {"encode": _affine_encode, "decode": _affine_decode, "category": "cipher", "reversible": True},
    "vigenere":     {"encode": _vigenere_encode, "decode": _vigenere_decode, "category": "cipher", "reversible": True},
    "baconian":     {"encode": _bacon_encode, "decode": _bacon_decode, "category": "cipher", "reversible": True},
    "railfence":    {"encode": _railfence_encode, "decode": _railfence_decode, "category": "cipher", "reversible": True},
    "tapcode":      {"encode": _tap_encode,   "decode": _tap_decode,   "category": "cipher", "reversible": True},
    "morse":        {"encode": _morse_encode, "decode": _morse_decode, "category": "radio", "reversible": True},
    "nato":         {"encode": _nato_encode,  "decode": _nato_decode,  "category": "radio", "reversible": True},
}
