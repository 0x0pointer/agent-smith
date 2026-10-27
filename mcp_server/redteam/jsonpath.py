"""Minimal JSONPath evaluator — pure-Python, dependency-free.

The structured success oracle (oracles.structured_verdict) needs to ask a
present/absent question of a JSON reply — "is there a record whose original_name
is 'X'?" — so an integrity red-team can assert an injected/dropped/falsified
field. A full JSONPath library is a pip dependency the engine deliberately
avoids (see the transform()/redteam() "no pip" contract), so this implements the
exact subset those oracles use:

    $                      root (optional; an expr may start at a name or bracket)
    .name  /  ['name']     child member            ($.record, $['a-b'])
    [n] / [-n]             array index              ($.items[0], $.items[-1])
    [*]  /  .*             wildcard (all members of an object or array)
    ..name                 recursive descent        ($..original_name)
    [?(<predicate>)]       filter over array elements (or a single object)

Predicate grammar (inside `?(...)`):
    @            the current element          (@ == 'x')
    @.a.b        a nested field               (@.record.id == 5)
    existence    @.field                      (field present and not null)
    comparisons  == != < <= > >=              (@.score >= 0.9)
    booleans     && ||                        (@.a=='x' && @.b)   (left-to-right)
Literals: 'str', "str", 123, 1.5, true, false, null.

Public API:
    find(data, expr)    -> list of matching values (data is already-parsed JSON)
    matches(data, expr) -> bool (len(find) > 0)

Unsupported syntax raises JsonPathError so a bad oracle predicate fails loudly
(a structured oracle that silently matches nothing would be a false "clean").
"""
from __future__ import annotations

_MISSING = object()


class JsonPathError(ValueError):
    """Raised for an unparseable or unsupported JSONPath expression."""


# ── tokenizer: expression string -> ordered list of path segments ───────────────

def _read_name(expr: str, i: int) -> tuple[str, int]:
    """Read a bare member name starting at i, up to the next . [ or ] ."""
    start = i
    while i < len(expr) and expr[i] not in ".[]":
        i += 1
    return expr[start:i], i


def _find_matching_bracket(expr: str, i: int) -> int:
    """Index of the ] that closes the [ at i, honouring quotes and nesting."""
    depth, quote = 0, ""
    j = i
    while j < len(expr):
        c = expr[j]
        if quote:
            if c == quote:
                quote = ""
        elif c in "'\"":
            quote = c
        elif c == "[":
            depth += 1
        elif c == "]":
            depth -= 1
            if depth == 0:
                return j
        j += 1
    raise JsonPathError(f"unbalanced '[' in {expr!r}")


def _parse_bracket(inner: str):
    """Parse the text inside [...] into a segment."""
    s = inner.strip()
    if s == "*":
        return ("wild",)
    if s.startswith("?"):
        pred = s[1:].strip()
        if pred.startswith("(") and pred.endswith(")"):
            pred = pred[1:-1]
        return ("filter", pred.strip())
    if s[:1] in "'\"" and s[-1:] == s[:1] and len(s) >= 2:
        return ("child", s[1:-1])
    try:
        return ("index", int(s))
    except ValueError as e:
        raise JsonPathError(f"bad bracket selector [{inner}]") from e


def _tokenize(expr: str) -> list[tuple]:
    expr = expr.strip()
    if not expr:
        raise JsonPathError("empty JSONPath expression")
    i = 1 if expr[0] == "$" else 0
    segs: list[tuple] = []
    n = len(expr)
    while i < n:
        c = expr[i]
        if c == ".":
            if i + 1 < n and expr[i + 1] == ".":        # '..' recursive descent
                segs.append(("recurse",))
                i += 2
                if i < n and expr[i] == "*":
                    segs.append(("wild",))
                    i += 1
                elif i < n and expr[i] not in ".[":
                    name, i = _read_name(expr, i)
                    if name:
                        segs.append(("child", name))
                continue
            i += 1
            if i < n and expr[i] == "*":                # '.*' wildcard
                segs.append(("wild",))
                i += 1
                continue
            name, i = _read_name(expr, i)
            if not name:
                raise JsonPathError(f"expected a name after '.' in {expr!r}")
            segs.append(("child", name))
        elif c == "[":
            j = _find_matching_bracket(expr, i)
            segs.append(_parse_bracket(expr[i + 1:j]))
            i = j + 1
        else:                                            # bare leading name
            name, i = _read_name(expr, i)
            if not name:
                raise JsonPathError(f"unexpected char {c!r} in {expr!r}")
            segs.append(("child", name))
    return segs


# ── predicate evaluation (the [?(...)] filter body) ─────────────────────────────

def _split_top(s: str, sep: str) -> list[str]:
    """Split on `sep` at top level only (not inside quotes or brackets)."""
    out, depth, quote, start, i = [], 0, "", 0, 0
    while i < len(s):
        c = s[i]
        if quote:
            if c == quote:
                quote = ""
        elif c in "'\"":
            quote = c
        elif c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif depth == 0 and s.startswith(sep, i):
            out.append(s[start:i])
            i += len(sep)
            start = i
            continue
        i += 1
    out.append(s[start:])
    return out


_OPS = ("==", "!=", "<=", ">=", "<", ">")


def _split_comparison(atom: str):
    """Return (op, lhs, rhs) or (None, atom, None) for an existence atom."""
    depth, quote = 0, ""
    i = 0
    while i < len(atom):
        c = atom[i]
        if quote:
            if c == quote:
                quote = ""
            i += 1
            continue
        if c in "'\"":
            quote = c
        elif c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif depth == 0:
            for op in _OPS:
                if atom.startswith(op, i):
                    return op, atom[:i], atom[i + len(op):]
        i += 1
    return None, atom, None


def _resolve_at(expr: str, item):
    """Resolve an @-rooted path (@, @.a, @.a.b) against `item`."""
    expr = expr.strip()
    if not expr.startswith("@"):
        raise JsonPathError(f"predicate operand must start with '@': {expr!r}")
    cur = item
    for part in expr[1:].split("."):
        if part == "":
            continue
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return _MISSING
    return cur


def _parse_literal(s: str):
    s = s.strip()
    if len(s) >= 2 and s[0] in "'\"" and s[-1] == s[0]:
        return s[1:-1]
    low = s.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if low in ("null", "none"):
        return None
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        return s


def _compare(op: str, a, b) -> bool:
    if op == "==":
        return a == b or str(a) == str(b)
    if op == "!=":
        return not (a == b or str(a) == str(b))
    try:
        fa, fb = float(a), float(b)
    except (TypeError, ValueError):
        return False
    return {"<": fa < fb, "<=": fa <= fb, ">": fa > fb, ">=": fa >= fb}[op]


def _eval_atom(atom: str, item) -> bool:
    op, lhs, rhs = _split_comparison(atom)
    left = _resolve_at(lhs, item)
    if op is None:                       # existence: present and not null
        return left is not _MISSING and left is not None
    if left is _MISSING:
        return op == "!="                # a missing field is != any concrete value
    return _compare(op, left, _parse_literal(rhs))


def _eval_predicate(pred: str, item) -> bool:
    for or_part in _split_top(pred, "||"):
        atoms = [a for a in _split_top(or_part, "&&") if a.strip()]
        if atoms and all(_eval_atom(a, item) for a in atoms):
            return True
    return False


# ── evaluation ──────────────────────────────────────────────────────────────────

def _descendants(node) -> list:
    """`node` and every value nested inside it (for recursive descent)."""
    out, stack = [node], [node]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            vals = list(cur.values())
        elif isinstance(cur, list):
            vals = list(cur)
        else:
            continue
        out.extend(vals)
        stack.extend(vals)
    return out


def _apply(seg: tuple, nodes: list) -> list:
    kind = seg[0]
    if kind == "recurse":
        out = []
        for node in nodes:
            out.extend(_descendants(node))
        return out
    out = []
    for node in nodes:
        if kind == "child":
            if isinstance(node, dict) and seg[1] in node:
                out.append(node[seg[1]])
        elif kind == "index":
            if isinstance(node, list) and -len(node) <= seg[1] < len(node):
                out.append(node[seg[1]])
        elif kind == "wild":
            if isinstance(node, dict):
                out.extend(node.values())
            elif isinstance(node, list):
                out.extend(node)
        elif kind == "filter":
            items = node if isinstance(node, list) else ([node] if isinstance(node, dict) else [])
            out.extend(it for it in items if _eval_predicate(seg[1], it))
    return out


def find(data, expr: str) -> list:
    """Every value in `data` (already-parsed JSON) matching JSONPath `expr`."""
    nodes = [data]
    for seg in _tokenize(expr):
        nodes = _apply(seg, nodes)
    return nodes


def matches(data, expr: str) -> bool:
    """True if `expr` selects at least one value in `data`."""
    return len(find(data, expr)) > 0
