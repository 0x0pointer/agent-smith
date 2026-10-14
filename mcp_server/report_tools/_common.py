"""
Shared module state and tiny helpers for the report_tools package.

Everything the individual action groups (findings / gates / diagrams / coverage)
need in common lives here so the groups don't import each other for plumbing.
"""
import asyncio
import re
from typing import Any

from core import findings as findings_store
from core import logger as log
from core import session as scan_session
# Gate-firing keyword sets — single source of truth in core.gate_keywords
# (kept separate from severity-scoring vocab in core.adjunction.rubric).
# Aliased to the historical _-prefixed names used throughout this module.
from core.gate_keywords import (
    AUTH_KEYWORDS as _AUTH_KEYWORDS,
    AUTH_WEAKNESS_KEYWORDS as _AUTH_WEAKNESS_KEYWORDS,
    CLOUD_KEYWORDS as _CLOUD_KEYWORDS,
    CLOUD_METADATA_PREFIX as _CLOUD_METADATA_PREFIX,
    GATE_BENIGN_MARKERS as _GATE_BENIGN_MARKERS,
    INTERNAL_NET_KEYWORDS as _INTERNAL_NET_KEYWORDS,
    K8S_KEYWORDS as _K8S_KEYWORDS,
    RCE_KEYWORDS as _RCE_KEYWORDS,
    RCE_EQUIVALENT_MARKERS as _RCE_EQUIVALENT_MARKERS,
    SPECULATION_MARKERS as _SPECULATION_MARKERS,
)

_background_tasks: set[asyncio.Task] = set()  # keeps fire-and-forget tasks alive


# ── Finding hygiene: trace validation + cross-run dedup ─────────────────────────
_WS_RE = re.compile(r"\s+")


def _norm_text(s: Any) -> str:
    """Lowercase, strip, collapse internal whitespace — for stable comparison."""
    return _WS_RE.sub(" ", str(s or "").strip().lower())


def _norm_target(s: Any) -> str:
    """Normalise a target so http://x/ and HTTP://X compare equal."""
    return _norm_text(s).rstrip("/")


def _safe(fid: str) -> str:
    """Make a finding id safe for a Mermaid node identifier."""
    return "".join(c if c.isalnum() else "_" for c in str(fid))


# Characters that break a Mermaid label. Unquoted edge labels (-->|...|) are the
# worst offenders: '(' is parsed as a node-shape opener (the "got 'PS'" error)
# and '|' closes the label early — both occur in MITRE technique names like
# "T1078 - Valid Accounts (Privileged Account Creation…)". HTML entity codes
# render as the literal character in every Mermaid theme, so the text is unchanged.
_MERMAID_ESCAPES = {
    # ';' first — every other entity ends in ';', so escaping ';' afterward would corrupt them.
    ";": "#59;",
    '"': "#34;", "(": "#40;", ")": "#41;", "|": "#124;",
    "[": "#91;", "]": "#93;", "{": "#123;", "}": "#125;",
    "<": "#60;", ">": "#62;",
}


def _mermaid_label(text: str) -> str:
    """Escape characters that break a Mermaid node/edge label."""
    out = str(text)
    for ch, ent in _MERMAID_ESCAPES.items():
        out = out.replace(ch, ent)
    return out


# Edge-label region: `-->|text|`, `--|text|`, `-.->|text|`, etc. Pipes do NOT nest, so
# this is unambiguous and safe to rewrite (unlike node shapes [(..)] / (( )) which DO
# nest and can't be split by a flat regex without corrupting the shape).
_MERMAID_EDGE_LABEL_RE = re.compile(r"\|([^|\n]*)\|")


def _escape_edge_label_interior(interior: str) -> str:
    """Entity-escape an edge-label interior so it renders literally in any Mermaid
    version. Strips one layer of surrounding quotes first (agent diagrams quote
    inconsistently)."""
    s = interior.strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        s = s[1:-1]
    return _mermaid_label(s)


def _sanitize_mermaid(src: str) -> str:
    """Make AGENT-AUTHORED Mermaid (report(action='diagram')) robust to the single most
    common breakage we see in practice: unescaped special chars inside EDGE labels —
    e.g. `-->|T1078 - Valid Accounts (Privileged Account Creation)|`, where the raw `(`
    makes Mermaid's parser read a node-shape and throw 'got PS'. Only edge-label interiors
    (`|...|`) are rewritten — a flat transform there is unambiguous and cannot corrupt node
    shapes. Node-label edge cases are left for the client-side per-diagram render fallback
    to degrade gracefully, rather than risk mangling a valid [(cylinder)] / ((circle)).

    Chain diagrams built by _chain_mermaid already escape their labels via _mermaid_label;
    this covers the diagrams the model writes by hand. Idempotent on already-clean input
    (a label with no special chars is returned unchanged). Fail-soft: returns src on any
    error so a sanitiser bug can never drop a diagram."""
    if not src:
        return src
    try:
        return _MERMAID_EDGE_LABEL_RE.sub(
            lambda m: "|" + _escape_edge_label_interior(m.group(1)) + "|", src)
    except Exception:
        return src


def _safe_port(value, default: int) -> int:
    """Coerce a user-supplied port value to a valid int in the IANA range.

    Defense against SonarQube python:S5145 (log injection): the result is a
    sanitized int that's safe to interpolate into log lines. Invalid input
    (non-int, non-numeric string, negative, > 65535) falls back to the
    default — we never log the raw value back to the operator, which would
    let a malicious tool-call payload write fake log entries by embedding
    newlines.
    """
    try:
        v = int(value)
    except (TypeError, ValueError):
        return default
    if 0 < v < 65536:
        return v
    return default
