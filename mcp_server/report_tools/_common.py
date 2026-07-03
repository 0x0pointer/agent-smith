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
    '"': "#34;", "(": "#40;", ")": "#41;", "|": "#124;",
    "[": "#91;", "]": "#93;", "{": "#123;", "}": "#125;",
}


def _mermaid_label(text: str) -> str:
    """Escape characters that break a Mermaid node/edge label."""
    out = str(text)
    for ch, ent in _MERMAID_ESCAPES.items():
        out = out.replace(ch, ent)
    return out


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
