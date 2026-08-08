"""Generic fallback summarizer — used when a tool has no dedicated summarizer."""
from __future__ import annotations

from ._common import SummaryResult


def _summarize_generic(raw: str, ctx: dict) -> SummaryResult:
    """Fallback: first 5 lines + line count."""
    result = SummaryResult()
    lines = raw.strip().splitlines()
    tool = ctx.get("_tool", "tool")

    result.summary = f"{tool} returned {len(lines)} line(s) of output"
    result.facts = [l.strip()[:300] for l in lines[:5] if l.strip()]
    if len(lines) > 5:
        result.facts.append(f"... and {len(lines) - 5} more line(s)")
    result.evidence = {"total_lines": len(lines), "total_chars": len(raw)}

    return result
