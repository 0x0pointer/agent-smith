"""
Parser-first summarizers — extract structured facts from raw tool output.

Each summarizer returns a SummaryResult. If a tool has no dedicated summarizer,
the generic fallback is used (first N lines + tail).

Adding a new summarizer: define a function `_summarize_<tool>(raw, ctx) -> SummaryResult`
and register it in _SUMMARIZERS.

Split into a package for the <300-lines-per-file convention. This facade keeps
the public import surface identical: `from mcp_server.scan_engine.summarizers
import summarize` (and every previously importable name) still resolves here.
"""
from __future__ import annotations

from typing import Any

from ._common import SummaryResult
from .http import (
    _parse_httpx_json_line,
    _parse_httpx_text_line,
    _build_httpx_facts,
    _find_parsed_httpx_line,
    _build_httpx_summary,
    _summarize_httpx,
    _summarize_http_request,
    _extract_body_signals,
)
from .web import (
    _process_sqlmap_line,
    _parse_sqlmap_lines,
    _build_sqlmap_vulnerable_result,
    _summarize_kali_sqlmap,
    _parse_ffuf_json,
    _parse_ffuf_text,
    _summarize_ffuf,
    _STATIC_EXTENSIONS,
    _extract_url_params,
    _extract_dynamic_endpoints,
    _summarize_spider,
)
from .net import (
    _summarize_naabu,
    _summarize_subfinder,
    _parse_nuclei_line,
    _summarize_nuclei,
)
from .ai import (
    _section_after,
    _summarize_garak,
    _summarize_promptfoo,
    _PYRIT_SUCCESS_KEYS,
    _summarize_pyrit,
    _summarize_fuzzyai,
)
from .generic import _summarize_generic


def summarize(tool: str, raw: str, ctx: dict) -> SummaryResult:
    """Dispatch to tool-specific summarizer or fall back to generic."""
    fn = _SUMMARIZERS.get(tool, _summarize_generic)
    return fn(raw, ctx)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_SUMMARIZERS: dict[str, Any] = {
    "httpx": _summarize_httpx,
    "http_request": _summarize_http_request,
    "kali_sqlmap": _summarize_kali_sqlmap,
    "naabu": _summarize_naabu,
    "nmap": _summarize_naabu,  # similar JSON lines format
    "subfinder": _summarize_subfinder,
    "nuclei": _summarize_nuclei,
    "ffuf": _summarize_ffuf,
    "spider": _summarize_spider,
    "garak": _summarize_garak,
    "promptfoo": _summarize_promptfoo,
    "pyrit": _summarize_pyrit,
    "fuzzyai": _summarize_fuzzyai,
}
