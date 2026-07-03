"""
P6 — Fire-and-forget quick_log entries built from tool context + summarizer result.
"""
from __future__ import annotations

from typing import Any

from mcp_server.scan_engine.envelope.auth_detect import _is_auth_attempt, _is_zero_status


def _build_quick_log_entry(
    tool: str, target: str, summarizer_summary: str, result: Any, ctx: dict | None = None,
) -> dict:
    """Build and return the quick_log entry dict for a tool call.

    Handles the spider vs TOOL branching, status_code extraction, and error
    detection. Extracted from _quick_log_tool to reduce cognitive complexity.
    """
    import re as _re
    if tool == "spider":
        m = _re.search(r'(\d+)\s{1,3}unique\s{1,3}endpoint', summarizer_summary, _re.IGNORECASE)
        return {
            "type": "SPIDER",
            "target": target,
            "endpoints_found": int(m.group(1)) if m else 0,
        }

    entry: dict = {"type": "TOOL", "name": tool, "target": target}
    _enrich_http_request_entry(entry, tool, result, ctx)
    _mark_tool_error(entry, tool, result)
    return entry


def _enrich_http_request_entry(
    entry: dict, tool: str, result: Any, ctx: dict | None
) -> None:
    """Add status_code and auth_attempt fields to http_request log entries."""
    if result is None or tool != "http_request":
        return
    ev = result.evidence or {}
    sc = ev.get("status", 0)
    if sc:
        entry["status_code"] = int(sc)
    if ctx and _is_auth_attempt(ctx):
        entry["auth_attempt"] = True


def _mark_tool_error(entry: dict, tool: str, result: Any) -> None:
    """Set entry["error"] = True when the tool call itself produced no real response.

    Only two narrow signals qualify (see _build_quick_log_entry for rationale).
    """
    if result is None:
        return
    ev = result.evidence or {}
    if ev.get("error") or (tool == "http_request" and _is_zero_status(ev.get("status"))):
        entry["error"] = True


def _quick_log_tool(tool: str, ctx: dict, summarizer_summary: str, result: Any = None) -> None:
    """Fire-and-forget quick_log entry. Called from within an async tool handler
    so asyncio.get_running_loop() is always available.

    Uses the summarizer's summary (before QA injection) so the log reflects
    what the tool actually found, not the alert state.

    status_code and error fields are extracted from result.evidence when available
    so the QA daemon can detect auth failures, unreachable targets, and tool failures.
    """
    import asyncio
    try:
        from core.quick_log import quick_log as _qlog
        target = ctx.get("url", ctx.get("host", ctx.get("domain", ctx.get("path", ""))))
        entry = _build_quick_log_entry(tool, target, summarizer_summary, result, ctx)
        loop = asyncio.get_running_loop()
        loop.create_task(_qlog.append(entry))
    except Exception:
        pass  # quick_log failures must never affect tool dispatch
