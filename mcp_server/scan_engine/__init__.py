"""
Scan Engine — context-lean stateful scan engine for small-context LLMs.

All tool responses pass through wrap() which:
1. Stores raw output as a retrievable artifact
2. Runs a tool-specific summarizer to extract facts
3. Enforces per-tool character budgets
4. Returns a canonical envelope (same shape for every tool)

Usage in tool wrappers:
    from mcp_server.scan_engine import wrap, retrieve_artifact

    raw = await run_scanner(...)
    return wrap("httpx", raw, context={"url": target})
"""
from mcp_server.scan_engine.envelope import wrap, Envelope
from mcp_server.scan_engine.artifacts import retrieve_artifact

__all__ = ["wrap", "retrieve_artifact", "Envelope"]
