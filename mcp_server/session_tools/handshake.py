"""Client-handshake detection helpers (session.start locks the MCP client)."""
from core import logger as log
from core import session as scan_session


def _client_from_ctx(ctx) -> str | None:
    """Map the MCP ``initialize`` handshake's ``clientInfo.name`` to a canonical
    Smith client (claude | opencode | codex). Per-connection and unambiguous —
    unlike TCP/PID scanning it isn't confused by several clients sharing the SSE
    server. Returns None when ctx/clientInfo is absent or unrecognized."""
    try:
        name = (ctx.session.client_params.clientInfo.name or "").lower()
    except Exception:
        return None
    for key in ("opencode", "codex", "claude"):
        if key in name:
            return key
    return None


def _record_handshake_client(ctx) -> None:
    """On session.start(), lock the session to the client the MCP handshake
    names — authoritative, overriding the best-effort TCP/PID detection that
    mislabels the scan when a dev Claude Code session shares the SSE server with
    the opencode scanner. No-op when the handshake doesn't identify a client."""
    name = _client_from_ctx(ctx)
    if not name:
        return
    try:
        from core.session.process_detect import _detect_smith_caller
        caller = _detect_smith_caller(prefer_client=name)
        scan_session.set_smith_proc(caller["pid"], name, "mcp_handshake")
        log.note(f"client locked from MCP handshake: {name} (pid={caller['pid']})")
    except Exception as e:
        log.note(f"handshake client record failed: {e}")
