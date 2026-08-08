"""
Smith caller detection.

At session.start() we inspect TCP connections to the MCP SSE port (and the
parent process for stdio MCP) to identify which client — claude / opencode /
codex — is driving the scan, then mirror it into logs/smith.pid + smith.client
for the dashboard. Independent of session ``_current``; only ``_persist_smith_caller``
touches the repo root, which it reads back via ``core.session`` so the tests'
``_REPO_ROOT`` patches apply.
"""
from __future__ import annotations

import os

import core.session as _sess
from core.client_patterns import classify_client

# MCP SSE listen port — must match start-mcp-server.sh. The caller-detection
# helper below uses this to identify the Smith client across the TCP socket.
_MCP_SSE_PORT = 7778


def _connected_client_candidates(port: int) -> list[dict]:
    """Connected PIDs that resolve to a known Smith client, in iteration order."""
    out: list[dict] = []
    for pid in _connected_pids(port):
        client = _resolve_client_for_pid(pid)
        if client:
            out.append({"pid": pid, "client": client})
    return out


def _detect_smith_caller(port: int = _MCP_SSE_PORT, prefer_client: str | None = None) -> dict | None:
    """Identify the calling Smith client.

    Returns ``{"pid": int, "client": "claude" | "opencode" | "codex"}`` for
    the most likely caller, or ``None`` when nothing recognizable is connected.
    Never raises — failure to detect is a routine outcome, not an error.

    ``prefer_client`` is the client name from the MCP ``initialize`` handshake
    (``clientInfo.name``) — authoritative and per-connection. When given, we
    return the connected PID whose cmdline matches THAT client. This
    disambiguates the case where several clients share the SSE server (e.g. a
    dev Claude Code session alongside the opencode scanner), which otherwise
    resolves to whichever PID ``process_iter`` yields first and silently
    mislabels the scan. If no connected PID matches, we still trust the
    handshake name and return ``pid=-1`` so the watchdog falls back to its
    other liveness signals.
    """
    candidates = _connected_client_candidates(port)
    if prefer_client:
        for cand in candidates:
            if cand["client"] == prefer_client:
                return cand
        return {"pid": -1, "client": prefer_client}
    if candidates:
        return candidates[0]
    # Stdio MCP fallback: the MCP server runs as a child of the client process.
    try:
        parent_pid = os.getppid()
        client = _resolve_client_for_pid(parent_pid)
        if client:
            return {"pid": parent_pid, "client": client}
    except OSError:
        pass
    return None


def _connected_pids(port: int) -> list[int]:
    """PIDs with an ESTABLISHED TCP connection involving the given port.

    Walks ``psutil.process_iter()`` and asks each process for its own
    connection list, instead of the system-wide ``psutil.net_connections()``.

    Why: on macOS, ``psutil.net_connections(kind="tcp")`` requires admin to
    return non-empty results — without elevation it silently returns ``[]``
    even though the connections clearly exist (lsof sees them fine). The
    per-process ``proc.net_connections()`` call works without elevation for
    any process owned by the current user, which is the realistic scope for
    a Smith client connecting to a Smith-owned MCP server. Slightly slower
    in big process tables (still well under 10 ms in practice), but
    correct on every platform we care about.

    Connections are accepted if EITHER the local or remote endpoint matches
    ``port``. Local match = the MCP server side; remote match = the client
    side. We collect both and let the cmdline check in
    ``_resolve_client_for_pid`` filter out the server's own PID.
    """
    try:
        import psutil
    except ImportError:
        return []
    pids: list[int] = []
    try:
        for proc in psutil.process_iter(["pid"]):
            try:
                # net_connections() replaces deprecated connections() in
                # psutil >= 6.0; both accept kind="tcp" and use the same
                # sconn shape under the hood.
                conn_iter = (
                    proc.net_connections(kind="tcp")
                    if hasattr(proc, "net_connections")
                    else proc.connections(kind="tcp")
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                continue
            for conn in conn_iter:
                if conn.status != psutil.CONN_ESTABLISHED:
                    continue
                local_match = conn.laddr and conn.laddr.port == port
                remote_match = conn.raddr and conn.raddr.port == port
                if local_match or remote_match:
                    pids.append(proc.pid)
                    break  # don't list a process twice for the same port
    except (psutil.AccessDenied, OSError, RuntimeError):
        return []
    return pids


def _resolve_client_for_pid(pid: int) -> str | None:
    """Map a PID to a known Smith client by command-line inspection.

    Returns the client name or ``None`` when the process doesn't look like a
    Smith client (e.g., the MCP server itself, vLLM, or unrelated processes).
    Cross-platform via ``psutil`` — replaces the Unix-only ``ps -o command=``.
    """
    try:
        import psutil
    except ImportError:
        return None
    try:
        proc = psutil.Process(pid)
        cmd = " ".join(proc.cmdline())
    except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError, OSError):
        return None
    if not cmd:
        return None
    # Per-client cmdline signatures live in core.client_patterns (the single
    # place a new client is added). classify_client is case-insensitive.
    return classify_client(cmd)


def _persist_smith_caller(info: dict) -> None:
    """Mirror the captured caller into logs/smith.pid + logs/smith.client so
    the dashboard's existing PID-file check picks it up unchanged. Failure
    is non-fatal — the in-memory smith_proc field is still authoritative."""
    if not info:
        return
    try:
        log_dir = _sess._REPO_ROOT / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        (log_dir / "smith.pid").write_text(str(info["pid"]))
        (log_dir / "smith.client").write_text(info["client"])
    except OSError:
        pass
