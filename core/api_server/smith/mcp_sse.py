"""
Cross-platform self-heal for the MCP SSE daemon (port 7778).

The dashboard's watchdog is the natural supervisor for the bare uvicorn MCP
process. ``_mcp_sse_alive`` and ``_launchd_supervises_mcp`` are reached through
the package object (``_smith.<name>``) so tests can patch them on the facade;
the restart-throttle timestamp ``_mcp_sse_last_restart_ts`` lives on the facade
(__init__) and is read/written via ``_smith.`` so a monkeypatch reset is honoured.
"""
from __future__ import annotations

import asyncio

import core.api_server as _api
import core.api_server.smith as _smith

from ._common import _log, _MCP_SSE_RESTART_MIN_GAP_SECONDS, _MCP_LAUNCHD_LABEL


def _mcp_sse_alive() -> bool:
    """Quick liveness check on the MCP SSE server (port 7778).

    Used by the watchdog to skip restarts when MCP is dead — restarting
    Smith into a dead MCP causes a 30–60s burn of subprocess fallbacks
    that always fail and end the opencode -p run with a text response.

    Socket is wrapped in contextlib.closing so the file descriptor is
    released even when settimeout/connect_ex raises before our own .close().
    """
    import contextlib
    import socket
    try:
        with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.settimeout(0.8)
            return sock.connect_ex(("127.0.0.1", 7778)) == 0
    except OSError as e:
        _log.debug("mcp_sse_alive check failed: %s", e)
        return False


async def _launchd_supervises_mcp(label: str = _MCP_LAUNCHD_LABEL) -> bool:
    """True when a loaded launchd job is already supervising the MCP SSE daemon.

    macOS only — on Linux/Windows ``launchctl`` is absent and this returns False,
    so the watchdog falls back to the launcher script. When launchd IS managing
    the daemon we restart *through* it (kickstart) instead of spawning a second,
    unsupervised process that would fight launchd for port 7778 and leave an
    orphan blocking the next bootstrap.
    """
    import os
    try:
        proc = await asyncio.create_subprocess_exec(
            "launchctl", "print", f"gui/{os.getuid()}/{label}",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.wait(), timeout=5)
        return proc.returncode == 0
    except Exception:
        return False


async def _ensure_mcp_sse_alive(now: float) -> None:
    """Cross-platform self-heal for the MCP SSE daemon (port 7778).

    The MCP server is a bare uvicorn process with no reliable OS supervisor on
    most setups: a launchd KeepAlive agent silently fails when the repo lives in
    a TCC-protected folder (~/Desktop, ~/Documents, ...), and there's nothing at
    all on a fresh Linux/Windows box. When that process dies, every
    session()/scan()/report() call fails with "Unable to connect" until someone
    restarts it by hand — the recurring breakage.

    The always-on dashboard process is the natural supervisor: it inherits the
    operator's permissions (so it can actually restart the daemon) and is the
    same process the operator is already watching. This runs on every watchdog
    tick, independent of scan status, so MCP is back before the next scan starts.
    OS-agnostic: bash launcher on POSIX, PowerShell launcher on Windows.
    """
    if _smith._mcp_sse_alive():
        return
    if now - _smith._mcp_sse_last_restart_ts < _MCP_SSE_RESTART_MIN_GAP_SECONDS:
        return
    _smith._mcp_sse_last_restart_ts = now

    import os
    # If launchd already supervises the daemon, restart THROUGH it — spawning a
    # parallel start-mcp-server.sh races launchd's own KeepAlive restart for port
    # 7778 and leaves an orphan that blocks the next bootstrap. kickstart -k
    # force-restarts the supervised process with no competing launcher.
    if os.name != "nt" and await _smith._launchd_supervises_mcp():
        cmd = ["launchctl", "kickstart", "-k", f"gui/{os.getuid()}/{_MCP_LAUNCHD_LABEL}"]
        launcher_name = f"launchctl kickstart {_MCP_LAUNCHD_LABEL}"
    elif os.name == "nt":
        launcher = _api._REPO_ROOT / "installers" / "start-mcp-server.ps1"
        cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(launcher), "start"]
        launcher_name = launcher.name
        if not launcher.exists():
            _log.warning("MCP SSE down but launcher missing: %s", launcher)
            return
    else:
        launcher = _api._REPO_ROOT / "installers" / "start-mcp-server.sh"
        cmd = ["/bin/bash", str(launcher), "start"]
        launcher_name = launcher.name
        if not launcher.exists():
            _log.warning("MCP SSE down but launcher missing: %s", launcher)
            return

    _log.warning("MCP SSE server down on 127.0.0.1:7778 — auto-restarting via %s", launcher_name)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.wait(), timeout=30)
    except asyncio.TimeoutError:
        _log.warning("MCP SSE auto-restart still coming up after 30s")
    except Exception:
        _log.exception("MCP SSE auto-restart failed")
        return
    if _smith._mcp_sse_alive():
        _log.info("MCP SSE server auto-restarted OK")
        try:
            from core import notifiers as _nfr
            _nfr.notify(
                title="MCP SSE server auto-restarted",
                body=(
                    "The MCP server on 127.0.0.1:7778 had died and the dashboard "
                    "watchdog brought it back automatically — no manual restart needed."
                ),
                urgency="normal",
                code="WATCHDOG_MCP_REVIVED",
            )
        except Exception:
            pass
