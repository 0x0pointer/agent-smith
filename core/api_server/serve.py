"""
Dashboard server lifecycle.

Starts the FastAPI dashboard as an independent background uvicorn process,
reusing an already-running instance (via a PID file) so it survives MCP
server restarts. Restarts automatically if the server code changed since
launch.

The liveness/PID helpers are read back through ``core.api_server`` (the
``_api`` alias) so tests patching e.g. ``core.api_server._port_healthy``
take effect when ``serve()`` calls them.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import core.api_server as _api

_PID_FILE = _api._REPO_ROOT / "logs" / "dashboard.pid"


def _read_pid() -> tuple[int | None, float | None]:
    """Return (pid, api_server_mtime_at_launch) from the PID file.

    Reads ``_api._PID_FILE`` (the package-level binding) so tests patching
    ``core.api_server._PID_FILE`` redirect it.
    """
    try:
        parts = _api._PID_FILE.read_text().strip().split(":", 1)
        pid = int(parts[0])
        mtime = float(parts[1]) if len(parts) > 1 else None
        return pid, mtime
    except Exception:
        return None, None


def _write_pid(pid: int) -> None:
    mtime = Path(__file__).stat().st_mtime
    _api._PID_FILE.write_text(f"{pid}:{mtime:.6f}")


def _pid_alive(pid: int) -> bool:
    """Cross-platform PID liveness check via psutil.pid_exists.

    The older ``os.kill(pid, 0)`` form was POSIX-only — on Windows it raises
    ``OSError: WinError 87`` (invalid parameter) for valid PIDs because the
    NT kernel doesn't model signal 0 the way POSIX does."""
    try:
        import psutil
        return bool(psutil.pid_exists(pid))
    except (ImportError, OSError):
        return False


def _port_healthy(port: int) -> bool:
    """Return True only if our FastAPI dashboard is responding on this port."""
    import urllib.request
    try:
        with urllib.request.urlopen(f"http://localhost:{port}/api/session", timeout=2) as r:
            return r.status == 200
    except Exception:
        return False


async def serve(port: int = 7777) -> str:
    """
    Start the dashboard server as an independent background process.
    Survives MCP server restarts — uses a PID file to detect and reuse
    a previously spawned dashboard instead of killing it.
    Restarts automatically if api_server.py has been modified since launch.
    """
    current_mtime = Path(__file__).stat().st_mtime

    # Check PID file first — survives MCP server restarts
    saved_pid, saved_mtime = _api._read_pid()
    code_unchanged = saved_mtime is not None and abs(current_mtime - saved_mtime) < 1.0
    if saved_pid and _api._pid_alive(saved_pid) and _api._port_healthy(port) and code_unchanged:
        return f"http://localhost:{port}"

    # Old process died, code changed, or never existed — kill stale process if running
    if saved_pid and _api._pid_alive(saved_pid):
        # psutil.Process.terminate() abstracts SIGTERM (POSIX) vs
        # TerminateProcess (Windows). Older form was os.kill(SIGTERM)
        # which Windows doesn't support for foreign processes.
        try:
            import psutil
            psutil.Process(saved_pid).terminate()
            await asyncio.sleep(0.3)
        except (psutil.NoSuchProcess, psutil.AccessDenied, ImportError, OSError):
            pass

    # Fire-and-forget: process runs independently in a new session.
    # stdout/stderr → /dev/null so the MCP stdio pipe is never touched.
    # start_new_session=True detaches from MCP server's process group.
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "uvicorn",
        "core.api_server:app",
        "--host", "0.0.0.0",
        "--port", str(port),
        "--no-access-log",
        "--log-level", "critical",
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
        cwd=str(_api._REPO_ROOT),
        start_new_session=True,
    )
    _api._write_pid(proc.pid)

    await asyncio.sleep(1.5)     # give uvicorn time to bind the port
    if not _api._port_healthy(port):
        return f"Dashboard failed to start on port {port}"
    return f"http://localhost:{port}"
