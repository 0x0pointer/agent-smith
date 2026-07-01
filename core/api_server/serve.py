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
import os
import sys

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


def _code_fingerprint() -> float:
    """Newest mtime across all Python the dashboard process imports.

    serve() reuses an already-running dashboard only when this value matches the
    one saved when that process launched. The earlier check used serve.py's OWN
    mtime alone — so edits to routes.py, __init__.py, smith.py, or any core/
    helper the dashboard imports were served STALE until serve.py itself happened
    to change (e.g. new triage endpoints never reloaded). Walking the Python
    sources under core/ and mcp_server/ makes any backend edit invalidate the
    reuse and force a fresh process.

    Front-end assets (dashboard/*.html|js|css) are intentionally excluded:
    StaticFiles serves them from disk per request and the template re-renders per
    request, so they're already live without a restart. serve() runs only at
    dashboard start, so this directory walk is cheap.
    """
    newest = 0.0
    for pkg in ("core", "mcp_server"):
        try:
            for p in (_api._REPO_ROOT / pkg).rglob("*.py"):
                try:
                    m = p.stat().st_mtime
                except OSError:
                    continue
                if m > newest:
                    newest = m
        except OSError:
            continue
    return newest


def _write_pid(pid: int) -> None:
    _api._PID_FILE.write_text(f"{pid}:{_code_fingerprint():.6f}")


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
        with urllib.request.urlopen(f"http://localhost:{port}/healthz", timeout=2) as r:
            return r.status == 200
    except Exception:
        return False


async def serve(port: int = 7777) -> str:
    """
    Start the dashboard server as an independent background process.
    Survives MCP server restarts — uses a PID file to detect and reuse
    a previously spawned dashboard instead of killing it.
    Restarts automatically if any backend Python module has changed since launch
    (see _code_fingerprint — not just serve.py's own mtime).
    """
    current_mtime = _code_fingerprint()

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
    # Bind loopback by default so the control plane isn't exposed on the network.
    # Combined with the per-session bearer token (core.dashboard_auth), this closes
    # the unauthenticated-dashboard / CSRF / rebind class. Override with
    # DASHBOARD_HOST=0.0.0.0 only behind a trusted boundary (e.g. reach it via an
    # SSH tunnel instead — see docs/production-isolation.md).
    host = os.environ.get("DASHBOARD_HOST", "127.0.0.1")
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "uvicorn",
        "core.api_server:app",
        "--host", host,
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
