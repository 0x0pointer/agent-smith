"""
FastAPI web server
==================
Serves the dashboard UI and REST API on the same port (default 7777).

Routes
------
  GET /               → dashboard UI
  GET /api/findings   → current scan findings + diagrams (findings.json)
  GET /api/session    → current scan session state (session.json)
  GET /api/cost       → current scan cost breakdown (session_cost.json)
  GET /api/logs       → current session log lines

Usage
-----
  from core.api_server import serve
  url = await serve(port=7777)
  # → "http://localhost:7777"

Layout
------
The implementation is split across focused submodules; import from
``core.api_server`` exactly as before — every name is re-exported here.

  __init__     this file — paths, the FastAPI app, watchdog state/config,
               shared file helpers, background tasks, and the facade
  mermaid      light→dark markdown mermaid rendering (cached)
  smith        Smith process supervision: detection, client resolution,
               spawn, hung-kill, and the auto-restart watchdog
  serve        dashboard server lifecycle (independent uvicorn process)
  routes       all HTTP endpoints (one APIRouter, included below)

State/config below (paths, app, the _watchdog_* globals, _svg_cache) lives
here in the package namespace so it stays patchable as ``core.api_server.NAME``.
Submodules read it back via ``import core.api_server as _api`` — deferred
attribute access that's monkeypatch-transparent and safe against the cycle.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from core import paths as _paths

_log = logging.getLogger(__name__)
_ERR_REQUEST_FAILED = "Request failed"

_REPO_ROOT         = _paths.REPO_ROOT
_FINDINGS_FILE     = _paths.FINDINGS_FILE
_SESSION_FILE      = _paths.SESSION_FILE
_COST_FILE         = _paths.COST_FILE
_COVERAGE_FILE     = _paths.COVERAGE_FILE
_QA_STATE_FILE     = _paths.QA_STATE_FILE
_STEERING_FILE     = _paths.STEERING_FILE
_QUICK_LOG_FILE    = _paths.QUICK_LOG_FILE
_METRICS_FILE      = _paths.METRICS_FILE
_TEMPLATES_DIR     = _paths.TEMPLATES_DIR
_DASHBOARD_DIR     = _paths.DASHBOARD_DIR
_THREAT_MODEL_DIR  = _paths.THREAT_MODEL_DIR
_SMITH_PID_FILE    = _paths.SMITH_PID_FILE
_SMITH_CLIENT_FILE = _paths.SMITH_CLIENT_FILE

# ── Optional Sentry error tracking ───────────────────────────────────────────
# Set SENTRY_DSN env var to enable. No-op when unset so other installs are
# unaffected. Remove this block (and unset the env var) when done testing.
_sentry_dsn = os.environ.get("SENTRY_DSN")
if _sentry_dsn:
    try:
        import sentry_sdk
        sentry_sdk.init(dsn=_sentry_dsn, send_default_pii=True)
    except ImportError:
        _log.warning("SENTRY_DSN set but sentry-sdk not installed; skipping")

# ── FastAPI app ───────────────────────────────────────────────────────────────

app = FastAPI(title="pentest-agent")

# Dashboard UI: a Jinja2-rendered index.html that {% include %}s one HTML
# partial per tab, plus raw static CSS/JS — all under dashboard/. Mounted at
# import so both TestClient(app) and the live uvicorn server serve it.
templates = Jinja2Templates(directory=str(_DASHBOARD_DIR))
app.mount("/static", StaticFiles(directory=str(_DASHBOARD_DIR)), name="static")

_qa_task:        asyncio.Task | None = None  # kept alive to prevent GC
_watchdog_task:  asyncio.Task | None = None
_status_task:    asyncio.Task | None = None
# Auto-restart watchdog state
_watchdog_last_restart_ts: float = 0.0
_watchdog_restart_count_window: list[float] = []  # epoch seconds of restarts in trailing hour
_WATCHDOG_POLL_SECONDS  = 60
_WATCHDOG_MIN_GAP_SECONDS = 90       # min seconds between auto-restarts
_WATCHDOG_MAX_PER_HOUR  = 20         # safety cap to avoid restart storms

# Periodic status update — interval is configurable via .env so an operator
# can dial it down for a long-running engagement. 0 disables the loop.
_STATUS_UPDATE_DEFAULT_MINUTES = 30

# Mermaid render cache (content_hash -> svgs dict); mutated by mermaid.py.
_svg_cache: dict[str, dict[str, str]] = {}


@app.on_event("startup")
async def _start_background_tasks() -> None:
    global _qa_task, _watchdog_task, _status_task
    from mcp_server._app import _load_dotenv
    _load_dotenv()
    from core.qa_agent import qa_daemon
    _qa_task = asyncio.create_task(qa_daemon.run(interval_s=120))
    _watchdog_task = asyncio.create_task(_smith_watchdog_loop())
    _status_task = asyncio.create_task(_status_update_loop())


async def _status_update_loop() -> None:
    """Fire a notifier status update every STATUS_UPDATE_INTERVAL_MINUTES.

    Skips when no scan is running so operators don't get idle pings.
    Reads the interval from env at startup so editing .env takes effect
    on the next dashboard restart (cheaper than re-reading every tick).
    Set STATUS_UPDATE_INTERVAL_MINUTES=0 to disable entirely.
    """
    import os
    raw = os.environ.get("STATUS_UPDATE_INTERVAL_MINUTES", "").strip()
    try:
        interval_min = int(raw) if raw else _STATUS_UPDATE_DEFAULT_MINUTES
    except ValueError:
        interval_min = _STATUS_UPDATE_DEFAULT_MINUTES
    if interval_min <= 0:
        return  # disabled
    interval_s = interval_min * 60

    from core import notifiers, status_reporter
    while True:
        try:
            await asyncio.sleep(interval_s)
            if not status_reporter.should_emit():
                continue
            msg = status_reporter.compose_status_message()
            if msg:
                notifiers.notify(**msg)
        except asyncio.CancelledError:
            raise
        except Exception:
            # Never let a status-update failure kill the loop — the
            # operator notices the next tick anyway. Log and continue.
            import logging
            logging.getLogger(__name__).exception(
                "status update tick failed"
            )


# ── Shared file helpers ─────────────────────────────────────────────────────

def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text()) if path.exists() else {}
    except Exception:
        return {}


def _safe_unlink(path) -> None:
    """Unlink a file, ignoring errors."""
    try:
        path.unlink(missing_ok=True)
    except Exception:
        pass


def _clear_dir_files(directory) -> None:
    """Delete all regular files inside a directory, ignoring errors."""
    try:
        if not directory.exists():
            return
        for f in directory.iterdir():
            try:
                if f.is_file():
                    f.unlink()
            except Exception:
                pass
    except Exception:
        pass


def _clear_log_files(log_dir) -> None:
    """Truncate all *.log files in log_dir to zero bytes."""
    try:
        for log_file in log_dir.glob("*.log"):
            try:
                log_file.write_text("")
            except Exception:
                pass
    except Exception:
        pass


async def _cleanup_tunnels() -> str:
    """Kill chisel server in the Kali container.

    When the server dies, remote chisel clients lose their connection
    and exit on their own — no need to reach back into the target.
    """
    import asyncio
    from tools.docker_cli import docker_executable

    try:
        proc = await asyncio.create_subprocess_exec(
            docker_executable(), "inspect", "--format={{.State.Running}}", "pentest-kali",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await proc.communicate()
        if stdout.strip() != b"true":
            return "no kali container running"

        proc = await asyncio.create_subprocess_exec(
            docker_executable(), "exec", "pentest-kali",
            "sh", "-c", "pkill -f 'chisel server' 2>/dev/null && echo 'chisel stopped' || echo 'no chisel running'",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await proc.communicate()
        return stdout.decode().strip()
    except Exception:
        _log.exception("cleanup_tunnels failed")
        return "cleanup error"


# ── Facade re-exports + route registration ──────────────────────────────────
# Imported after the state/helpers above so the submodules' module-level
# ``import core.api_server as _api`` binds a package that already exposes them.
# (Access is deferred to call time regardless, so order is belt-and-suspenders.)

from .mermaid import _DARK_REMAP, _remap_mermaid_dark, _render_mermaid_svgs  # noqa: E402
from .serve import (  # noqa: E402
    _PID_FILE,
    _pid_alive,
    _port_healthy,
    _read_pid,
    _write_pid,
    serve,
)
from .smith import (  # noqa: E402
    _KNOWN_CLIENTS,
    _SMITH_IDLE_SECONDS,
    _SMITH_PROC_NEEDLES,
    _SMITH_STALL_SECONDS,
    _SPAWN_SOURCE_TAGS,
    _client_installed,
    _client_process_running,
    _detect_active_client,
    _kill_hung_smith,
    _ensure_mcp_sse_alive,
    _live_pid_from_pid_file,
    _live_pid_from_process_scan,
    _mcp_sse_alive,
    _process_matches_smith,
    _quick_log_age_seconds,
    _resolve_client_from_running_process,
    _resolve_client_from_session,
    _resolve_client_from_smith_client_file,
    _scan_has_pending_cells,
    _signal_pid_file_alive,
    _signal_process_scan_finds_client,
    _signal_quick_log_fresh,
    _signal_session_recently_started,
    _smith_generating,
    _smith_hung_pid,
    _smith_running,
    _smith_stalled_pid,
    _smith_watchdog_loop,
    _spawn_smith,
    _spawn_source_tag,
    _watchdog_tick,
)

from . import routes  # noqa: E402

app.include_router(routes.router)
