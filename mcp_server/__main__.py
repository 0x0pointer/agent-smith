"""
Pentest Agent MCP Server
========================
Thin entry point — loads .env, imports all tool modules, starts the server.

Consolidated tools (5 MCP tools, down from 24):
  mcp_server/scan_tools.py    — scan()    : nmap, naabu, subfinder, httpx, nuclei, ffuf, spider, semgrep, trufflehog, fuzzyai, pyrit
  mcp_server/kali_tools.py    — kali()    : freeform Kali container commands
  mcp_server/http_tools.py    — http()    : raw HTTP requests + PoC saving
  mcp_server/report_tools.py  — report()  : findings, diagrams, notes, dashboard
  mcp_server/session_tools.py — session() : scan lifecycle, Kali infra, codebase target

Register with Claude Code (run once):
  claude mcp add pentest-agent -- poetry -C ~/Desktop/agent-smith run python -m server
"""
import asyncio
import faulthandler
import os
import platform
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

# ── Crash log setup ───────────────────────────────────────────────────────────
# All stderr + explicit phase logs land here.  The file is appended (not
# truncated) so multiple restarts accumulate in one place.

_LOG_DIR   = Path(__file__).parent.parent / "logs"
_LOG_DIR.mkdir(exist_ok=True)
_crash_log = _LOG_DIR / "mcp_crash.log"


class _Tee:
    """Write to both original stderr and crash log file."""
    def __init__(self, original, path):
        self._orig = original
        self._file = open(path, "a", buffering=1)

    def write(self, data):
        self._orig.write(data)
        self._file.write(data)

    def flush(self):
        self._orig.flush()
        self._file.flush()

    def fileno(self):
        # Needed by faulthandler which calls fileno() on the fd it writes to.
        return self._orig.fileno()


sys.stderr = _Tee(sys.stderr, _crash_log)

# ── faulthandler — catches SIGSEGV, SIGFPE, hard C-level crashes ─────────────
# Writes a Python stack trace to stderr (→ also lands in mcp_crash.log).
faulthandler.enable(file=sys.stderr)


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _phase(label: str) -> None:
    """Write a timestamped phase marker to stderr so the crash log shows
    exactly how far startup got before the process died."""
    msg = f"\n[STARTUP {_ts()}] {label}\n"
    sys.stderr.write(msg)
    sys.stderr.flush()


# ── sys.excepthook — catches every uncaught exception ────────────────────────
# Python's default hook only prints to stderr; this one also records the full
# chain and re-raises nothing (the process exits naturally after the hook).

def _excepthook(exc_type, exc_value, exc_tb):
    sys.stderr.write(f"\n[UNCAUGHT EXCEPTION {_ts()}]\n")
    traceback.print_exception(exc_type, exc_value, exc_tb, file=sys.stderr)
    sys.stderr.flush()

sys.excepthook = _excepthook


# ── Sentry ────────────────────────────────────────────────────────────────────
# Set SENTRY_DSN in .env (or the shell environment) to enable.
# All uncaught exceptions, import failures, and tool crashes are captured.

def _init_sentry() -> None:
    dsn = os.environ.get("SENTRY_DSN", "")
    if not dsn:
        sys.stderr.write("[Sentry] SENTRY_DSN not set — error reporting disabled\n")
        sys.stderr.flush()
        return
    try:
        import sentry_sdk
        sentry_sdk.init(
            dsn=dsn,
            # Capture 100 % of transactions; lower in high-traffic setups.
            traces_sample_rate=1.0,
            # Full local variable values in stack frames.
            include_local_variables=True,
            # Attach the server name so you can tell instances apart.
            server_name="pentest-agent-mcp",
        )
        sys.stderr.write(f"[Sentry] Initialised (DSN: {dsn[:32]}...)\n")
        sys.stderr.flush()
    except Exception:
        sys.stderr.write("[Sentry] init failed — continuing without it\n")
        traceback.print_exc(file=sys.stderr)
        sys.stderr.flush()

# ── .env loading (early, before Sentry so DSN is available) ──────────────────

_phase("LOADING .env  →  mcp_server._app._load_dotenv")
try:
    from mcp_server._app import _load_dotenv
    _load_dotenv()
    _phase(".env loaded OK")
except BaseException:
    _phase("FAILED during _load_dotenv")
    traceback.print_exc(file=sys.stderr)
    sys.exit(1)


# ── Sentry (init after .env so SENTRY_DSN is populated) ──────────────────────
_init_sentry()


# ── Environment snapshot ──────────────────────────────────────────────────────
# Logged once at startup — if the problem is Python version / event-loop
# policy / missing env vars, this is where you'll see it.

_phase("ENVIRONMENT SNAPSHOT")
sys.stderr.write(
    f"  python      : {sys.version}\n"
    f"  platform    : {platform.platform()}\n"
    f"  cwd         : {os.getcwd()}\n"
    f"  __file__    : {__file__}\n"
    f"  asyncio policy : {type(asyncio.get_event_loop_policy()).__name__}\n"
)
# Warn if an event loop is already running (common source of
# 'asyncio.run() cannot be called from a running event loop' errors).
try:
    _running_loop = asyncio.get_running_loop()
    sys.stderr.write(
        f"  WARNING: event loop already running at startup: {_running_loop!r}\n"
    )
except RuntimeError:
    sys.stderr.write("  event loop   : none running at startup (expected)\n")
sys.stderr.flush()


# ── Module imports — each wrapped individually ────────────────────────────────
# If any import blows up the *exact* module name and full traceback appear in
# mcp_crash.log before the process exits, eliminating all guesswork.

def _safe_import(module_name: str) -> None:
    """Import *module_name*; abort with a clear diagnostic on any failure."""
    _phase(f"IMPORTING  {module_name}")
    try:
        __import__(module_name)
        _phase(f"OK         {module_name}")
    except BaseException:
        _phase(f"FAILED     {module_name}")
        traceback.print_exc(file=sys.stderr)
        sys.stderr.write(
            f"\n[ABORT] Could not import '{module_name}' — see traceback above.\n"
            f"        Fix the import error and restart the MCP server.\n\n"
        )
        sys.stderr.flush()
        try:
            import sentry_sdk
            sentry_sdk.set_tag("startup.failed_module", module_name)
            sentry_sdk.capture_exception()
            sentry_sdk.flush(timeout=3)
        except Exception:
            pass
        sys.exit(1)


_safe_import("mcp_server.scan_tools")
_safe_import("mcp_server.kali_tools")
_safe_import("mcp_server.http_tools")
_safe_import("mcp_server.report_tools")
_safe_import("mcp_server.session_tools")


# ── Tool registration audit ───────────────────────────────────────────────────

_phase("AUDITING registered tools")
try:
    from mcp_server._app import mcp
    _tool_log = _LOG_DIR / "tools_registered.log"
    with open(_tool_log, "w") as _f:
        _tools = mcp._tool_manager.list_tools()
        for _t in _tools:
            _f.write(f"REGISTERED: {_t.name}\n")
        _f.write(f"TOTAL: {len(_tools)}\n")
    _phase(f"Tools registered: {len(_tools)}  (see logs/tools_registered.log)")
except BaseException:
    _phase("FAILED during tool audit")
    traceback.print_exc(file=sys.stderr)
    # Non-fatal — don't exit, the server may still function.


# ── Start MCP server ──────────────────────────────────────────────────────────

_phase("CALLING mcp.run()  — server handshake begins now")
try:
    mcp.run()
    _phase("mcp.run() returned normally")
except BaseException:
    _phase("CRASHED inside mcp.run()")
    traceback.print_exc(file=sys.stderr)
    try:
        import sentry_sdk
        sentry_sdk.capture_exception()
        sentry_sdk.flush(timeout=3)
    except Exception:
        pass
    raise
