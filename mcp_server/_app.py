"""
Shared MCP application state
==============================
Single source of truth for the FastMCP instance and the helpers that
every tool module needs.  Import from here; never create a second instance.

  from mcp_server._app import mcp, _run, _clip, _record, _session_tools_called
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import traceback
from datetime import datetime, timezone


def _app_phase(label: str) -> None:
    """Write a timestamped phase marker to stderr (→ mcp_crash.log)."""
    msg = f"[_app.py {datetime.now(timezone.utc).strftime('%H:%M:%S.%f')[:-3]}Z] {label}\n"
    sys.stderr.write(msg)
    sys.stderr.flush()


_app_phase("importing FastMCP")
try:
    from mcp.server.fastmcp import FastMCP
    _app_phase("FastMCP imported OK")
except BaseException:
    _app_phase("FAILED importing FastMCP")
    traceback.print_exc(file=sys.stderr)
    raise

_app_phase("importing core modules")
try:
    from core import cost as cost_tracker
    from core import session as scan_session
    _app_phase("core modules imported OK")
except BaseException:
    _app_phase("FAILED importing core modules")
    traceback.print_exc(file=sys.stderr)
    raise

# ── FastMCP singleton ──────────────────────────────────────────────────────────

_app_phase("instantiating FastMCP('pentest-agent')")
try:
    mcp = FastMCP("pentest-agent")
    _app_phase("FastMCP instance created OK")
except BaseException:
    _app_phase("FAILED instantiating FastMCP")
    traceback.print_exc(file=sys.stderr)
    raise

# ── Session tool-call tracking (reset on start_scan) ─────────────────────────

_session_tools_called: set[str] = set()


def _record(tool_name: str) -> None:
    _session_tools_called.add(tool_name)
    scan_session.add_tool_called(tool_name)


# ── Output clipping ───────────────────────────────────────────────────────────

def _clip(text: str, limit: int = 8_000) -> str:
    """
    Smart head+tail truncation.
    Keeps the first 2/3 and last 1/3 of the limit, dropping the middle.
    Security tools (sqlmap, nikto, nuclei) emit the most important results
    at the END, so preserving the tail is critical.
    """
    if len(text) <= limit:
        return text
    head    = (limit * 2) // 3
    tail    = limit - head
    dropped = len(text) - head - tail
    return text[:head] + f"\n\n[… {dropped:,} chars clipped …]\n\n" + text[-tail:]


# ── Docker tool runner ────────────────────────────────────────────────────────

async def _run(name: str, **kwargs) -> str:
    """Run a lightweight Docker tool from the registry with logging + cost tracking."""
    from core import logger as log
    from tools import REGISTRY
    from tools.docker_runner import run_container

    try:
        stop = scan_session.check_limits(cost_tracker.get_summary())
        if stop:
            return stop

        log.tool_call(name, kwargs)
        call_id = cost_tracker.start(name)
        tool    = REGISTRY[name]
        args    = tool.build_args(**kwargs)
        mount   = os.environ.get("PENTEST_TARGET_PATH", os.getcwd()) if tool.needs_mount else None
        env_vars = {k: os.environ[k] for k in tool.forward_env if k in os.environ} or None

        try:
            stdout, stderr, _ = await run_container(
                tool.image, args, timeout=tool.default_timeout,
                mount_path=mount, extra_volumes=tool.extra_volumes or None,
                env_vars=env_vars,
            )
        except asyncio.TimeoutError:
            result = f"[{name} timed out after {tool.default_timeout}s — increase timeout or reduce scope]"
            cost_tracker.finish(call_id, result)
            log.tool_result(name, result)
            return result

        # Log full verbose output before any clipping
        log.tool_result_verbose(name, stdout, stderr)

        if tool.parser is None:
            result = _clip(stdout or stderr, tool.max_output)
        else:
            parsed = tool.parser(stdout, stderr)
            result = json.dumps({"findings": parsed, "raw": _clip(stdout, tool.max_output)}, indent=2)

        cost_tracker.finish(call_id, result)
        log.tool_result(name, result)
        return result

    except BaseException as exc:
        # Catch everything including asyncio.CancelledError (BaseException in Python 3.8+).
        # Never let any exception propagate to FastMCP — that crashes the stdio transport.
        err = f"[{name} error: {type(exc).__name__}: {exc}]"
        try:
            log.tool_result(name, err)
        except Exception:
            pass
        try:
            import sentry_sdk
            with sentry_sdk.new_scope() as scope:
                scope.set_tag("tool", name)
                scope.set_context("tool_call", {"tool": name, "kwargs": str(kwargs)})
                sentry_sdk.capture_exception(exc)
        except Exception:
            pass
        return err


# ── .env loader ───────────────────────────────────────────────────────────────

def _load_dotenv() -> None:
    """Read .env from the project root into os.environ (only sets missing keys)."""
    env_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
    if not os.path.isfile(env_file):
        return
    with open(env_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = val
