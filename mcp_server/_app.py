"""
Shared MCP application state
==============================
Single source of truth for the FastMCP instance and the helpers that
every tool module needs.  Import from here; never create a second instance.

  from mcp_server._app import mcp, _run, _clip, _record, _session_tools_called
"""
from __future__ import annotations

import json
import os

from mcp.server.fastmcp import FastMCP

from core import cost as cost_tracker
from core import session as scan_session

# ── FastMCP singleton ──────────────────────────────────────────────────────────

mcp = FastMCP("pentest-agent")

# ── Session tool-call tracking (reset on start_scan) ─────────────────────────

_session_tools_called: set[str] = set()


def _record(tool_name: str) -> None:
    _session_tools_called.add(tool_name)


# ── Output clipping ───────────────────────────────────────────────────────────

def _clip(text: str, limit: int = 12_000) -> str:
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

    stop = scan_session.check_limits(cost_tracker.get_summary())
    if stop:
        return stop

    log.tool_call(name, kwargs)
    call_id = cost_tracker.start(name)
    tool    = REGISTRY[name]
    args    = tool.build_args(**kwargs)
    mount   = os.environ.get("PENTEST_TARGET_PATH", os.getcwd()) if tool.needs_mount else None
    env_vars = {k: os.environ[k] for k in tool.forward_env if k in os.environ} or None

    stdout, stderr, _ = await run_container(
        tool.image, args, timeout=tool.default_timeout,
        mount_path=mount, extra_volumes=tool.extra_volumes or None,
        env_vars=env_vars,
    )

    if tool.parser is None:
        result = _clip(stdout or stderr, tool.max_output)
    else:
        parsed = tool.parser(stdout, stderr)
        result = json.dumps({"findings": parsed, "raw": _clip(stdout, tool.max_output)}, indent=2)

    cost_tracker.finish(call_id, result)
    log.tool_result(name, result)
    return result


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
