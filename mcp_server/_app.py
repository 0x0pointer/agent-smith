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

from tools.base import SCAN_FAILED_SENTINEL


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


def _rehydrate_tools() -> None:
    """Repopulate _session_tools_called from session.json after an MCP process restart.

    Without this, all in-memory tool tracking is lost on restart and completion
    gates (httpx→spider, coverage matrix checks) would incorrectly report that
    no web tools were run, even for an active scan.
    """
    import json as _json
    import os as _os
    _session_file = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), "session.json")
    try:
        if not _os.path.isfile(_session_file):
            return
        data = _json.loads(open(_session_file).read())
        if data.get("status") == "running":
            for tool in data.get("tools_called", []):
                _session_tools_called.add(tool)
    except Exception:
        pass  # silently ignore — fresh set is safe


_rehydrate_tools()


# ── Parameter coercion ────────────────────────────────────────────────────

def _ensure_dict(value):
    """Coerce a dict-ish tool argument to a dict (or None).

    LLMs — especially smaller local models — serialize dict params as JSON
    strings, or send an empty string for "no options". A bare ``json.loads``
    raised on ``''`` and crashed the tool call (the validation/loop error that
    spun the watchdog). Empty/blank or unparseable strings now coerce to None;
    callers do ``_ensure_dict(x) or {}``.
    """
    if value is None:
        return None
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        try:
            return json.loads(s)
        except (ValueError, TypeError):
            return None
    return value


# ── QA alert injection ────────────────────────────────────────────────────────

_QA_STATE_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "qa_state.json")
_last_qa_shown_ts: str = ""   # ISO timestamp of last alert batch shown to Smith


def _inject_qa_alerts(result: str) -> str:
    """
    DEPRECATED: QA alert injection now happens inside scan_engine.wrap() where
    alerts are placed into the structured envelope (warnings[] + summary) rather
    than appended as plaintext. This function is kept for import compatibility
    only and is a no-op pass-through.
    """
    return result  # no-op — logic lives in scan_engine/envelope.py _inject_qa_alerts_into_envelope()


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

async def _append_quick_log(name: str, kwargs: dict, result: str, elapsed: float) -> None:
    """DEPRECATED: Quick log now fires inside scan_engine.wrap() via _quick_log_tool().
    Kept as no-op for import compatibility only."""
    pass


def _forward_env(tool) -> dict | None:
    """Build the tool subprocess's env from the tool's forward_env specs.

    Each entry is "VAR" or "SRC:DST" — the SRC:DST form forwards SRC's value into
    the tool subprocess under the name DST. This lets us keep the anthropic
    AI-testing key in .env as AITEST_ANTHROPIC_API_KEY (so Claude Code never picks
    it up for model billing) while the red-team tools still receive it as the
    ANTHROPIC_API_KEY they expect. Server-side only. Returns None when nothing is
    forwarded so callers pass an explicit "no extra env".
    """
    env_vars = {}
    for _spec in tool.forward_env:
        _src, _, _dst = _spec.partition(":")
        if _src in os.environ:
            env_vars[_dst or _src] = os.environ[_src]
    return env_vars or None


def _scan_failed_result(tool, stdout: str, stderr: str, exit_code: int) -> str:
    """Build the SCAN_FAILED-sentinel string for a broken scan (issue #178).
    wrap() elevates it into a visible failure envelope."""
    tail = _clip((stderr.strip() or stdout.strip()), 1_500)
    hint = ""
    if exit_code == 137:
        hint = (" (137 = OOM-killed / SIGKILL; the container's memory cap may be "
                "too low for this target — narrow the path or raise the limit)")
    return (
        f"{SCAN_FAILED_SENTINEL}{tool.name} exited {exit_code}{hint}. "
        f"This is a BROKEN scan, not a clean result — do NOT treat empty "
        f"findings as secure; re-run before trusting the output.\nstderr:\n{tail}"
    )


def _format_run_result(tool, stdout: str, stderr: str, exit_code: int = 0) -> str:
    """Render a container's stdout/stderr into the tool's result string.

    A non-ok container exit (issue #178) is a BROKEN scan — a crashed/OOM/
    config-errored container returns empty stdout, which a parser happily reads
    as zero findings and reports as "clean". We surface that as a SCAN_FAILED
    sentinel. BUT we parse FIRST: a tool that exits non-zero yet still produced
    usable output (e.g. a linter that exits 1 *because* it found issues) RAN
    successfully — its results must not be discarded. So a run is only "broken"
    when a non-ok exit coincides with NO usable output. On a clean/with-output
    exit: clipped raw text when the tool has no parser, else a JSON envelope."""
    nonok = exit_code not in tool.ok_exit_codes
    if tool.parser is None:
        # "Usable output" is stdout (results) — stderr is the error channel, so a
        # non-ok exit with empty stdout is a failure even when stderr is noisy.
        if nonok and not stdout.strip():
            return _scan_failed_result(tool, stdout, stderr, exit_code)
        return _clip(stdout or stderr, tool.max_output)
    parsed = tool.parser(stdout, stderr)
    if nonok and not parsed:
        return _scan_failed_result(tool, stdout, stderr, exit_code)
    return json.dumps({"findings": parsed, "raw": _clip(stdout, tool.max_output)}, indent=2)


def _resolve_mount(name: str, tool, kwargs: dict) -> tuple[str | None, str | None]:
    """Resolve the host dir to mount at /target for a needs_mount tool.

    Returns (mount_path, error). Fixes issue #178 root-cause B: previously the
    mount was ``PENTEST_TARGET_PATH or os.getcwd()`` while _build_args remaps any
    path arg to /target — so a `target` passed to scan() was silently ignored and,
    with no codebase set, the agent scanned its OWN repo (cwd) and reported it
    "clean". Now, mirroring exec_sandbox (handlers_code.py): an explicit `target`
    OVERRIDES the env, and if neither resolves to a real dir we return an explicit
    error instead of silently scanning cwd."""
    if not tool.needs_mount:
        return None, None
    for cand in (kwargs.get("path"), os.environ.get("PENTEST_TARGET_PATH", "")):
        if not cand:
            continue
        abs_path = os.path.abspath(os.path.expanduser(cand))
        if os.path.isdir(abs_path):
            return abs_path, None
    err = (
        f"{SCAN_FAILED_SENTINEL}{name}: no valid codebase to scan. Pass "
        f"target=<absolute dir> or call session(action='set_codebase', "
        f"options={{'path': '/abs/path'}}) first. NOT scanning the current "
        f"working directory."
    )
    return None, err


def _report_run_error(name: str, kwargs: dict, exc: BaseException) -> str:
    """Log a tool-run failure and report it to Sentry, returning the error string.

    Never raises — a failure logging or reporting the error must not propagate to
    FastMCP (that crashes the stdio transport), so both steps are best-effort.
    """
    err = f"[{name} error: {type(exc).__name__}: {exc}]"
    try:
        from core import logger as log
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


async def _run(name: str, **kwargs) -> str:
    """Run a lightweight Docker tool from the registry with logging + cost tracking."""
    import time
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

        # Resolve the mount for needs_mount tools. A missing/invalid codebase is
        # an explicit failure (sentinel) — never a silent scan of cwd (issue #178).
        mount, mount_err = _resolve_mount(name, tool, kwargs)
        if mount_err:
            cost_tracker.finish(call_id, mount_err)
            log.tool_result(name, mount_err)
            return mount_err
        if mount:
            log.note(f"{name}: mounting {mount} at /target")

        env_vars = _forward_env(tool)

        try:
            stdout, stderr, exit_code = await run_container(
                tool.image, args, timeout=tool.default_timeout,
                mount_path=mount, extra_volumes=tool.extra_volumes or None,
                env_vars=env_vars,
                network=tool.network, cap_add=tool.cap_add or None,
            )
        except asyncio.TimeoutError:
            result = (f"{SCAN_FAILED_SENTINEL}{name} timed out after "
                      f"{tool.default_timeout}s — increase timeout or reduce scope. "
                      f"This is an INCOMPLETE scan, not a clean result.")
            cost_tracker.finish(call_id, result)
            log.tool_result(name, result)
            return result

        # Log full verbose output before any clipping
        log.tool_result_verbose(name, stdout, stderr)

        result = _format_run_result(tool, stdout, stderr, exit_code)

        cost_tracker.finish(call_id, result)
        log.tool_result(name, result)

        # QA alerts and quick_log are now handled inside scan_engine.wrap(),
        # which every tool handler calls after _run() returns raw output.
        # Do NOT re-add _inject_qa_alerts or _append_quick_log here — that
        # would pollute artifacts with QA text and double-log to quick_log.

        return result

    except BaseException as exc:
        # Catch everything including asyncio.CancelledError (BaseException in Python 3.8+).
        # Never let any exception propagate to FastMCP — that crashes the stdio transport.
        return _report_run_error(name, kwargs, exc)


# ── .env loader ───────────────────────────────────────────────────────────────

def _load_dotenv() -> None:
    """Read .env from the project root into os.environ.

    .env values always win over inherited environment so that editing the file
    and restarting the dashboard picks up the new values without requiring a
    full MCP server restart.
    """
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
            if key:
                os.environ[key] = val

    # Server-only: the AI-testing anthropic key lives in .env as AITEST_ANTHROPIC_API_KEY so an
    # interactive Claude Code can't pick it up and bill the Smith agent's model calls to it. Inside the
    # server we re-expose it as ANTHROPIC_API_KEY for the QA agent + red-team tool forwarding; the
    # spawned Smith strips ANTHROPIC_API_KEY unless SMITH_SPAWN_USE_API_KEY=1, so it never bills the
    # agent. A real ANTHROPIC_API_KEY (SMITH_USE_API_KEY=yes / legacy) takes precedence if present.
    _aitest = os.environ.get("AITEST_ANTHROPIC_API_KEY")
    if _aitest and not os.environ.get("ANTHROPIC_API_KEY"):
        os.environ["ANTHROPIC_API_KEY"] = _aitest
