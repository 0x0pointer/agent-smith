"""Code-analysis handlers: semgrep, trufflehog, exec_sandbox."""
import asyncio

from core import logger as log
from mcp_server._app import _clip, _record, _run


async def _handle_semgrep(target, flags, _options):
    _record("semgrep")
    raw = await _run("semgrep", path=target, flags=flags)
    from mcp_server.scan_engine import wrap
    return wrap("semgrep", raw, {"path": target})


async def _handle_trufflehog(target, flags, _options):
    _record("trufflehog")
    raw = await _run("trufflehog", path=target, flags=flags)
    from mcp_server.scan_engine import wrap
    return wrap("trufflehog", raw, {"path": target})


async def _handle_exec_sandbox(target, flags, options):
    """Build & run white-box target code in a network-isolated, caps-dropped
    sandbox to CONFIRM a finding with a real crash/exec artifact.

    Opt-in and fail-soft: a setup/staging failure returns guidance (never an
    exception, never a completion gate). Use it for the no-live-path white-box
    slice (libraries, parsers, deserialization gadgets) where the always-on
    adjudication gate can't re-run a live attack.
    """
    import os as _os
    from tools import sandbox_runner
    from mcp_server.scan_engine.artifacts import store_artifact
    _record("exec_sandbox")

    codebase = target or _os.environ.get("PENTEST_TARGET_PATH", "")
    if not codebase or not _os.path.isdir(codebase):
        return (
            "[exec_sandbox] No codebase available. Pass target=<absolute path> or call "
            "session(action='set_codebase', options={'path': '/abs/path'}) first. This tool "
            "builds/runs WHITE-BOX target code in isolation to confirm a finding with a real "
            "execution artifact."
        )
    cmd = options.get("cmd", "") or flags
    try:
        timeout = int(options.get("timeout", sandbox_runner.DEFAULT_TIMEOUT) or sandbox_runner.DEFAULT_TIMEOUT)
    except (TypeError, ValueError):
        timeout = sandbox_runner.DEFAULT_TIMEOUT
    image = options.get("image", sandbox_runner.DEFAULT_IMAGE)
    # Network is ON by default (so dependency installs work); pass
    # allow_network=false for strict isolation of genuinely untrusted code.
    allow_network = options.get("allow_network", True)
    if isinstance(allow_network, str):
        allow_network = allow_network.strip().lower() not in ("false", "0", "no", "off")

    log.tool_call("exec_sandbox", {"target": codebase, "subdir": options.get("subdir", ""),
                                   "network": "enabled" if allow_network else "isolated"})
    # The deadline is owned here via asyncio.timeout() (the idiomatic place — the
    # runner kills the container subprocess on cancellation so nothing is orphaned).
    try:
        async with asyncio.timeout(timeout):
            res = await sandbox_runner.run_in_sandbox(
                codebase_path=codebase,
                cmd=cmd,
                setup=options.get("setup", ""),
                image=image,
                subdir=options.get("subdir", ""),
                allow_network=allow_network,
            )
    except asyncio.TimeoutError:
        res = {"ok": True, "timed_out": True, "exit_code": None, "output": "", "image": image,
               "network": "enabled" if allow_network else "isolated",
               "error": f"sandbox timed out after {timeout}s"}
    if not res.get("ok"):
        msg = f"[exec_sandbox] could not run (fall back to static evidence): {res.get('error', 'unknown')}"
        log.tool_result("exec_sandbox", msg)
        return msg

    output = res.get("output", "")
    artifact_id = store_artifact(
        "exec_sandbox",
        f"$ {options.get('setup', '')}\n$ {cmd}\n"
        f"exit_code={res.get('exit_code')} timed_out={res.get('timed_out')}\n\n{output}",
    )
    header = (
        f"[exec_sandbox] image={res.get('image')} exit_code={res.get('exit_code')} "
        f"timed_out={res.get('timed_out')} network={res.get('network', 'enabled')} "
        f"artifact_id={artifact_id}\n"
        "(caps-dropped, pid/mem/cpu-capped, over a staged copy — original source untouched; "
        "network on by default, pass allow_network=false to isolate)\n"
        "If this output PROVES the finding (crash / code execution / leaked data), file the "
        "finding and pass this artifact_id as the reproduction artifact. If it does NOT reproduce, "
        "the static claim is unconfirmed — downgrade or drop it. This is opt-in evidence, never a "
        "completion gate; a clean static trace remains acceptable.\n\n"
    )
    clipped = _clip(output, 8_000)
    log.tool_result("exec_sandbox", f"exit={res.get('exit_code')} artifact={artifact_id}")
    return header + clipped
