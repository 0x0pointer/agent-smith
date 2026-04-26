"""
Consolidated kali tool — replaces the kali_exec part of exploitation.py
"""
from core import cost as cost_tracker
from core import logger as log
from core import session as scan_session
from mcp_server._app import mcp, _clip, _record


@mcp.tool()
async def kali(command: str, timeout: int = 600) -> str:
    """Run any command in the Kali container (auto-starts if needed).
    Hundreds of tools available: nikto, sqlmap, gobuster, hydra, testssl,
    enum4linux-ng, wapiti, sslscan, ssh-audit, theHarvester, dnsrecon, etc.

    timeout: seconds to wait for the command (default 600 = 10 min).
    Increase for long-running tools — e.g. timeout=1200 for deep sqlmap/hydra runs.
    The command is killed and partial output returned if the timeout is exceeded.
    """
    from tools import kali_runner

    stop = scan_session.check_limits(cost_tracker.get_summary())
    if stop:
        return stop

    _record("kali")
    log.tool_call("kali", {"command": command, "timeout": timeout})
    call_id = cost_tracker.start("kali")
    raw_output = await kali_runner.exec_command(command, timeout=timeout)
    log.tool_result_verbose("kali", raw_output, "")
    result = _clip(raw_output, 8_000)
    cost_tracker.finish(call_id, result)
    log.tool_result("kali", result)

    # Route through scan_engine: use tool-specific summarizer when detected
    from mcp_server.scan_engine import wrap
    tool_key = "kali_sqlmap" if command.strip().startswith("sqlmap") else "kali"
    return wrap(tool_key, raw_output, {"command": command, "_tool": tool_key})
