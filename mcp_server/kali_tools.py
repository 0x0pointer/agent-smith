"""
Consolidated kali tool — replaces the kali_exec part of exploitation.py
"""
from core import cost as cost_tracker
from core import logger as log
from core import session as scan_session
from mcp_server._app import mcp, _clip, _record, _inject_qa_alerts


# A request/command that hit its time bound is a LEAD, not just wasted wall-clock —
# time-based-blind SQLi/cmdi, an SSRF connecting outbound, or a genuinely slow endpoint.
_KALI_TIMEOUT_MARKERS = (
    "[partial — command timed out]", "operation timed out",
    "connection timed out", "timed out after", "curl: (28)",
)


def _kali_timed_out(output: str) -> bool:
    low = (output or "").lower()
    return any(mk in low for mk in _KALI_TIMEOUT_MARKERS)


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

    # Layer 3 — timeout-as-signal: surface a hung request as a LEAD instead of letting
    # the agent silently burn minutes waiting (and re-waiting) on it.
    timed_out = _kali_timed_out(raw_output)
    if timed_out:
        raw_output = (
            "⏱ TIMEOUT SIGNAL — a request/command here hit its time bound. This is a LEAD, not just a "
            "slow call: it can indicate time-based-blind SQLi/cmdi, an SSRF connecting outbound, or a "
            "genuinely slow endpoint. Do NOT just re-run and wait — confirm with a CONTROLLED time-based "
            "probe (a known sleep delta) or bound the request with --max-time (curl is already capped at "
            "30s by default in the container).\n\n" + raw_output
        )

    result = _clip(raw_output, 8_000)
    cost_tracker.finish(call_id, result)
    log.tool_result("kali", result)

    from mcp_server.scan_engine import wrap
    tool_key = "kali_sqlmap" if command.strip().startswith("sqlmap") else "kali"
    return _inject_qa_alerts(wrap(
        tool_key, raw_output, {"command": command, "_tool": tool_key, "timed_out": timed_out}))
