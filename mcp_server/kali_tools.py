"""
Consolidated kali tool — replaces the kali_exec part of exploitation.py
"""
import re
import shlex
import uuid

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


_WHOLE_COMMAND_TIMEOUT = "[partial — command timed out]"

# Tools whose own request timing out is a time-based LEAD. Matched as a command word
# anywhere in the (possibly piped/looped) command line.
_NETWORK_PROBE_RE = re.compile(
    r"(?:^|[\s;|&(`'\"])(?:curl|wget|sqlmap|commix|httpx|nc|ncat|netcat|http|nuclei|ffuf|"
    r"gobuster|wfuzz|nikto|ghauri|xsstrike|dalfox)(?=$|[\s;|&)])")

_JOB_ID_RE = re.compile(r"^[a-f0-9]{8,32}$")


def _kali_timed_out(output: str) -> bool:
    low = (output or "").lower()
    return any(mk in low for mk in _KALI_TIMEOUT_MARKERS)


def _is_network_probe(command: str) -> bool:
    return bool(_NETWORK_PROBE_RE.search(command or ""))


def _classify_timeout(command: str, output: str) -> str | None:
    """'command' — the whole command exceeded kali()'s timeout (NOT a lead: a long
    batch job, just partial output); 'probe' — a network probe's own request timed
    out (a time-based LEAD); None — no timeout."""
    if _WHOLE_COMMAND_TIMEOUT in (output or ""):
        return "command"
    if _kali_timed_out(output) and _is_network_probe(command):
        return "probe"
    return None


async def _stage_files(files: dict) -> str | None:
    """Copy {container_path: artifact_id | {"content": str}} into the container."""
    from tools import kali_runner
    from mcp_server.scan_engine.artifacts import read_artifact_raw
    for path, src in (files or {}).items():
        if isinstance(src, dict):
            content = src.get("content")
            if content is None and src.get("artifact_id"):
                content = read_artifact_raw(str(src["artifact_id"]))
        else:
            content = read_artifact_raw(str(src))
        if content is None:
            return f"files[{path!r}]: artifact not found / no content — pass an artifact_id or {{'content': ...}}"
        err = await kali_runner.put_file(str(path), content.encode("utf-8", "surrogatepass"))
        if err:
            return err
    return None


@mcp.tool()
async def kali(command: str = "", timeout: int = 600, files: dict | None = None,
               background: bool = False, job_id: str = "") -> str:
    """Run any command in the Kali container (auto-starts if needed).
    Hundreds of tools available: nikto, sqlmap, gobuster, hydra, testssl,
    enum4linux-ng, wapiti, sslscan, ssh-audit, theHarvester, dnsrecon, etc.

    timeout: seconds to wait for the command (default 600 = 10 min, max 7200).
    Increase for long-running tools — e.g. timeout=1200 for deep sqlmap/hydra runs.
    The command is killed and partial output returned if the timeout is exceeded.

    files: stage payloads in the container BEFORE the command runs —
      {"/tmp/payloads.txt": "<artifact_id>"} or {"/tmp/x.json": {"content": "..."}}.
      Session artifacts are also mounted read-only at /artifacts/<artifact_id>.txt.
    background: true → detach the command and return a job id immediately (for long
      batch jobs, e.g. a k/N runner). Poll with kali(job_id="<id>") → status
      (running | done rc=N) + output tail.
    """
    from tools import kali_runner

    stop = scan_session.check_limits(cost_tracker.get_summary())
    if stop:
        return stop

    if job_id:
        if not _JOB_ID_RE.match(job_id):
            return f"invalid job_id '{job_id}'"
        _record("kali")
        return await kali_runner.exec_command(kali_runner.poll_command(job_id), timeout=30)
    if not command.strip():
        return "kali() requires command= (or job_id= to poll a background job)"

    _record("kali")
    log.tool_call("kali", {"command": command, "timeout": timeout,
                           "files": sorted(files or {}), "background": background})
    if files:
        err = await _stage_files(files)
        if err:
            return f"Error staging files: {err}"
    if background:
        jid = uuid.uuid4().hex[:12]
        out = await kali_runner.exec_command(kali_runner.background_command(command, jid), timeout=30)
        log_f, _ = kali_runner.job_paths(jid)
        return (f"{out}\njob_id={jid} — poll with kali(job_id={shlex.quote(jid)}); "
                f"output → {log_f}")

    call_id = cost_tracker.start("kali")
    raw_output = await kali_runner.exec_command(command, timeout=timeout)
    log.tool_result_verbose("kali", raw_output, "")

    # Layer 3 — timeout-as-signal: surface a hung request as a LEAD instead of letting
    # the agent silently burn minutes waiting (and re-waiting) on it. Only when a
    # network probe's own request timed out — a whole batch job exceeding kali()'s
    # timeout is not a time-based-blind signal, just partial output.
    timeout_kind = _classify_timeout(command, raw_output)
    timed_out = timeout_kind is not None
    if timeout_kind == "command":
        raw_output = (
            f"⏱ command exceeded timeout={timeout}s — output below is PARTIAL. For long batch "
            "jobs use kali(command=..., background=true) and poll with kali(job_id=...), or "
            "raise timeout (max 7200).\n\n" + raw_output
        )
    elif timeout_kind == "probe":
        raw_output = (
            "⏱ TIMEOUT SIGNAL — a network request here hit its own time bound. This is a LEAD, not just a "
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
