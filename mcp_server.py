"""
Pentest Agent MCP Server
========================
Thin registration layer — @mcp.tool() wrappers only.
All logic lives in dedicated modules:

  tools/kali_runner.py  — Kali container lifecycle + exec
  tools/findings.py     — findings.json persistence
  tools/dashboard.py    — local HTTP server for dashboard.html
  logger.py             — session activity log (logs/session_*.log)

Register with Claude Code (run once):
  claude mcp add pentest-agent -- poetry -C ~/Desktop/pentest-agent-lightweight run python mcp_server.py
"""
from __future__ import annotations

import asyncio
import json
import os

from mcp.server.fastmcp import FastMCP

import cost_tracker
import scan_session
import logger as log
from tools import REGISTRY
from tools.docker_runner import run_container
from tools import kali_runner
from tools import findings as findings_store
from tools import dashboard

mcp = FastMCP("pentest-agent")

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _clip(text: str, limit: int = 12_000) -> str:
    """
    Smart head+tail truncation.
    Keeps the first 2/3 and last 1/3 of the limit, dropping the middle.
    Many security tools (sqlmap, nikto, nuclei) emit the most important
    results at the END, so preserving the tail is critical.
    """
    if len(text) <= limit:
        return text
    head    = (limit * 2) // 3
    tail    = limit - head
    dropped = len(text) - head - tail
    return text[:head] + f"\n\n[… {dropped:,} chars clipped …]\n\n" + text[-tail:]


async def _run(name: str, **kwargs) -> str:
    """Run a lightweight Docker tool from the registry, with logging and cost tracking."""
    stop = scan_session.check_limits(cost_tracker.get_summary())
    if stop:
        return stop
    log.tool_call(name, kwargs)
    call_id = cost_tracker.start(name)          # dashboard shows "running" immediately
    tool  = REGISTRY[name]
    args  = tool.build_args(**kwargs)
    mount = os.environ.get("PENTEST_TARGET_PATH", os.getcwd()) if tool.needs_mount else None
    stdout, stderr, _ = await run_container(
        tool.image, args, timeout=tool.default_timeout, mount_path=mount
    )
    if tool.parser is None:
        result = _clip(stdout or stderr, tool.max_output)
    else:
        parsed = tool.parser(stdout, stderr)
        result = json.dumps({"findings": parsed, "raw": _clip(stdout, tool.max_output)}, indent=2)
    cost_tracker.finish(call_id, result)        # dashboard updates with token count
    log.tool_result(name, result)
    return result


# ---------------------------------------------------------------------------
# Lightweight Docker tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def run_nmap(host: str, ports: str = "top-1000", flags: str = "") -> str:
    """Port scanner. Args: host, ports (top-1000 | full | '80,443'), flags."""
    return await _run("nmap", host=host, ports=ports, flags=flags)


@mcp.tool()
async def run_naabu(host: str, ports: str = "top-100", flags: str = "") -> str:
    """Fast port scanner. Args: host, ports (top-100 | full | '1-10000'), flags."""
    return await _run("naabu", host=host, ports=ports, flags=flags)


@mcp.tool()
async def run_httpx(url: str, flags: str = "") -> str:
    """HTTP probe — status, title, tech stack. Args: url, flags."""
    return await _run("httpx", url=url, flags=flags)


@mcp.tool()
async def run_nuclei(
    url: str,
    templates: str = "default-logins,cves,exposures,misconfiguration",
    flags: str = "",
) -> str:
    """Template-based vulnerability scanner. Args: url, templates, flags."""
    return await _run("nuclei", url=url, templates=templates, flags=flags)


@mcp.tool()
async def run_ffuf(
    url: str,
    wordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt",
    extensions: str = "",
    flags: str = "",
) -> str:
    """Web directory/file fuzzer. Args: url, wordlist, extensions, flags."""
    return await _run("ffuf", url=url, wordlist=wordlist, extensions=extensions, flags=flags)


@mcp.tool()
async def run_subfinder(domain: str, flags: str = "") -> str:
    """Subdomain discovery. Args: domain, flags."""
    return await _run("subfinder", domain=domain, flags=flags)


@mcp.tool()
async def run_semgrep(path: str = "/target", flags: str = "") -> str:
    """Static code analysis on mounted codebase. Args: path, flags."""
    return await _run("semgrep", path=path, flags=flags)


@mcp.tool()
async def run_trufflehog(path: str = "/target", flags: str = "") -> str:
    """Secret/credential scanner on mounted codebase. Args: path, flags."""
    return await _run("trufflehog", path=path, flags=flags)


# ---------------------------------------------------------------------------
# Kali — full toolset via the persistent kali-mcp container
# ---------------------------------------------------------------------------

@mcp.tool()
async def kali_exec(command: str, timeout: int = 120) -> str:
    """
    Run any Kali Linux tool via the persistent kali-mcp container.
    The container auto-starts on first call and stays running until stop_kali is called.
    Build the image once: docker build -t pentest-agent/kali-mcp ./tools/kali/

    Available (non-exhaustive): nmap, masscan, nikto, sqlmap, gobuster, feroxbuster,
    dirb, wfuzz, hydra, medusa, testssl, sslscan, enum4linux-ng, nxc, theHarvester,
    dnsrecon, dnsenum, fierce, amass, dnstwist, whatweb, wafw00f, wapiti, commix,
    xsser, ssh-audit, snmpwalk, smtp-user-enum, ike-scan, ldapdomaindump, kerbrute,
    certipy, eyewitness, searchsploit, ...

    Examples:
      kali_exec("nikto -h http://target.com")
      kali_exec("sqlmap -u 'http://target.com/?id=1' --batch --dbs")
      kali_exec("testssl --quiet target.com:443")
      kali_exec("enum4linux-ng -A target.com")
    """
    stop = scan_session.check_limits(cost_tracker.get_summary())
    if stop:
        return stop
    log.tool_call("kali_exec", {"command": command, "timeout": timeout})
    call_id = cost_tracker.start("kali_exec")
    result  = _clip(await kali_runner.exec_command(command, timeout=timeout), 15_000)
    cost_tracker.finish(call_id, result)
    log.tool_result("kali_exec", result)
    return result


@mcp.tool()
async def start_kali() -> str:
    """
    Explicitly start the Kali container and wait for it to be ready.
    kali_exec does this automatically, but call this first to pre-warm
    the container before a scan session.
    """
    log.tool_call("start_kali", {})
    ok, msg = await kali_runner.ensure_running()
    result = (
        f"Kali container ready at {kali_runner.KALI_API} ({msg})"
        if ok else f"Failed to start Kali container: {msg}"
    )
    log.tool_result("start_kali", result)
    return result


@mcp.tool()
async def stop_kali() -> str:
    """Stop and remove the Kali container. Call this to clean up after a session."""
    log.tool_call("stop_kali", {})
    result = await kali_runner.stop()
    log.tool_result("stop_kali", result)
    return result


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

@mcp.tool()
async def http_request(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    body: str | None = None,
    poc: bool = False,
    burp_proxy: str = "http://127.0.0.1:8080",
) -> str:
    """Raw HTTP request for manual probing or PoC verification.

    Set poc=True only for confirmed, report-worthy exploits — the request will
    be routed through Burp Suite (burp_proxy) so it lands in HTTP History ready
    for Repeater. Do NOT set poc=True for recon or speculative probes.
    """
    import aiohttp
    log.tool_call("http_request", {"url": url, "method": method, "poc": poc})
    call_id = cost_tracker.start("http_request")
    proxy = burp_proxy if poc else None
    try:
        async with aiohttp.ClientSession() as session:
            async with session.request(
                method, url,
                headers=headers or {},
                data=body,
                timeout=aiohttp.ClientTimeout(total=30),
                ssl=False,
                proxy=proxy,
            ) as resp:
                text   = await resp.text()
                result = json.dumps(
                    {
                        "status":    resp.status,
                        "headers":   dict(resp.headers),
                        "body":      text[:8_000],
                        "burp":      f"request sent through {burp_proxy}" if poc else "not routed through Burp",
                    },
                    indent=2,
                )
    except Exception as exc:
        result = json.dumps({"error": str(exc), "hint": "If poc=True, make sure Burp Suite is open with proxy listener on " + burp_proxy})
    cost_tracker.finish(call_id, result)
    log.tool_result("http_request", result)
    return result


@mcp.tool()
async def save_poc(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    body: str | None = None,
    title: str = "poc",
    notes: str = "",
) -> str:
    """Save a confirmed PoC as a raw HTTP request file that can be imported into Burp Repeater.

    Only call this for confirmed, report-worthy exploits. The file is written to
    the pocs/ directory next to mcp_server.py and named with a timestamp + title.
    Open Burp Repeater → Paste from file (or copy-paste the content) to load it.
    """
    from urllib.parse import urlparse
    import datetime

    parsed   = urlparse(url)
    host     = parsed.netloc
    path     = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    # Build raw HTTP request
    lines = [f"{method.upper()} {path} HTTP/1.1", f"Host: {host}"]
    for k, v in (headers or {}).items():
        lines.append(f"{k}: {v}")
    if body:
        lines.append(f"Content-Length: {len(body.encode())}")
    lines.append("")
    if body:
        lines.append(body)

    raw = "\r\n".join(lines)

    # Write to pocs/
    pocs_dir = os.path.join(os.path.dirname(__file__), "pocs")
    os.makedirs(pocs_dir, exist_ok=True)
    safe_title = "".join(c if c.isalnum() or c in "-_" else "_" for c in title)
    timestamp  = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename   = f"{timestamp}_{safe_title}.http"
    filepath   = os.path.join(pocs_dir, filename)

    with open(filepath, "w") as f:
        if notes:
            f.write(f"# {notes}\n\n")
        f.write(raw)

    result = json.dumps({"saved": filepath, "hint": "Open Burp Repeater → click the Paste icon (or Edit > Paste) to load this request"})
    log.tool_result("save_poc", result)
    return result


@mcp.tool()
async def set_codebase_target(path: str) -> str:
    """Set the local codebase path that run_semgrep and run_trufflehog will mount."""
    abs_path = os.path.abspath(path)
    if not os.path.isdir(abs_path):
        return f"Error: '{abs_path}' is not a directory"
    os.environ["PENTEST_TARGET_PATH"] = abs_path
    log.note(f"codebase target → {abs_path}")
    return f"Codebase target set to: {abs_path}"


@mcp.tool()
async def pull_images() -> str:
    """
    Pull all lightweight tool images from Docker Hub.
    Run once on first setup so scans don't stall on image downloads.
    The Kali image is not pulled here — build it separately:
      docker build -t pentest-agent/kali-mcp ./tools/kali/
    """
    log.tool_call("pull_images", {})
    images = [tool.image for tool in REGISTRY.values() if not tool.needs_mount]
    seen: set[str] = set()
    unique = [img for img in images if not (img in seen or seen.add(img))]  # type: ignore[func-returns-value]
    lines: list[str] = []
    for image in unique:
        proc = await asyncio.create_subprocess_exec(
            "docker", "pull", image,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await proc.communicate()
        status = "ok" if proc.returncode == 0 else "FAILED"
        lines.append(f"[{status}] {image}")
    result = "\n".join(lines)
    log.tool_result("pull_images", result)
    return result


# ---------------------------------------------------------------------------
# Findings dashboard
# ---------------------------------------------------------------------------

@mcp.tool()
async def report_finding(
    title:       str,
    severity:    str,
    target:      str,
    description: str,
    evidence:    str,
    tool_used:   str = "",
    cve:         str = "",
) -> str:
    """
    Log a confirmed vulnerability to findings.json (shown in the live dashboard).
    Call this whenever you are confident a real vulnerability exists.

    severity : critical | high | medium | low | info
    evidence : raw tool output, HTTP request/response, or proof of exploitability
    """
    severity = severity.lower()
    if severity not in ("critical", "high", "medium", "low", "info"):
        return f"Invalid severity '{severity}'. Use: critical, high, medium, low, info"
    await findings_store.add_finding(
        title=title, severity=severity, target=target,
        description=description, evidence=evidence,
        tool_used=tool_used, cve=cve,
    )
    log.finding(severity, title, target)
    return f"Finding logged: [{severity.upper()}] {title}"


@mcp.tool()
async def report_diagram(title: str, mermaid: str) -> str:
    """
    Save a Mermaid architecture/network diagram to findings.json.

    title   : short label, e.g. "Network topology" or "Web app data flow"
    mermaid : valid Mermaid source, e.g.:
                graph TD
                  Internet --> WAF
                  WAF --> WebServer
                  WebServer --> DB[(MySQL)]
    """
    await findings_store.add_diagram(title=title, mermaid=mermaid)
    log.diagram(title)
    return f"Diagram saved: {title}"


@mcp.tool()
async def start_dashboard(port: int = 8080) -> str:
    """Serve dashboard.html at http://localhost:PORT/dashboard.html"""
    log.tool_call("start_dashboard", {"port": port})
    url = await dashboard.serve(port)
    log.tool_result("start_dashboard", url)
    return f"Dashboard running — open {url}"


# ---------------------------------------------------------------------------
# Scan session — scope, depth, and hard limits
# ---------------------------------------------------------------------------

@mcp.tool()
async def start_scan(
    target:           str,
    depth:            str        = "standard",
    scope:            list[str]  | None = None,
    out_of_scope:     list[str]  | None = None,
    max_cost_usd:     float | None = None,
    max_time_minutes: int   | None = None,
    max_tool_calls:   int   | None = None,
) -> str:
    """
    Initialise a scan session with defined scope and hard limits.
    ALWAYS call this before any other tool — it sets the guardrails that
    prevent the scan from running forever or exceeding the budget.

    depth presets (override any limit with the explicit params):
      recon    — port scan + subdomains + HTTP probe only     ($0.10 / 15 min / 10 calls)
      standard — recon + nuclei + dir fuzzing                 ($0.50 / 45 min / 25 calls)
      thorough — standard + full Kali toolchain               ($2.00 / 120 min / 60 calls)

    scope        : list of in-scope hosts/domains (defaults to [target])
    out_of_scope : explicit exclusions Claude must not touch
    """
    cfg = scan_session.start(
        target=target, depth=depth,
        scope=scope, out_of_scope=out_of_scope,
        max_cost_usd=max_cost_usd,
        max_time_minutes=max_time_minutes,
        max_tool_calls=max_tool_calls,
    )
    log.note(
        f"Scan started — target={target}  depth={depth}  "
        f"limits: ${cfg['limits']['max_cost_usd']} / "
        f"{cfg['limits']['max_time_minutes']}min / "
        f"{cfg['limits']['max_tool_calls']} calls"
    )
    lim = cfg["limits"]
    lines = [
        f"Scan session started.",
        f"  Target      : {target}",
        f"  Depth       : {cfg['depth_label']} — {cfg['description']}",
        f"  Scope       : {', '.join(cfg['scope'])}",
    ]
    if cfg["out_of_scope"]:
        lines.append(f"  Out-of-scope: {', '.join(cfg['out_of_scope'])}")
    lines += [
        f"  Cost limit  : ${lim['max_cost_usd']}",
        f"  Time limit  : {lim['max_time_minutes']} min",
        f"  Call limit  : {lim['max_tool_calls']} tool calls",
        f"",
        f"Proceed with the {depth} scan workflow.",
        f"Stop and call complete_scan() when finished or when a limit is hit.",
    ]
    return "\n".join(lines)


@mcp.tool()
async def complete_scan(notes: str = "") -> str:
    """
    Mark the scan as complete. Call this when:
      - all planned tools have run, OR
      - a limit was hit and you have written the final report.
    notes : brief summary of what was found / why stopping.
    """
    cfg = scan_session.complete(notes)
    log.note(f"Scan complete — {notes}")
    status = cfg.get("status", "complete")
    return f"Scan marked {status}. session.json updated."


# ---------------------------------------------------------------------------
# Reasoning log
# ---------------------------------------------------------------------------

@mcp.tool()
async def log_note(message: str) -> str:
    """
    Write a reasoning note, decision, or observation to the session log.
    Use this to record why you chose a particular tool or approach,
    what you noticed, or what you plan to do next.
    """
    log.note(message)
    return "Logged."


if __name__ == "__main__":
    mcp.run()
