"""
Web scanning tools
==================
HTTP probing, vulnerability scanning, directory fuzzing, and crawling.
"""
import shlex

from core import cost as cost_tracker
from core import logger as log
from core import session as scan_session
from mcp_server._app import mcp, _clip, _record, _run


@mcp.tool()
async def run_httpx(url: str, flags: str = "") -> str:
    """HTTP probe — status, title, tech stack. Args: url, flags."""
    _record("httpx")
    return await _run("httpx", url=url, flags=flags)


@mcp.tool()
async def run_nuclei(
    url:       str,
    templates: str = "cve,exposure,misconfig,default-login",
    flags:     str = "",
) -> str:
    """Template-based vulnerability scanner.
    templates: comma-separated tag names (cve, exposure, misconfig, default-login, takeover, tech).
    First run downloads templates (~1-2 min); subsequent runs use the cached copy.
    """
    return await _run("nuclei", url=url, templates=templates, flags=flags)


@mcp.tool()
async def run_ffuf(
    url:      str,
    wordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt",
    extensions: str = "",
    flags:    str = "",
) -> str:
    """Web directory/file fuzzer. Runs ffuf inside the Kali container.
    url: base URL without FUZZ (e.g. http://target.com) — /FUZZ is appended automatically.
    wordlist: path inside the Kali container (seclists are pre-installed).
    extensions: comma-separated (e.g. .php,.html,.bak).
    flags: extra ffuf flags (e.g. '-mc 200,301 -fc 404 -t 50').
    """
    from tools import kali_runner

    stop = scan_session.check_limits(cost_tracker.get_summary())
    if stop:
        return stop

    fuzz_url  = f"{url.rstrip('/')}/FUZZ"
    cmd_parts = ["ffuf", "-u", fuzz_url, "-w", wordlist, "-of", "json", "-s"]
    if extensions:
        cmd_parts += ["-e", extensions]
    if flags:
        cmd_parts += flags.split()
    cmd = " ".join(cmd_parts)

    log.tool_call("ffuf", {"url": url, "wordlist": wordlist, "extensions": extensions, "flags": flags})
    call_id = cost_tracker.start("ffuf")
    result  = _clip(await kali_runner.exec_command(cmd, timeout=300), 8_000)
    cost_tracker.finish(call_id, result)
    log.tool_result("ffuf", result)
    return result


@mcp.tool()
async def run_spider(
    url:   str,
    depth: int = 3,
    mode:  str = "fast",
    flags: str = "",
) -> str:
    """Spider / crawl a web application to discover all reachable endpoints and pages.

    mode:
      fast  — katana (ProjectDiscovery crawler, already in kali). Best for APIs and
              standard HTML apps. Very fast.
      deep  — ZAP baseline spider (zaproxy). Includes AJAX/JS crawling and passive
              scanning. Slower (~2–5 min) but finds JS-rendered routes.

    depth: crawl depth (default 3).
    flags: extra flags passed to the underlying tool.
    """
    from tools import kali_runner

    stop = scan_session.check_limits(cost_tracker.get_summary())
    if stop:
        return stop

    log.tool_call("spider", {"url": url, "depth": depth, "mode": mode, "flags": flags})
    call_id    = cost_tracker.start("spider")
    safe_url   = shlex.quote(url)
    safe_depth = str(max(1, depth))
    safe_flags = shlex.join(shlex.split(flags)) if flags else ""

    if mode == "deep":
        base = f"zap-baseline.py -t {safe_url} -m {safe_depth} -I"
        if safe_flags:
            base += f" {safe_flags}"
        cmd = f"{base} 2>&1 | grep -E '(PASS|WARN|FAIL|INFO|https?://)' | head -200"
    else:
        cmd = f"katana -u {safe_url} -d {safe_depth} -silent -no-color"
        if safe_flags:
            cmd += f" {safe_flags}"

    result = _clip(await kali_runner.exec_command(cmd, timeout=360), 12_000)
    _record("spider")
    cost_tracker.finish(call_id, result)
    log.tool_result("spider", result)
    return result
