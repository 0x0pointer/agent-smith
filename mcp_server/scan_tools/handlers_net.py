"""Network / web recon handlers: nmap, naabu, subfinder, httpx, nuclei, ffuf."""
import shlex

from core import cost as cost_tracker
from core import logger as log
from mcp_server._app import _clip, _record, _run
from ._common import _strip_scheme


async def _handle_nmap(target, flags, options):
    _record("nmap")
    raw = await _run("nmap", host=_strip_scheme(target), ports=options.get("ports", "top-1000"), flags=flags)
    from mcp_server.scan_engine import wrap
    return wrap("nmap", raw, {"host": _strip_scheme(target)})


async def _handle_naabu(target, flags, options):
    _record("naabu")
    raw = await _run("naabu", host=_strip_scheme(target), ports=options.get("ports", "top-100"), flags=flags)
    from mcp_server.scan_engine import wrap
    return wrap("naabu", raw, {"host": _strip_scheme(target)})


async def _handle_subfinder(target, flags, options):
    _record("subfinder")
    raw = await _run("subfinder", domain=_strip_scheme(target), flags=flags)
    from mcp_server.scan_engine import wrap
    return wrap("subfinder", raw, {"domain": _strip_scheme(target)})


async def _handle_httpx(target, flags, options):
    _record("httpx")
    raw = await _run("httpx", url=target, flags=flags)
    if options.get("_raw"):
        return raw
    from mcp_server.scan_engine import wrap
    return wrap("httpx", raw, {"url": target})


async def _handle_nuclei(target, flags, options):
    _record("nuclei")
    if "-rate-limit" not in flags:
        flags = f"-rate-limit 50 {flags}".strip()
    raw = await _run(
        "nuclei", url=target,
        templates=options.get("templates", "cve,exposure,misconfig,default-login"),
        flags=flags,
    )
    from mcp_server.scan_engine import wrap
    return wrap("nuclei", raw, {"url": target})


def _build_ffuf_cmd(
    target: str,
    wordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt",
    extensions: str = "",
    flags: str = "",
) -> list[str]:
    """Build the ffuf command parts. Pure function — no side effects, easy to test."""
    fuzz_url = f"{target.rstrip('/')}/FUZZ"
    # Resolve a bare wordlist name (e.g. "common.txt" — the docs' wordlist=common.txt
    # shorthand) to the seclists Web-Content dir. A relative name isn't present at the
    # container CWD, so ffuf would error "wordlist not found" and dump its full usage
    # instead of fuzzing.
    if "/" not in wordlist:
        wordlist = f"/usr/share/seclists/Discovery/Web-Content/{wordlist}"
    if "-rate" not in flags:
        flags = f"-rate 50 {flags}".strip()
    cmd_parts = ["ffuf", "-u", fuzz_url, "-w", wordlist, "-of", "json", "-s"]
    if extensions:
        cmd_parts += ["-e", extensions]
    if flags:
        cmd_parts += shlex.split(flags)
    return cmd_parts


async def _handle_ffuf(target, flags, options):
    from tools import kali_runner

    wordlist = options.get("wordlist", "/usr/share/seclists/Discovery/Web-Content/common.txt")
    extensions = options.get("extensions", "")
    cmd = " ".join(_build_ffuf_cmd(target, wordlist, extensions, flags))

    log.tool_call("ffuf", {"url": target, "wordlist": wordlist, "extensions": extensions, "flags": flags})
    call_id = cost_tracker.start("ffuf")
    raw = _clip(await kali_runner.exec_command(cmd, timeout=900), 8_000)
    _record("ffuf")
    cost_tracker.finish(call_id, raw)
    log.tool_result("ffuf", raw)
    from mcp_server.scan_engine import wrap
    return wrap("ffuf", raw, {"url": target})
