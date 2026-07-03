"""
Consolidated scan tool — replaces network.py, web.py, code_analysis.py, ai_red_team.py

Split into a package for the <300-lines-per-file convention. This facade keeps
the public import surface identical: `import mcp_server.scan_tools` still
registers the `@mcp.tool()` `scan` dispatcher, and every name previously
importable from the module is re-exported here.
"""
from core import cost as cost_tracker
from core import logger as log
from core import session as scan_session
from mcp_server._app import mcp, _ensure_dict

# ── Shared state + helpers (re-exported for consumers/tests) ────────────────────
from ._common import (
    _strip_scheme,
    _kali_target_url,
    _stage_file_cmd,
    _kali_scratch_dir,
    _ai_headers,
    _ai_auth_headers,
    _SPIDER_HARD_FAIL_SIGNALS,
    _spider_succeeded,
)
from .handlers_net import (
    _handle_nmap,
    _handle_naabu,
    _handle_subfinder,
    _handle_httpx,
    _handle_nuclei,
    _build_ffuf_cmd,
    _handle_ffuf,
)
from .spider import (
    _run_spider_thorough,
    _run_spider_fast,
    _handle_spider,
)
from .handlers_code import (
    _handle_semgrep,
    _handle_trufflehog,
    _handle_exec_sandbox,
)
from .handlers_ai import (
    _handle_fuzzyai,
    _load_role_confusion_payloads,
    _handle_pyrit,
    _handle_garak,
    _handle_promptfoo,
)
from .handlers_exploit import (
    _handle_metasploit,
)
from .handlers_mobile import (
    _handle_mobsf,
    _handle_mobsfscan,
)


_DISPATCH = {
    "nmap":        _handle_nmap,
    "naabu":       _handle_naabu,
    "subfinder":   _handle_subfinder,
    "httpx":       _handle_httpx,
    "nuclei":      _handle_nuclei,
    "ffuf":        _handle_ffuf,
    "spider":      _handle_spider,
    "semgrep":     _handle_semgrep,
    "trufflehog":  _handle_trufflehog,
    "mobsfscan":   _handle_mobsfscan,
    "mobsf":       _handle_mobsf,
    "fuzzyai":     _handle_fuzzyai,
    "pyrit":       _handle_pyrit,
    "garak":       _handle_garak,
    "promptfoo":   _handle_promptfoo,
    "metasploit":  _handle_metasploit,
    "exec_sandbox": _handle_exec_sandbox,
}


@mcp.tool()
async def scan(tool: str, target: str, flags: str = "", options: dict | str | None = None) -> str:
    """Run a security scanner.

    tool    : scanner name (see table)
    target  : URL, host, domain, or local path
    flags   : extra CLI flags (optional)
    options : tool-specific settings (optional dict)

    | tool       | target type | options (defaults)                                |
    |------------|-------------|---------------------------------------------------|
    | nmap       | host/IP     | ports=top-1000                                    |
    | naabu      | host/IP     | ports=top-100                                     |
    | subfinder  | domain      |                                                   |
    | httpx      | URL         |                                                   |
    | nuclei     | URL         | templates=cve,exposure,misconfig,default-login    |
    | ffuf       | URL         | wordlist=common.txt, extensions=                  |
    | spider     | URL         | depth=3, mode=fast|playwright, cookies={}, max_pages=200 |
    | semgrep    | path        |                                                   |
    | trufflehog | path        |                                                   |
    | exec_sandbox | path (codebase) | cmd= (required), setup=, image=python:3.11-slim, subdir=, timeout=180 — build/run white-box code in a network-isolated, caps-dropped sandbox to confirm a finding; returns an artifact_id |
    | fuzzyai    | URL         | attack=jailbreak, provider=openai, model=         |
    | pyrit      | URL         | attack=prompt_injection, objective=, max_turns=5, scorer=self_ask, provider=openai|anthropic|azure, body_key=message, body_template=, response_field=, headers={} |
    | garak      | URL         | probes=dan,encoding,..., body_key=message, method=post, response_field=, headers={} (REST generator config auto-generated; -G) |
    | promptfoo  | URL         | plugins=prompt-injection,..., attack_strategies=jailbreak,crescendo, body_key=prompt, response_field=, attacker_provider=, headers={} (config auto-generated; -c) |
    | metasploit | host/IP     | module=, payload=, rport=, lhost=, lport=4444     |
    """
    options = _ensure_dict(options) or {}

    # Auto-start session if model skipped session(action="start")
    current = scan_session.get()
    if not current or current.get("status") != "running":
        scan_session.start(target=target, depth="thorough")
        log.note(f"Auto-started session for target={target} (model skipped session start)")

    handler = _DISPATCH.get(tool)
    if not handler:
        return f"Unknown tool '{tool}'. Available: {', '.join(_DISPATCH)}"

    stop = scan_session.check_limits(cost_tracker.get_summary())
    if stop:
        return stop

    # Spider failure is NOT a runtime block on other tools. Other scanners
    # (nuclei, ffuf, kali sqlmap, http probes, etc.) can productively run
    # against the original target URL + endpoints already discovered by
    # httpx / naabu / subdomain enumeration, even while spider is retrying
    # or has given up. The spider failure is still recorded in
    # session.spider_failures + the generalised tool_failures registry
    # (Phase 4) so the QA agent surfaces it as a coverage warning, and
    # Phase 7's tool-class coverage gate still catches "web target but ffuf
    # never ran" at completion time.

    try:
        return await handler(target, flags, options)
    except BaseException as exc:
        err = f"[{tool} error: {type(exc).__name__}: {exc}]"
        log.tool_result(tool, err)
        if tool == "spider":
            current_retries = scan_session.get_spider_failures().get(target, {}).get("retry_count", 0)
            if current_retries >= scan_session.spider_max_retries():
                scan_session.clear_spider_failure(target)
                log.note(f"spider: failure-tracking released for {target} after {current_retries + 1} exception-based attempts")
            else:
                new_count = scan_session.record_spider_failure(target)
                log.note(f"spider: failure recorded (exception) for {target} (attempt {new_count})")
                err += (
                    "\n\n⚠️  SPIDER WARNING: Spider raised an exception. "
                    "Other scan tools can still run; matrix coverage will be narrower than a full crawl.\n"
                    "Recommended:\n"
                    "  1. If Kali is not running: session(action='start_kali')\n"
                    f"  2. Retry: scan(tool='spider', target='{target}')\n"
                    f"  (Failure tracking auto-releases after {scan_session.spider_max_retries()} retries.)"
                )
        return err
