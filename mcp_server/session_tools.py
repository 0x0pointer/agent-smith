"""
Consolidated session tool — replaces scan.py and infra.py
"""
import asyncio
import json
import os

from core import cost as cost_tracker
from core import findings as findings_store
from core import logger as log
from core import session as scan_session
from mcp_server._app import mcp, _session_tools_called


@mcp.tool()
async def session(action: str, options: dict | None = None) -> str:
    """Scan lifecycle and infrastructure management.

    action  : start | complete | status | start_kali | stop_kali | pull_images | set_codebase

    start options:
      target, depth=standard (recon|standard|thorough), scope=[],
      out_of_scope=[], max_cost_usd=, max_time_minutes=, max_tool_calls=

    complete options:
      notes=

    status: returns current scan state (target, tools run, findings, cost)

    set_codebase options:
      path= (absolute path to local codebase)

    start_kali, stop_kali, pull_images: no options needed
    """
    opts = options or {}

    if action == "start":
        return _do_start(opts)
    elif action == "complete":
        return _do_complete(opts)
    elif action == "status":
        return _do_status()
    elif action == "start_kali":
        return await _do_start_kali()
    elif action == "stop_kali":
        return await _do_stop_kali()
    elif action == "pull_images":
        return await _do_pull_images()
    elif action == "set_codebase":
        return _do_set_codebase(opts)
    else:
        return f"Unknown action '{action}'. Use: start, complete, status, start_kali, stop_kali, pull_images, set_codebase"


def _do_start(opts):
    _session_tools_called.clear()
    target = opts.get("target", "")
    depth = opts.get("depth", "standard")
    cfg = scan_session.start(
        target=target, depth=depth,
        scope=opts.get("scope"),
        out_of_scope=opts.get("out_of_scope"),
        max_cost_usd=opts.get("max_cost_usd"),
        max_time_minutes=opts.get("max_time_minutes"),
        max_tool_calls=opts.get("max_tool_calls"),
    )
    lim = cfg["limits"]
    log.note(
        f"Scan started — target={target}  depth={depth}  "
        f"limits: ${lim['max_cost_usd']} / {lim['max_time_minutes']}min / {lim['max_tool_calls']} calls"
    )
    lines = [
        "Scan session started.",
        f"  Target      : {target}",
        f"  Depth       : {cfg['depth_label']} — {cfg['description']}",
        f"  Scope       : {', '.join(cfg['scope'])}",
    ]
    if cfg["out_of_scope"]:
        lines.append(f"  Out-of-scope: {', '.join(cfg['out_of_scope'])}")
    call_limit_str = f"{lim['max_tool_calls']} tool calls" if lim['max_tool_calls'] > 0 else "unlimited"
    lines += [
        f"  Cost limit  : ${lim['max_cost_usd']}",
        f"  Time limit  : {lim['max_time_minutes']} min",
        f"  Call limit  : {call_limit_str}",
        "",
        f"Proceed with the {depth} scan workflow.",
        "Stop and call session(action='complete') when finished or when a limit is hit.",
    ]
    return "\n".join(lines)


def _do_complete(opts):
    notes = opts.get("notes", "")
    blockers: list[str] = []

    data = findings_store._load()

    if not data.get("diagrams"):
        blockers.append(
            "NO DIAGRAM: call report(action='diagram') with a Mermaid diagram of the "
            "application architecture before completing."
        )

    if "httpx" in _session_tools_called and "spider" not in _session_tools_called:
        blockers.append(
            "NO SPIDER: httpx confirmed web targets but spider was never called. "
            "Run scan(tool='spider', target=url) to crawl the application before completing."
        )

    repo_root = os.path.dirname(os.path.dirname(__file__))
    pocs_dir = os.path.join(repo_root, "pocs")
    poc_files = set(os.listdir(pocs_dir)) if os.path.isdir(pocs_dir) else set()
    high_findings = [
        f for f in data.get("findings", [])
        if f.get("severity") in ("high", "critical")
    ]
    if high_findings and not poc_files:
        titles = ", ".join(f["title"] for f in high_findings)
        blockers.append(
            f"NO POC FILES: {len(high_findings)} high/critical finding(s) have no Burp PoC. "
            f"Call http(action='request', poc=true) + http(action='save_poc') for each: {titles}"
        )

    if blockers:
        msg = "complete BLOCKED — fix the following first:\n\n"
        msg += "\n\n".join(f"  [{i+1}] {b}" for i, b in enumerate(blockers))
        log.note(f"complete blocked: {'; '.join(blockers)}")
        return msg

    cfg = scan_session.complete(notes)
    status = cfg.get("status", "complete")
    log.note(f"Scan complete — {notes}")
    return f"Scan marked {status}. session.json updated."


def _do_status():
    summary = cost_tracker.get_summary()
    data = findings_store._load()
    current = scan_session.get() or {}
    return json.dumps({
        "target": current.get("target", ""),
        "tools_run": sorted(_session_tools_called),
        "findings_count": len(data.get("findings", [])),
        "diagrams_count": len(data.get("diagrams", [])),
        "cost_usd": summary.get("est_cost_usd", 0),
        "tool_calls": summary.get("tool_calls_total", 0),
    }, indent=2)


async def _do_start_kali():
    from tools import kali_runner
    log.tool_call("start_kali", {})
    ok, msg = await kali_runner.ensure_running()
    result = (
        f"Kali container ready at {kali_runner.KALI_API} ({msg})"
        if ok else f"Failed to start Kali container: {msg}"
    )
    log.tool_result("start_kali", result)
    return result


async def _do_stop_kali():
    from tools import kali_runner
    log.tool_call("stop_kali", {})
    result = await kali_runner.stop()
    log.tool_result("stop_kali", result)
    return result


async def _do_pull_images():
    from tools import REGISTRY
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
        _, _ = await proc.communicate()
        status = "ok" if proc.returncode == 0 else "FAILED"
        lines.append(f"[{status}] {image}")
    result = "\n".join(lines)
    log.tool_result("pull_images", result)
    return result


def _do_set_codebase(opts):
    path = opts.get("path", "")
    abs_path = os.path.abspath(path)
    if not os.path.isdir(abs_path):
        return f"Error: '{abs_path}' is not a directory"
    os.environ["PENTEST_TARGET_PATH"] = abs_path
    log.note(f"codebase target set to {abs_path}")
    return f"Codebase target set to: {abs_path}"
