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
from mcp_server._app import mcp, _ensure_dict, _session_tools_called


@mcp.tool()
async def session(action: str, options: dict | None = None) -> str:
    """Scan lifecycle and infrastructure management.

    action  : start | complete | status | recovery | set_skill | set_step | start_kali | stop_kali | start_metasploit | stop_metasploit | pull_images | set_codebase

    start options:
      target, depth=standard (recon|standard|thorough), scope=[],
      out_of_scope=[], max_cost_usd=, max_time_minutes=, max_tool_calls=, skill=

    complete options:
      notes=

    status: returns current scan state (target, tools run, findings, cost, skill)

    recovery: returns compact recovery brief after context compaction — resume step,
              in-progress cells with technique notes, pending escalation leads, action list

    set_skill options:
      skill= (name of the active skill, e.g. "pentester", "ai-redteam")

    set_step options:
      step= (current workflow step, e.g. "5_nuclei_scan")

    set_codebase options:
      path= (absolute path to local codebase)

    start_kali, stop_kali, start_metasploit, stop_metasploit, pull_images: no options needed
    """
    opts = _ensure_dict(options) or {}

    if action == "start":
        return _do_start(opts)
    elif action == "complete":
        return _do_complete(opts)
    elif action == "status":
        return _do_status()
    elif action == "set_skill":
        return _do_set_skill(opts)
    elif action == "set_step":
        return _do_set_step(opts)
    elif action == "start_kali":
        return await _do_start_kali()
    elif action == "stop_kali":
        return await _do_stop_kali()
    elif action == "start_metasploit":
        return await _do_start_metasploit()
    elif action == "stop_metasploit":
        return await _do_stop_metasploit()
    elif action == "pull_images":
        return await _do_pull_images()
    elif action == "set_codebase":
        return _do_set_codebase(opts)
    elif action == "recovery":
        return _do_recovery()
    else:
        return f"Unknown action '{action}'. Use: start, complete, status, recovery, set_skill, set_step, start_kali, stop_kali, start_metasploit, stop_metasploit, pull_images, set_codebase"


def _do_start(opts):
    _session_tools_called.clear()
    # Reset coverage matrix for new session (sync — just rewrites the file)
    from core.coverage import COVERAGE_FILE, _save as _cov_save
    from datetime import datetime, timezone
    _cov_save({
        "meta": {
            "created": datetime.now(timezone.utc).isoformat(),
            "target": "",
            "total_cells": 0, "tested": 0, "vulnerable": 0,
            "not_applicable": 0, "skipped": 0,
        },
        "endpoints": [],
        "matrix": [],
    })
    target = opts.get("target", "")
    depth = opts.get("depth", "standard")
    cfg = scan_session.start(
        target=target, depth=depth,
        scope=opts.get("scope"),
        out_of_scope=opts.get("out_of_scope"),
        max_cost_usd=opts.get("max_cost_usd"),
        max_time_minutes=opts.get("max_time_minutes"),
        max_tool_calls=opts.get("max_tool_calls"),
        skill=opts.get("skill"),
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

    # Coverage matrix completeness check (soft warning, not a blocker)
    from core.coverage import get_matrix
    cov = get_matrix()
    cov_meta = cov.get("meta", {})
    total = cov_meta.get("total_cells", 0)
    if total > 0:
        addressed = (
            cov_meta.get("tested", 0)
            + cov_meta.get("not_applicable", 0)
            + cov_meta.get("skipped", 0)
        )
        pct = (addressed / total) * 100
        if pct < 80:
            blockers.append(
                f"LOW COVERAGE: only {addressed}/{total} matrix cells addressed ({pct:.0f}%). "
                f"Review pending cells in the coverage matrix — test, skip with reason, or mark N/A."
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
    remaining = scan_session.remaining(summary) if current else {}
    # Merge in-memory + persisted tool tracking for resilience
    persisted_tools = set(current.get("tools_called", []))
    all_tools = sorted(_session_tools_called | persisted_tools)
    result = {
        "target": current.get("target", ""),
        "depth": current.get("depth", ""),
        "status": current.get("status", ""),
        "skill": current.get("skill"),
        "current_step": current.get("current_step"),
        "tools_run": all_tools,
        "findings_count": len(data.get("findings", [])),
        "diagrams_count": len(data.get("diagrams", [])),
        "cost_usd": summary.get("est_cost_usd", 0),
        "tool_calls": summary.get("tool_calls_total", 0),
    }
    # Coverage matrix summary
    from core.coverage import get_matrix
    cov = get_matrix()
    meta = cov.get("meta", {})
    result["coverage"] = {
        "total_cells": meta.get("total_cells", 0),
        "tested": meta.get("tested", 0),
        "vulnerable": meta.get("vulnerable", 0),
        "not_applicable": meta.get("not_applicable", 0),
        "skipped": meta.get("skipped", 0),
        "endpoints": len(cov.get("endpoints", [])),
    }
    if remaining:
        result["remaining"] = {
            "cost_usd": remaining.get("cost_remaining_usd", 0),
            "time_min": remaining.get("time_remaining_minutes", 0),
            "calls": remaining.get("calls_remaining", -1),
        }
    if current.get("skill") and current.get("status") == "running":
        step = current.get("current_step", "")
        step_msg = f" Resume at step: {step}." if step else ""
        result["_recovery_hint"] = (
            f"If you lost context, re-invoke the /{current['skill']} skill "
            f"to reload its workflow.{step_msg}"
        )
    return json.dumps(result, indent=2)


def _do_recovery():
    """Compact recovery brief — one call gives the agent everything to resume."""
    current = scan_session.get() or {}
    if not current or current.get("status") != "running":
        return json.dumps({"error": "No active scan session to recover."})

    summary = cost_tracker.get_summary()
    remaining = scan_session.remaining(summary)

    # Coverage matrix: in_progress and pending cells
    from core.coverage import get_matrix
    cov = get_matrix()
    meta = cov.get("meta", {})
    endpoints = cov.get("endpoints", [])
    ep_map = {ep["id"]: ep["path"] for ep in endpoints}

    in_progress_cells = [
        {
            "cell_id": c["id"],
            "endpoint": ep_map.get(c["endpoint_id"], "?"),
            "param": c["param"],
            "injection": c["injection_type"],
            "notes": c["notes"],
        }
        for c in cov.get("matrix", [])
        if c["status"] == "in_progress"
    ]

    pending_count = sum(1 for c in cov.get("matrix", []) if c["status"] == "pending")

    # Findings with pending escalation leads
    data = findings_store._load()
    pending_escalations = []
    for f in data.get("findings", []):
        leads = f.get("escalation_leads", [])
        pending = [l for l in leads if l.get("status") == "pending"]
        if pending:
            pending_escalations.append({
                "finding_id": f["id"],
                "title": f["title"],
                "pending_leads": [l["lead"] for l in pending],
            })

    # Determine resume step from tools_run
    step_tools = {
        "2": ["naabu", "subfinder"],
        "3": ["httpx"],
        "5": ["ffuf"],
        "6": ["spider"],
        "6a": [],  # web-exploit skill — check skill_history
        "8": ["nuclei"],
    }
    tools_run = set(_session_tools_called)
    resume_step = None
    for step, tools in step_tools.items():
        if step == "6a":
            if "web-exploit" not in current.get("skill_history", []):
                resume_step = "6a (chain /web-exploit with endpoint inventory)"
                break
        elif tools and not any(t in tools_run for t in tools):
            resume_step = f"{step} ({', '.join(tools)})"
            break
    if not resume_step:
        resume_step = "10+ (deep dives / reporting)"

    result = {
        "target": current.get("target", ""),
        "depth": current.get("depth", ""),
        "skill": current.get("skill"),
        "resume_from_step": resume_step,
        "tools_already_run": sorted(tools_run),
        "findings_count": len(data.get("findings", [])),
        "cost_usd": summary.get("est_cost_usd", 0),
        "remaining": remaining,
        "coverage_in_progress": in_progress_cells,
        "coverage_pending_cells": pending_count,
        "coverage_tested": meta.get("tested", 0),
        "pending_escalations": pending_escalations,
        "action_required": [],
    }

    # Build action list
    if in_progress_cells:
        result["action_required"].append(
            f"Resume {len(in_progress_cells)} in-progress test cell(s) — read their notes for technique state"
        )
    if pending_escalations:
        result["action_required"].append(
            f"Follow up on {len(pending_escalations)} finding(s) with pending escalation leads"
        )
    if resume_step.startswith("6a"):
        result["action_required"].append(
            "Chain /web-exploit — endpoint inventory exists but systematic testing not started"
        )
    if not result["action_required"]:
        result["action_required"].append(f"Resume from step {resume_step}")

    return json.dumps(result, indent=2)


def _do_set_skill(opts):
    skill_name = opts.get("skill", "")
    if not skill_name:
        return "Error: 'skill' option is required"
    result = scan_session.set_skill(skill_name)
    if result is None:
        return "No active running session — cannot set skill."
    log.note(f"Active skill changed to: {skill_name}")
    return f"Active skill set to: {skill_name}"


def _do_set_step(opts):
    step = opts.get("step", "")
    if not step:
        return "Error: 'step' option is required"
    result = scan_session.set_step(step)
    if result is None:
        return "No active running session — cannot set step."
    log.note(f"Step checkpoint: {step}")
    return f"Step checkpoint: {step}"


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


async def _do_start_metasploit():
    from tools import metasploit_runner
    log.tool_call("start_metasploit", {})
    ok, msg = await metasploit_runner.ensure_running()
    result = (
        f"Metasploit container ready at {metasploit_runner.MSF_API} ({msg})"
        if ok else f"Failed to start Metasploit container: {msg}"
    )
    log.tool_result("start_metasploit", result)
    return result


async def _do_stop_metasploit():
    from tools import metasploit_runner
    log.tool_call("stop_metasploit", {})
    result = await metasploit_runner.stop()
    log.tool_result("stop_metasploit", result)
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
