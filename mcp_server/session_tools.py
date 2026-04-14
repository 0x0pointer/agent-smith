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
      reason= (why this skill was chosen — shown in logs)
      chained_from= (parent skill name when chaining, omit for first skill)

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
        return await _do_complete(opts)
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
    elif action == "pre_chain":
        return _do_pre_chain(opts)
    else:
        return f"Unknown action '{action}'. Use: start, complete, status, recovery, pre_chain, set_skill, set_step, start_kali, stop_kali, start_metasploit, stop_metasploit, pull_images, set_codebase"


def _do_start(opts):
    _session_tools_called.clear()
    target = opts.get("target", "")

    # Coverage matrix lifecycle: only reset when the target changes.
    # Same target = keep matrix (resume interrupted scan or view completed results).
    # Different target = archive old matrix, then reset.
    from core.coverage import COVERAGE_FILE, _save as _cov_save, get_matrix
    from datetime import datetime, timezone
    import shutil

    prev = scan_session.get()
    prev_target = prev.get("target", "") if prev else ""
    cov = get_matrix()
    has_data = len(cov.get("matrix", [])) > 0

    if prev_target and prev_target != target and has_data:
        # Different target — archive the old matrix before resetting
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        archive_dir = COVERAGE_FILE.parent / "logs"
        archive_dir.mkdir(exist_ok=True)
        archive_path = archive_dir / f"coverage_matrix_{ts}.json"
        shutil.copy2(COVERAGE_FILE, archive_path)
        log.note(f"Coverage matrix archived to {archive_path.name} (previous target: {prev_target})")
        _cov_save({
            "meta": {
                "created": datetime.now(timezone.utc).isoformat(),
                "target": target,
                "total_cells": 0, "tested": 0, "in_progress": 0,
                "vulnerable": 0, "not_applicable": 0, "skipped": 0,
            },
            "endpoints": [],
            "matrix": [],
        })
    elif not has_data:
        # Empty matrix — just set the target
        _cov_save({
            "meta": {
                "created": datetime.now(timezone.utc).isoformat(),
                "target": target,
                "total_cells": 0, "tested": 0, "in_progress": 0,
                "vulnerable": 0, "not_applicable": 0, "skipped": 0,
            },
            "endpoints": [],
            "matrix": [],
        })
    # Same target with existing data — keep matrix as-is (resume or view results)
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
        "",
        "Skills available (invoke these instead of improvising workflows):",
        "  /pentester /web-exploit /codebase /ai-redteam /cloud-security /ad-assessment",
        "  /network-assess /lateral-movement /credential-audit /post-exploit",
        "  /container-k8s-security /osint /ssl-tls-audit /email-security /metasploit",
        "  /reverse-shell /analyze-cve /threat-model /aikido-triage /gh-export",
        "  /remediate /request-cves",
        "  See CLAUDE.md for full skill descriptions and trigger conditions.",
    ]
    return "\n".join(lines)


def _coverage_blockers(cov: dict, ctf_mode: bool = False) -> list[str]:
    """Return coverage-related completion blockers for the given matrix state.

    For non-CTF runs, an empty matrix is a hard blocker if web testing happened —
    the agent must register endpoints in the matrix so the methodology is auditable
    and so re-spidering picks up new endpoints later. CTF mode bypasses this because
    benchmarks have a single flag goal where matrix bookkeeping is overhead.
    """
    from core.coverage import _BYPASS_REQUIRED_TYPES  # local import to avoid circularity
    blockers: list[str] = []
    meta = cov.get("meta", {})
    total = meta.get("total_cells", 0)

    # Empty matrix gate — only enforced for non-CTF runs where web work happened.
    web_work_done = any(t in _session_tools_called for t in ("httpx", "spider", "ffuf", "nuclei"))
    if total == 0:
        if not ctf_mode and web_work_done:
            blockers.append(
                "EMPTY COVERAGE MATRIX: web tools were run (httpx/spider/ffuf/nuclei) "
                "but no endpoints were registered. For non-CTF pentests you MUST register "
                "every discovered endpoint with report(action='coverage', data={'type': 'endpoint', "
                "'path': '/...', 'method': 'GET', 'params': [...], 'discovered_by': 'spider'}). "
                "The matrix is the audit trail of what was tested — without it, coverage gaps "
                "are invisible and re-spider can't deduplicate. See /web-exploit Phase 1 for the "
                "full registration pattern."
            )
        return blockers

    addressed = meta.get("tested", 0) + meta.get("not_applicable", 0) + meta.get("skipped", 0)
    pct = (addressed / total) * 100
    if pct < 80:
        blockers.append(
            f"LOW COVERAGE: only {addressed}/{total} matrix cells addressed ({pct:.0f}%). "
            f"Review pending cells in the coverage matrix — test, skip with reason, or mark N/A."
        )

    all_cells = cov.get("matrix", [])
    untooled = [c for c in all_cells
                if c["status"] in ("tested_clean", "vulnerable") and not c.get("tested_by")]
    if untooled:
        blockers.append(
            f"INTEGRITY: {len(untooled)} cell(s) marked tested/vulnerable but have no "
            f"tested_by tool. Re-test these cells or add the tested_by field."
        )

    suspect_na = _suspect_na_cells(all_cells, _BYPASS_REQUIRED_TYPES)
    if suspect_na:
        sample = ", ".join(suspect_na[:5]) + ("..." if len(suspect_na) > 5 else "")
        blockers.append(
            f"INTEGRITY: {len(suspect_na)} cell(s) marked N/A without testing bypass "
            f"techniques: {sample}. Test the bypass before marking N/A."
        )
    return blockers


def _suspect_na_cells(cells: list[dict], bypass_types: dict) -> list[str]:
    """Return cell IDs/types marked N/A without bypass justification."""
    suspect = []
    for c in cells:
        if c["status"] != "not_applicable" or c["injection_type"] not in bypass_types:
            continue
        cell_notes = c.get("notes", "")
        bypass = bypass_types[c["injection_type"]]
        keywords = bypass.lower().split(", ")
        if not any(kw in cell_notes.lower() for kw in keywords) and len(cell_notes) < 40:
            suspect.append(f"{c['id']} ({c['injection_type']})")
    return suspect


def _gate_blockers() -> list[str]:
    """Return completion blockers for unsatisfied gates."""
    blockers: list[str] = []
    for gate in scan_session.pending_gates():
        missing = sorted(set(gate["required_skills"]) - set(gate.get("satisfied_skills", [])))
        blockers.append(
            f"GATE [{gate['id']}]: {gate['trigger']} — "
            f"required skill(s) not yet invoked: {', '.join(missing)}. "
            f"Chain into these skills before completing."
        )
    return blockers


def _escalation_lead_blockers(data: dict) -> list[str]:
    """Return completion blockers for pending escalation leads."""
    pending_leads: list[str] = []
    for f in data.get("findings", []):
        for lead in f.get("escalation_leads", []):
            if lead.get("status") == "pending":
                pending_leads.append(f"{f['title']}: {lead['lead']}")
    if not pending_leads:
        return []
    sample = "; ".join(pending_leads[:5])
    more = f" (and {len(pending_leads) - 5} more)" if len(pending_leads) > 5 else ""
    return [
        f"PENDING LEADS: {len(pending_leads)} escalation lead(s) not followed up{more}. "
        f"Investigate or dismiss each before completing: {sample}"
    ]


async def _do_complete(opts):
    notes = opts.get("notes", "")
    blockers: list[str] = []

    data = findings_store._load()

    blockers.extend(_gate_blockers())
    blockers.extend(_escalation_lead_blockers(data))

    # ── Existing checks ──────────────────────────────────────────────────────

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
    high_findings = [f for f in data.get("findings", []) if f.get("severity") in ("high", "critical")]
    if high_findings and not poc_files:
        titles = ", ".join(f["title"] for f in high_findings)
        blockers.append(
            f"NO POC FILES: {len(high_findings)} high/critical finding(s) have no Burp PoC. "
            f"Call http(action='request', poc=true) + http(action='save_poc') for each: {titles}"
        )

    from core.coverage import get_matrix
    blockers.extend(_coverage_blockers(get_matrix(), ctf_mode=_has_ctf_flag(data)))

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
    # Mid-scan warning when the matrix is empty but web work has happened
    # — only shown when not in CTF mode (CTF runs intentionally skip the matrix).
    web_work_done = any(t in _session_tools_called for t in ("httpx", "spider", "ffuf", "nuclei"))
    if (
        meta.get("total_cells", 0) == 0
        and web_work_done
        and not _has_ctf_flag(data)
    ):
        result["coverage_warning"] = (
            "MATRIX EMPTY: web tools have run but no endpoints are registered. "
            "Register every discovered endpoint with report(action='coverage', "
            "data={'type': 'endpoint', 'path': ..., 'method': ..., 'params': [...], "
            "'discovered_by': 'spider'}). The matrix drives Phase 2's systematic "
            "per-cell testing and prevents you from forgetting which params you tested. "
            "complete_scan will be blocked until at least one endpoint is registered."
        )
    if remaining:
        result["remaining"] = {
            "cost_usd": remaining.get("cost_remaining_usd", 0),
            "time_min": remaining.get("time_remaining_minutes", 0),
            "calls": remaining.get("calls_remaining", -1),
        }
    # Pending gates
    unsatisfied = scan_session.pending_gates()
    if unsatisfied:
        result["pending_gates"] = [
            {
                "gate_id": g["id"],
                "trigger": g["trigger"],
                "missing_skills": sorted(set(g["required_skills"]) - set(g.get("satisfied_skills", []))),
            }
            for g in unsatisfied
        ]

    if current.get("skill") and current.get("status") == "running":
        step = current.get("current_step", "")
        step_msg = f" Resume at step: {step}." if step else ""
        result["_recovery_hint"] = (
            f"If you lost context, re-invoke the /{current['skill']} skill "
            f"to reload its workflow.{step_msg}"
        )
    return json.dumps(result, indent=2)


_INJECTION_TOOL_MAP = {
    "sqli": {"sqlmap", "http_request", "kali"},
    "xxe": {"http_request", "kali"},
    "xss": {"xsser", "http_request", "kali"},
    "ssti": {"http_request", "kali"},
    "cmdi": {"commix", "http_request", "kali"},
    "ssrf": {"http_request", "kali"},
    "nosqli": {"http_request", "kali"},
    "deserial": {"http_request", "kali"},
}


def _determine_resume_step(current: dict, tools_run: set[str]) -> str:
    """Find the earliest incomplete pentester workflow step."""
    step_tools = {
        "2": ["naabu", "subfinder"],
        "3": ["httpx"],
        "5": ["ffuf"],
        "6": ["spider"],
        "6a": [],
        "8": ["nuclei"],
    }
    for step, tools in step_tools.items():
        if step == "6a":
            skill_names = [
                (s["skill"] if isinstance(s, dict) else s)
                for s in current.get("skill_history", [])
            ]
            if "web-exploit" not in skill_names:
                return "6a (chain /web-exploit with endpoint inventory)"
        elif tools and not any(t in tools_run for t in tools):
            return f"{step} ({', '.join(tools)})"
    return "10+ (deep dives / reporting)"


def _check_coverage_integrity(matrix: list[dict], tools_run: set[str]) -> list[str]:
    """Cross-check coverage cell statuses against tools actually run."""
    warnings: list[str] = []

    # Cells marked tested/vulnerable without a tested_by field
    by_type: dict[str, list[str]] = {}
    for c in matrix:
        if c["status"] in ("tested_clean", "vulnerable") and not c.get("tested_by"):
            by_type.setdefault(c["injection_type"], []).append(c["id"])
    for inj, ids in by_type.items():
        warnings.append(
            f"SUSPECT: {len(ids)} {inj} cell(s) marked tested but have no tested_by tool. "
            f"Re-verify these cells with actual tool execution."
        )

    # Injection types marked clean but no corresponding tool ran
    tested_types = {c["injection_type"] for c in matrix if c["status"] == "tested_clean"}
    for inj_type in tested_types:
        expected_tools = _INJECTION_TOOL_MAP.get(inj_type, set())
        if expected_tools and not (expected_tools & tools_run):
            warnings.append(
                f"MISMATCH: {inj_type} cells marked clean but none of "
                f"{expected_tools} appear in tools_run. These cells were likely "
                f"marked from memory, not from actual testing."
            )

    return warnings


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
    ep_map = {ep["id"]: ep["path"] for ep in cov.get("endpoints", [])}

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
        leads = [l for l in f.get("escalation_leads", []) if l.get("status") == "pending"]
        if leads:
            pending_escalations.append({
                "finding_id": f["id"],
                "title": f["title"],
                "pending_leads": [l["lead"] for l in leads],
            })

    tools_run = set(_session_tools_called)
    resume_step = _determine_resume_step(current, tools_run)
    integrity_warnings = _check_coverage_integrity(cov.get("matrix", []), tools_run)

    # Pending gates
    unsatisfied_gates = [
        {
            "gate_id": g["id"],
            "trigger": g["trigger"],
            "missing_skills": sorted(set(g["required_skills"]) - set(g.get("satisfied_skills", []))),
        }
        for g in scan_session.pending_gates()
    ]

    result = {
        "target": current.get("target", ""),
        "depth": current.get("depth", ""),
        "skill": current.get("skill"),
        "resume_from_step": resume_step,
        "tools_already_run": sorted(tools_run),
        "findings_count": len(data.get("findings", [])),
        "cost_usd": summary.get("est_cost_usd", 0),
        "remaining": remaining,
        "pending_gates": unsatisfied_gates,
        "coverage_in_progress": in_progress_cells,
        "coverage_pending_cells": pending_count,
        "coverage_tested": meta.get("tested", 0),
        "pending_escalations": pending_escalations,
        "integrity_warnings": integrity_warnings,
        "action_required": _build_action_list(
            integrity_warnings, in_progress_cells, pending_escalations,
            resume_step, unsatisfied_gates,
        ),
    }

    return json.dumps(result, indent=2)


def _build_action_list(
    integrity_warnings: list[str],
    in_progress_cells: list[dict],
    pending_escalations: list[dict],
    resume_step: str,
    unsatisfied_gates: list[dict] | None = None,
) -> list[str]:
    """Build prioritized action list for recovery."""
    actions: list[str] = []

    # Gates are highest priority — they block completion
    for gate in (unsatisfied_gates or []):
        actions.append(
            f"GATE BLOCKED [{gate['gate_id']}]: chain into {', '.join(gate['missing_skills'])} "
            f"— {gate['trigger']}"
        )

    if integrity_warnings:
        actions.append(
            f"FIX {len(integrity_warnings)} INTEGRITY WARNING(S): cells marked tested/clean "
            f"without tool evidence. Re-test these cells with actual tools before proceeding."
        )
    if in_progress_cells:
        actions.append(
            f"Resume {len(in_progress_cells)} in-progress test cell(s) — read their notes for technique state"
        )
    if pending_escalations:
        actions.append(
            f"Follow up on {len(pending_escalations)} finding(s) with pending escalation leads"
        )
    if resume_step.startswith("6a"):
        actions.append(
            "Chain /web-exploit — endpoint inventory exists but systematic testing not started"
        )
    if not actions:
        actions.append(f"Resume from step {resume_step}")
    return actions


def _do_pre_chain(opts):
    """Checkpoint state before chaining to a new skill.

    Persists all state to disk so it survives compaction, then returns
    a summary of what the next skill needs to know.
    """
    next_skill = opts.get("next_skill", "")
    if not next_skill:
        return "Error: 'next_skill' option is required"

    current = scan_session.get() or {}
    prev_skill = current.get("skill", "unknown")

    # Persist cost state
    cost_tracker.flush()

    # Calculate context savings estimate
    from core.coverage import get_matrix
    cov = get_matrix()
    meta = cov.get("meta", {})
    data = findings_store._load()

    # Set the new skill and log the chain decision
    chain_reason = f"chained from /{prev_skill}"
    scan_session.set_skill(next_skill, reason=chain_reason, chained_from=prev_skill)
    log.skill_start(next_skill, reason=chain_reason, chained_from=prev_skill)

    result = {
        "action": "pre_chain",
        "previous_skill": prev_skill,
        "next_skill": next_skill,
        "state_persisted": {
            "findings": len(data.get("findings", [])),
            "diagrams": len(data.get("diagrams", [])),
            "coverage_cells": meta.get("total_cells", 0),
            "coverage_tested": meta.get("tested", 0),
            "coverage_pending": sum(1 for c in cov.get("matrix", []) if c["status"] == "pending"),
        },
        "context_recommendation": (
            f"RECOMMEND COMPACTION: The /{prev_skill} skill and its tool results are "
            f"no longer needed in context. All state is persisted to disk "
            f"(session.json, findings.json, coverage_matrix.json). "
            f"Compacting before loading /{next_skill} would free ~50-80k tokens "
            f"(~40% of context window). The /{next_skill} skill can recover "
            f"full state via session(action='recovery')."
        ),
    }

    return json.dumps(result, indent=2)


def _do_set_skill(opts):
    skill_name = opts.get("skill", "")
    reason = opts.get("reason", "")
    chained_from = opts.get("chained_from", "")
    if not skill_name:
        return "Error: 'skill' option is required"
    result = scan_session.set_skill(skill_name, reason=reason, chained_from=chained_from)
    if result is None:
        return "No active running session — cannot set skill."

    # Auto-satisfy any gates that require this skill
    satisfied_gates: list[str] = []
    for gate in result.get("gates", []):
        if gate["status"] == "pending" and skill_name in gate["required_skills"]:
            scan_session.satisfy_gate(gate["id"], skill_name)
            satisfied_gates.append(gate["id"])

    log.skill_start(skill_name, reason=reason, chained_from=chained_from)
    msg = f"Skill '{skill_name}' logged"
    if satisfied_gates:
        msg += f" (satisfied gate(s): {', '.join(satisfied_gates)})"
    return msg


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
