"""session(action='status') — live scan-state payload + work queue + QA alerts."""
import json

from core import cost as cost_tracker
from core import findings as findings_store
from core import session as scan_session

import mcp_server.session_tools as _st
from .blocker_response import _pending_steer_block


def _do_status():
    summary = cost_tracker.get_summary()
    data = findings_store._load()
    current = scan_session.get() or {}
    remaining = scan_session.remaining(summary) if current else {}
    from core.coverage import get_matrix
    cov = get_matrix()
    result = _build_status_base(current, summary, remaining, cov, data)
    _add_status_work_queue(result, cov)
    _add_status_qa_alerts(result)
    payload = json.dumps(result, indent=2)
    # Same envelope-bypass story as _build_blocker_response: session()
    # responses don't pass through the steering injector, so status calls
    # made while Smith is in a complete()/resume() loop never see pending
    # HUMAN_STEER. Status is the natural "what's going on" call Smith
    # makes when confused — surface the human's messages here too.
    steer_block = _pending_steer_block()
    if steer_block:
        return payload + steer_block
    return payload


def _build_status_base(
    current: dict,
    summary: dict,
    remaining: dict,
    cov: dict,
    data: dict,
) -> dict:
    """Build the core status dict (base fields, coverage, gates, recovery hint)."""
    all_tools = sorted(_st._effective_tools())
    meta = cov.get("meta", {})
    result: dict = {
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
        "coverage": {
            "total_cells": meta.get("total_cells", 0),
            "tested": meta.get("tested", 0),
            "vulnerable": meta.get("vulnerable", 0),
            "not_applicable": meta.get("not_applicable", 0),
            "skipped": meta.get("skipped", 0),
            "endpoints": len(cov.get("endpoints", [])),
        },
    }
    web_work_done = any(t in _st._effective_tools() for t in ("httpx", "spider", "ffuf", "nuclei"))
    ai_work_done = any(t in _st._effective_tools() for t in ("fuzzyai", "garak", "pyrit", "promptfoo"))
    if meta.get("total_cells", 0) == 0 and web_work_done and not _st._has_ctf_flag(data):
        result["coverage_warning"] = (
            "MATRIX EMPTY: web tools have run but no endpoints are registered. "
            "Register every discovered endpoint with report(action='coverage', "
            "data={'type': 'endpoint', 'path': ..., 'method': ..., 'params': [...], "
            "'discovered_by': 'spider'}). The matrix drives Phase 2's systematic "
            "per-cell testing and prevents you from forgetting which params you tested. "
            "complete_scan will be blocked until at least one endpoint is registered."
        )
    elif meta.get("total_cells", 0) == 0 and ai_work_done and not _st._has_ctf_flag(data):
        result["coverage_warning"] = (
            "MATRIX EMPTY: AI red-team tools have run but no LLM/MCP endpoint is registered. "
            "Register the chat/LLM endpoint with report(action='coverage', data={'type':'endpoint', "
            "'path': ..., 'method':'POST', 'params':[{'name':'message','type':'llm_prompt'}], "
            "'discovered_by':'ai-redteam'}) so every OWASP LLM/MCP category becomes a closable cell. "
            "complete_scan will be blocked until at least one endpoint is registered."
        )
    if remaining:
        result["remaining"] = {
            "cost_usd": remaining.get("cost_remaining_usd", 0),
            "time_min": remaining.get("time_remaining_minutes", 0),
            "calls": remaining.get("calls_remaining", -1),
        }
    spider_failures = _st.scan_session.get_spider_failures()
    if spider_failures:
        result["spider_gate"] = {
            "status": "BLOCKED",
            "failed_targets": list(spider_failures.keys()),
            "instruction": (
                "Spider failed — retry scan(tool='spider', target=...) for each target. "
                "If Kali is not running, call session(action='start_kali') first. "
                "All other scan tools are blocked until spider succeeds."
            ),
        }

    unsatisfied = _st.scan_session.pending_gates()
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
    return result


def _add_status_work_queue(result: dict, cov: dict) -> None:
    """Append next_work queue to the status result dict (in-place)."""
    all_cells = cov.get("matrix", [])
    ep_map = {ep["id"]: ep["path"] for ep in cov.get("endpoints", [])}
    pending_cells = [c for c in all_cells if c["status"] == "pending"]
    in_progress_cells = [c for c in all_cells if c["status"] == "in_progress"]
    if not in_progress_cells and not pending_cells:
        return
    queue: list[dict] = []
    for c in in_progress_cells[:3]:
        queue.append({
            "cell_id": c["id"],
            "endpoint": ep_map.get(c["endpoint_id"], "?"),
            "param": c["param"],
            "injection": c["injection_type"],
            "status": "IN_PROGRESS — resume this test first",
        })
    for c in pending_cells[:5]:
        queue.append({
            "cell_id": c["id"],
            "endpoint": ep_map.get(c["endpoint_id"], "?"),
            "param": c["param"],
            "injection": c["injection_type"],
            "status": "pending",
        })
    result["next_work"] = {
        "instruction": (
            "Test these cells systematically. Mark each in_progress BEFORE running any tool, "
            "then tested_clean/vulnerable when done. This is the primary work queue — "
            "do NOT skip to session(action='complete') while cells remain pending."
        ),
        "in_progress_count": len(in_progress_cells),
        "pending_count": len(pending_cells),
        "cells": queue,
    }


def _add_status_qa_alerts(result: dict) -> None:
    """Append QA alerts and active steering directives to the status result dict."""
    import os as _os
    _qa_path = _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.dirname(__file__))), _st._QA_STATE_FILENAME)
    try:
        if _os.path.exists(_qa_path):
            with open(_qa_path) as _fh:
                _qa = json.loads(_fh.read())
            _alerts = _qa.get("alerts", [])
            result["qa_alerts"] = _alerts
            result["qa_last_check"] = _qa.get("ts", "")
        else:
            result["qa_alerts"] = []
    except Exception:
        result["qa_alerts"] = []

    # Include active steering directives so status gives a complete picture
    try:
        from core.steering import steering_queue
        active = steering_queue.get_active()
        if active:
            result["steering_directives"] = [
                {"id": d.id, "code": d.code, "priority": d.priority,
                 "message": d.message, "status": d.status}
                for d in active
            ]
            result["qa_note"] = (
                "Steering directives above are already injected into tool responses. "
                "To acknowledge: session(action='qa_reply', options={message: '...', directive_id: '<id>'})"
            )
    except Exception:
        pass
