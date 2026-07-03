"""session(action='recovery') — compact resume brief after compaction."""
import json

from core import findings as findings_store
from core import logger as log
from core import session as scan_session

import mcp_server.session_tools as _st
from .recovery_build import (
    _build_recovery_result,
    _concrete_next_call,
    _build_action_list,
)


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

    # Cells marked tested/vulnerable that cite no test evidence (artifact_id)
    from core.coverage import cell_has_test_evidence
    by_type: dict[str, list[str]] = {}
    for c in matrix:
        if c["status"] in ("tested_clean", "vulnerable") and not cell_has_test_evidence(c):
            by_type.setdefault(c["injection_type"], []).append(c["id"])
    for inj, ids in by_type.items():
        warnings.append(
            f"SUSPECT: {len(ids)} {inj} cell(s) marked tested but cite no artifact_id. "
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


_TERMINAL_SCAN_STATUSES = (
    "complete", "incomplete_with_unresolved_blockers", "limit_reached",
)


def _terminal_recovery_brief(scan_status: str, current: dict) -> str | None:
    """Recovery brief for a STOPPED scan, or None when the scan isn't terminal.

    Two shapes, kept out of _do_recovery to hold its cognitive complexity down:
      - TRIAGE_ADJUDICATION when an operator triage pass is in flight on the
        stopped scan (adjudicate every pending finding, then stop), and
      - the plain SCAN_COMPLETED brief otherwise (stop, the scan is over).
    """
    if scan_status not in _TERMINAL_SCAN_STATUSES:
        return None
    if current.get("triage_requested"):
        try:
            from core.findings import _load as _load_findings
            from core.adjunction import pending_findings
            from core.adjunction.directive import build_adjudication_directive
            pending = pending_findings(_load_findings())
        except Exception:
            pending = []
        return json.dumps({
            "status": "TRIAGE_ADJUDICATION",
            "scan_status": scan_status,
            "mode": "triage",
            "target": current.get("target", ""),
            "pending_adjudication": len(pending),
            "EXECUTE_NOW": (
                build_adjudication_directive(pending) if pending
                else "All findings already adjudicated — write a one-line summary and stop."
            ),
            "message": (
                "TRIAGE pass requested by the human operator on a STOPPED scan. "
                "Record a verdict for every finding listed above via "
                "report(action='update_finding', data={id, adjudication:{reproducible, "
                "original_severity, revised_severity, rationale}}). You may re-verify a "
                "finding with http()/kali() to confirm reproducibility. When every "
                "finding has a verdict, STOP — do NOT resume testing and do NOT call "
                "session(action='start'). The scan remains complete."
            ),
        }, indent=2)
    return json.dumps({
        "status": "SCAN_COMPLETED",
        "scan_status":  scan_status,
        "target":       current.get("target", ""),
        "finished":     current.get("finished", ""),
        "notes":        current.get("notes", ""),
        "message": (
            f"This scan is already marked '{scan_status}' on disk. Stop calling "
            "tools. Write one final brief summary and end your turn. Do NOT call "
            "session(action='start') to begin a new scan — the human will trigger "
            "that themselves when they want fresh work."
        ),
    }, indent=2)


def _do_recovery():
    """Compact recovery brief — one call gives the agent everything to resume."""
    current = scan_session.get() or {}
    # Terminal status: the previous scan is finished (possibly mid-triage).
    # Surface that explicitly instead of falling through to the "no_session →
    # start a new one" path, because Smith would otherwise try to start a new
    # scan over the top of a completed one.
    scan_status = current.get("status", "") if current else ""
    terminal_brief = _terminal_recovery_brief(scan_status, current)
    if terminal_brief is not None:
        return terminal_brief

    if not current or current.get("status") != "running":
        # No session exists — tell the model to start one
        return json.dumps({
            "EXECUTE_NOW": "session(action='start', options={\"target\": \"<TARGET_URL>\", \"depth\": \"thorough\"})",
            "status": "no_session",
            "TOOLS": (
                "Only use these 5 MCP tools. Do NOT use Skill or Read tools. "
                "scan(tool, target) | kali(command) | http(action, url) | "
                "report(action, data) | session(action)"
            ),
        }, indent=2)

    # Coverage matrix: in_progress and pending cells
    from core.coverage import get_matrix
    cov = get_matrix()
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
        leads = [l for l in f.get("escalation_leads", [])
                 if isinstance(l, dict) and l.get("status") == "pending"]
        if leads:
            pending_escalations.append({
                "finding_id": f["id"],
                "title": f["title"],
                "pending_leads": [l.get("lead") for l in leads],
            })

    tools_run = _st._effective_tools()
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

    # Profile-aware: limit cells shown in recovery for small models
    from mcp_server.scan_engine.budget import get_profile
    profile = get_profile(current.get("model_profile", "full"))
    max_cells = profile.get("recovery_cells_shown")
    extra_cells = 0
    if max_cells and len(in_progress_cells) > max_cells:
        extra_cells = len(in_progress_cells) - max_cells
        in_progress_cells = in_progress_cells[:max_cells]

    target = current.get("target", "")
    action_list = _build_action_list(
        integrity_warnings, in_progress_cells, pending_escalations,
        resume_step, unsatisfied_gates,
    )
    next_call = _concrete_next_call(target, tools_run, in_progress_cells, pending_count)

    result = _build_recovery_result(
        current, cov, data, extra_cells,
        unsatisfied_gates, pending_escalations, integrity_warnings,
        target, tools_run, action_list, next_call, resume_step,
    )

    # Manual-setup gates still open (capabilities.yaml prerequisites). Surfaced so
    # a deferred/failed gate survives compaction and the operator/agent can resume
    # it. NON-blocking — these never appear as completion blockers.
    open_setup_gates = [
        {
            "id": g["id"], "status": g.get("status"), "election": g.get("election"),
            "requires_host": g.get("requires_host"), "skill": g.get("skill"),
            "recheck": f"session(action='setup_gate', options={{'action':'check','id':'{g['id']}'}})",
        }
        for g in scan_session.list_setup_gates()
        if g.get("status") in ("pending_election", "deferred", "elected_now", "failed")
    ]
    if open_setup_gates:
        result["open_setup_gates"] = open_setup_gates

    try:
        return json.dumps(result, indent=2)
    except TypeError as e:
        # In-memory state can drift over long MCP uptimes (e.g. dict keys that
        # are tuples). Falling back to default=str lets the recovery brief
        # serialize so Smith can resume, rather than failing the whole call.
        log.note(f"recovery: json encoding fallback ({e}) — reloading from disk")
        scan_session.load_from_disk()
        return json.dumps(result, indent=2, default=str)
