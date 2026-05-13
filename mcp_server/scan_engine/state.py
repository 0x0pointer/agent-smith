"""
Scan state — server-determined phase tracking and progress computation.

Reads session.json + coverage_matrix.json to compute the current scan phase.
Phase transitions are automatic, not model-declared.
"""
from __future__ import annotations

from core import session as scan_session
from core import cost as cost_tracker
from core.coverage import get_matrix


# Phase order — each phase has entry criteria based on tools run + coverage state
PHASES = ["recon", "discovery", "testing", "validation", "reporting"]

# Tools that indicate recon is done
_RECON_TOOLS = {"naabu", "subfinder", "nmap"}
_DISCOVERY_TOOLS = {"httpx", "spider", "ffuf"}
_TESTING_TOOLS = {"kali", "nuclei"}


def get_state() -> dict:
    """Compute current scan state from session.json + coverage_matrix.json.

    Returns a compact dict embedded in every tool response envelope.
    Includes recovery-oriented fields so a post-compaction model can orient
    from any tool response without calling session(action='recovery').
    """
    current = scan_session.get()
    if not current or current.get("status") != "running":
        return {"phase": "idle", "status": "no_active_scan"}

    tools_run = set(current.get("tools_called", []))
    cov = get_matrix()
    meta = cov.get("meta", {})
    total_cells = meta.get("total_cells", 0)
    # Use the pre-computed "addressed" counter so phase logic agrees with coverage blockers.
    # skipped is not addressed — it is a deferral. See core/coverage.ADDRESSED_STATUSES.
    tested = meta.get("addressed", meta.get("tested", 0) + meta.get("not_applicable", 0))
    vulnerable = meta.get("vulnerable", 0)
    endpoints = len(cov.get("endpoints", []))

    # Determine phase
    phase = _compute_phase(tools_run, endpoints, total_cells, tested)

    # Cost/time remaining
    summary = cost_tracker.get_summary()
    remaining = scan_session.remaining(summary)

    # In-progress cells — post-compaction orientation (capped at 3 to limit envelope size)
    ep_map = {ep["id"]: ep.get("path", "?") for ep in cov.get("endpoints", [])}
    in_progress = [
        {
            "cell_id":   c["id"],
            "endpoint":  ep_map.get(c["endpoint_id"], "?"),
            "param":     c["param"],
            "injection": c["injection_type"],
            "notes":     c.get("notes", "")[:100],
        }
        for c in cov.get("matrix", []) if c["status"] == "in_progress"
    ][:3]

    # Pending escalation leads count
    try:
        from core.findings import findings_store
        findings_data = findings_store._load()
        pending_escalations = sum(
            1 for f in findings_data.get("findings", [])
            for lead in f.get("escalation_leads", [])
            if lead.get("status") == "pending"
        )
    except Exception:
        pending_escalations = 0

    state: dict = {
        "target":               current.get("target", ""),
        "phase":                phase,
        "active_skill":         current.get("skill", ""),
        "tools_run":            sorted(tools_run),
        "endpoints":            endpoints,
        "coverage":             f"{tested}/{total_cells}" if total_cells else "no endpoints registered",
        "findings":             vulnerable,
        "calls_used":           summary.get("tool_calls_total", 0),
        "time_pct":             remaining.get("time_pct", 0),
        "pending_escalations":  pending_escalations,
    }
    if in_progress:
        state["in_progress_cells"] = in_progress
    return state


def _compute_phase(tools_run: set, endpoints: int, total_cells: int, tested: int) -> str:
    """Server-determined phase based on actual state, not model declaration."""
    has_recon = bool(tools_run & _RECON_TOOLS)
    has_discovery = bool(tools_run & _DISCOVERY_TOOLS)

    if not has_recon and not has_discovery:
        return "recon"

    if has_recon and not has_discovery:
        return "recon"

    if has_discovery and endpoints == 0:
        return "discovery"

    if total_cells > 0 and tested < total_cells:
        return "testing"

    if total_cells > 0 and tested >= total_cells:
        return "validation"

    return "discovery"
