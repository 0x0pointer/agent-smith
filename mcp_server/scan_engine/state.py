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

    Returns a compact dict suitable for embedding in every tool response envelope.
    """
    current = scan_session.get()
    if not current or current.get("status") != "running":
        return {"phase": "idle", "status": "no_active_scan"}

    tools_run = set(current.get("tools_called", []))
    cov = get_matrix()
    meta = cov.get("meta", {})
    total_cells = meta.get("total_cells", 0)
    tested = meta.get("tested", 0) + meta.get("not_applicable", 0) + meta.get("skipped", 0)
    vulnerable = meta.get("vulnerable", 0)
    endpoints = len(cov.get("endpoints", []))

    # Determine phase
    phase = _compute_phase(tools_run, endpoints, total_cells, tested)

    # Cost/time remaining
    summary = cost_tracker.get_summary()
    remaining = scan_session.remaining(summary)

    return {
        "target": current.get("target", ""),
        "phase": phase,
        "tools_run": sorted(tools_run),
        "endpoints": endpoints,
        "coverage": f"{tested}/{total_cells}" if total_cells else "no endpoints registered",
        "findings": vulnerable,
        "calls_used": summary.get("tool_calls_total", 0),
        "time_pct": remaining.get("time_pct", 0),
    }


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
