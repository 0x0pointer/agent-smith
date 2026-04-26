"""
Coverage-driven planner — computes next actions and detects behavioral drift.

Called by the envelope wrapper on every tool response. Returns required actions
(obligations the model must fulfill) and recommended actions (suggestions).
Also detects drift: duplicate tests, phase-inappropriate tools, skipped coverage.
"""
from __future__ import annotations

from core import session as scan_session
from core.coverage import get_matrix


def compute_next(tool: str, state: dict) -> dict:
    """Compute next actions based on current state.

    Returns {"required": [...], "recommended": [...], "warnings": [...]}.
    """
    required: list[str] = []
    recommended: list[str] = []
    warnings: list[str] = []

    phase = state.get("phase", "idle")
    tools_run = set(state.get("tools_run", []))
    target = state.get("target", "")

    if phase == "idle":
        required.append(f"Start scan: session(action='start', options={{target: '{target}', depth: 'thorough'}})")
        return {"required": required, "recommended": recommended, "warnings": warnings}

    # --- Drift detection ---
    drift = _detect_drift(tool, phase, tools_run)
    warnings.extend(drift)

    # --- Phase-specific next actions ---
    if phase == "recon":
        if "httpx" not in tools_run:
            required.append(f"Run httpx: scan(tool='httpx', target='{target}')")
        if "naabu" not in tools_run and "nmap" not in tools_run:
            recommended.append(f"Port scan: scan(tool='naabu', target='{target}')")
        if "subfinder" not in tools_run:
            recommended.append(f"Subdomain enum: scan(tool='subfinder', target='{target}')")

    elif phase == "discovery":
        if "spider" not in tools_run:
            required.append(f"Crawl endpoints: scan(tool='spider', target='{target}')")
        else:
            required.append(
                "Register endpoints in coverage matrix: "
                "report(action='coverage', data={type:'endpoint', path:'...', method:'GET', "
                "params:[{name, type, value_hint}], discovered_by:'spider'})"
            )
        if "nuclei" not in tools_run:
            recommended.append(f"Vulnerability scan: scan(tool='nuclei', target='{target}')")
        if "ffuf" not in tools_run:
            recommended.append(f"Directory fuzzing: scan(tool='ffuf', target='{target}')")

    elif phase == "testing":
        _add_testing_actions(required, recommended, target)

    elif phase == "validation":
        recommended.append("Save PoCs: http(action='save_poc', ...) for each finding")
        recommended.append("Create architecture diagram: report(action='diagram', data={title, mermaid})")
        recommended.append("Complete scan: session(action='complete')")

    return {"required": required, "recommended": recommended, "warnings": warnings}


def _add_testing_actions(required: list[str], recommended: list[str], target: str) -> None:
    """Compute next testing action from coverage matrix."""
    cov = get_matrix()
    endpoints = {ep["id"]: ep for ep in cov.get("endpoints", [])}

    # Find highest-priority pending cell
    pending = [c for c in cov.get("matrix", []) if c["status"] == "pending"]
    in_progress = [c for c in cov.get("matrix", []) if c["status"] == "in_progress"]

    if in_progress:
        cell = in_progress[0]
        ep = endpoints.get(cell["endpoint_id"], {})
        required.append(
            f"Continue testing: {cell['injection_type']} on "
            f"{ep.get('method', '?')} {ep.get('path', '?')} param={cell['param']} "
            f"(cell {cell['id']})"
        )
        return

    if not pending:
        recommended.append("All cells addressed — proceed to validation/reporting")
        return

    # Prioritize: sqli > xss > ssti > cmdi > ssrf > others
    priority_order = ["sqli", "xss", "ssti", "cmdi", "ssrf", "xxe", "nosqli", "idor"]
    best = None
    for inj_type in priority_order:
        candidates = [c for c in pending if c["injection_type"] == inj_type]
        if candidates:
            best = candidates[0]
            break
    if not best:
        best = pending[0]

    ep = endpoints.get(best["endpoint_id"], {})
    path = ep.get("path", "?")
    method = ep.get("method", "?")
    param = best["param"]
    inj = best["injection_type"]

    # Build concrete action
    if inj == "sqli":
        required.append(
            f"Mark in_progress then test SQLi: "
            f"kali(command=\"sqlmap -u '{target}{path}?{param}=test' --batch --dbs\") "
            f"(cell {best['id']})"
        )
    elif inj == "xss":
        required.append(
            f"Mark in_progress then test XSS: "
            f"http(action='request', url='{target}{path}?{param}=<script>alert(1)</script>', method='{method}') "
            f"(cell {best['id']})"
        )
    else:
        required.append(
            f"Mark in_progress then test {inj} on {method} {path} param={param} "
            f"(cell {best['id']})"
        )

    total = len(pending)
    if total > 1:
        recommended.append(f"{total - 1} more pending cells after this one")


# ---------------------------------------------------------------------------
# Drift detection
# ---------------------------------------------------------------------------

_RECON_ONLY_TOOLS = {"naabu", "subfinder", "nmap"}
_EXPLOITATION_TOOLS = {"kali_sqlmap", "kali"}  # kali used for sqlmap/hydra/etc


def _detect_drift(tool: str, phase: str, tools_run: set) -> list[str]:
    """Detect behavioral drift and return warning strings."""
    warnings: list[str] = []

    # Exploitation during recon
    if phase == "recon" and tool in _EXPLOITATION_TOOLS:
        warnings.append(
            f"DRIFT: Running {tool} during recon phase. "
            f"Complete discovery first: httpx → spider → register endpoints → then test."
        )

    # Recon tool during testing (going backwards)
    if phase == "testing" and tool in _RECON_ONLY_TOOLS:
        warnings.append(
            f"DRIFT: Running {tool} during testing phase. "
            f"Recon is already complete. Focus on pending coverage cells."
        )

    # httpx not run but trying to spider/test
    if tool == "spider" and "httpx" not in tools_run:
        warnings.append(
            "DRIFT: Spider called before httpx. Run httpx first to confirm target is live."
        )

    return warnings
