"""Completion-blocker leaf gates + the _collect_completion_blockers orchestrator."""
import json
import os

from core import session as scan_session

import mcp_server.session_tools as _st


def _qa_blockers() -> list[str]:
    """Return completion blockers from open high-urgency, blocking QA alerts."""
    qa_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), _st._QA_STATE_FILENAME)
    try:
        if os.path.exists(qa_path):
            with open(qa_path) as _fh:
                qa = json.loads(_fh.read())
            return [
                f"QA BLOCKER [{a.get('code', '?')}]: {a.get('message', '')}"
                for a in qa.get("alerts", [])
                if isinstance(a, dict) and a.get("blocking") and a.get("urgency") == "high"
            ]
    except Exception:
        pass
    return []


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
            if isinstance(lead, dict) and lead.get("status") == "pending":
                pending_leads.append(f"{f['title']}: {lead['lead']}")
    if not pending_leads:
        return []
    sample = "; ".join(pending_leads[:5])
    more = f" (and {len(pending_leads) - 5} more)" if len(pending_leads) > 5 else ""
    return [
        f"PENDING LEADS: {len(pending_leads)} escalation lead(s) not followed up{more}. "
        f"Investigate or dismiss each before completing: {sample}"
    ]


def _finding_quality_blockers(high_findings: list[dict]) -> str | None:
    """Return a blocker string if any high/critical finding lacks evidence or reproduction."""
    quality_issues: list[str] = []
    for f in high_findings:
        missing: list[str] = []
        if not str(f.get("evidence", "")).strip():
            missing.append("evidence")
        if not f.get("reproduction"):
            missing.append("reproduction")
        if missing:
            quality_issues.append(f"[{f['severity'].upper()}] {f['title']}: missing {', '.join(missing)}")
    if not quality_issues:
        return None
    sample = "\n    ".join(quality_issues[:5])
    more   = f"\n    (+{len(quality_issues) - 5} more)" if len(quality_issues) > 5 else ""
    return (
        f"FINDING QUALITY: {len(quality_issues)} high/critical finding(s) missing required fields. "
        f"Add evidence and reproduction steps before completing:\n    {sample}{more}"
    )

def _collect_completion_blockers(data: dict, effective: set) -> list[str]:
    """Run all completion gate checks and return the list of blocker strings."""
    blockers: list[str] = []

    blockers.extend(_st._gate_blockers())
    blockers.extend(_st._qa_blockers())
    blockers.extend(_st._escalation_lead_blockers(data))

    # ── Existing checks ──────────────────────────────────────────────────────

    if not data.get("diagrams"):
        blockers.append(
            "NO DIAGRAM: call report(action='diagram') with a Mermaid diagram of the "
            "application architecture before completing."
        )

    if "httpx" in effective and "spider" not in effective:
        blockers.append(
            "NO SPIDER: httpx confirmed web targets but spider was never called. "
            "Run scan(tool='spider', target=url) to crawl the application before completing."
        )

    # Spider failures are NOT a completion blocker. Phase 7 work-based gates
    # already require ffuf to have run on a web target (tool-class coverage)
    # and finding-saturation to be reached, both of which together cover
    # under-discovery without forcing the model to retry a spider that may
    # be permanently broken on the target (cloudflare interstitials, etc.).
    # The failure is still recorded in the spider_failures registry + the
    # Phase 4 tool_failures registry so it's visible to QA + dashboards.

    high_findings = [f for f in data.get("findings", []) if f.get("severity") in ("high", "critical")]
    missing_poc = [f for f in high_findings if not f.get("poc_files")]
    if missing_poc:
        titles = ", ".join(f["title"] for f in missing_poc[:5])
        if len(missing_poc) > 5:
            titles += f" (+{len(missing_poc) - 5} more)"
        blockers.append(
            f"NO POC FILES: {len(missing_poc)} high/critical finding(s) have no linked PoC. "
            f"Call http(action='save_poc', options={{finding_id: '<id>'}}) for each: {titles}"
        )

    # ── Finding quality blockers ──────────────────────────────────────────────
    quality_blocker = _st._finding_quality_blockers(high_findings)
    if quality_blocker:
        blockers.append(quality_blocker)

    # ── Final-QA adjudication ─────────────────────────────────────────────────
    # Always-on senior-review pass: every high/critical finding must carry a
    # reproducibility + recalibrated-severity verdict before completion. Runs
    # here (at completion) on purpose — never mid-scan, so discovery is not
    # interrupted and findings are judged with full chained context.
    from core.adjunction import adjudication_blockers
    blockers.extend(adjudication_blockers(data, digest=_st._condensed_directives()))

    from core.coverage import get_matrix
    blockers.extend(_st._coverage_blockers(get_matrix(), data=data, ctf_mode=_st._has_ctf_flag(data)))

    return blockers
