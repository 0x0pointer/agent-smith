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
            f"Chain into these skills and do their work (a tool firing under the skill clears it). "
            f"If a required skill genuinely CANNOT run on this target — the trigger was a false "
            f"positive or the precondition is absent (e.g. post_exploit_rce with no code-execution, "
            f"so reverse-shell has nothing to launch) — record the dead-end instead of re-chaining "
            f"it forever: session(action='dismiss_gate', options={{gate_id:'{gate['id']}', "
            f"rationale:'<why {', '.join(missing)} is not applicable here>'}})."
        )
    return blockers


def _escalation_lead_blockers(data: dict) -> list[str]:
    """Return completion blockers for pending escalation leads."""
    pending_leads: list[str] = []
    for f in data.get("findings", []):
        for lead in f.get("escalation_leads", []):
            if isinstance(lead, dict) and lead.get("status") == "pending":
                # AR-B9: finding titles + leads are target-derived — fence them
                # so a reflected/crafted string can't inject into this directive.
                from core.prompt_fence import fence as _fence
                pending_leads.append(f"{_fence(f.get('title', ''))}: {_fence(lead.get('lead', ''))}")
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

def _phase_completion_blocker() -> str | None:
    """Advance the scan phase to saturation, then return a completion blocker if the scan is
    not yet in SYNTHESIS (Phase C). Ensures the deep pass (A) → coverage (B) → synthesis (C)
    all run before completion, instead of finishing early in Phase A. None once in C."""
    from core import session as _sess
    from core.session import phases as _phases
    _sess.maybe_advance_phase()   # catch the phase up before we judge completion
    cur = _sess.get()
    if not cur:
        return None
    ph = _phases.current_phase(cur)
    if ph == _phases.SYNTHESIS:
        return None
    if ph == _phases.EXPLOIT:
        return (
            "PHASE A NOT COMPLETE — you can't finish yet. Drive EVERY high/critical finding to a "
            "terminal (RCE / pivot / takeover) or a documented dead-end (dismissed escalation_lead), "
            "and attempt every provable exploit bridge. The scan AUTO-ADVANCES to Phase B (coverage) "
            "the moment depth saturates — keep hunting, don't stop to summarise."
        )
    return (
        "PHASE B NOT COMPLETE — drain the pending coverage cells (report(action='coverage', "
        "data={type:'sweep'}) / bulk_tested). The scan AUTO-ADVANCES to Phase C (synthesis) at 0 "
        "pending, where you compose the final kill-chains and then complete."
    )


def _deep_pivot_host_blocker() -> str | None:
    """Deep-pivot (depth=danger / scan_mode=benchmark): block completion while internal
    hosts discovered via SSRF/RCE remain unscanned (network-assess not yet run on them).

    Fires on EVERY profile and in EVERY phase (unlike the coverage-matrix gates) — the
    whole point of danger/benchmark is to not finish leaving a discovered internal host
    untouched. Dischargeable by scanning each host (the ledger marks it covered when a
    tool fires against it while /network-assess is active); the operator force-complete
    still bypasses it. No-op for normal scans."""
    try:
        from core.session import surface_ledger as _ledger
        if not scan_session.deep_pivot_enabled(scan_session.get()):
            return None
        pend = _ledger.pending("network-assess")
        if not pend:
            return None
        shown = ", ".join(pend[:8]) + (f" (+{len(pend) - 8} more)" if len(pend) > 8 else "")
        return (
            f"DEEP-PIVOT — {len(pend)} discovered internal host(s) not yet scanned: {shown}. "
            "Tunnel in (chisel / ssh -D + proxychains via kali) and run /network-assess against "
            "each: naabu/nmap top-ports -> httpx -> nuclei, then spider + register endpoints for "
            "any web service found. Each host clears when a scan fires against it. "
            "(Applies to depth=danger / scan_mode=benchmark only.)"
        )
    except Exception:
        return None


def _collect_completion_blockers(data: dict, effective: set) -> list[str]:
    """Run all completion gate checks and return the list of blocker strings."""
    blockers: list[str] = []

    # Skill-chain gates HARD-BLOCK completion only on the enforcing (full / capable
    # cloud) profile. On local/weak profiles (medium+small, enforce_coverage=False)
    # they are ADVISORY — still surfaced in recovery/status, but not a completion wall
    # — because a weak model that already exploited the domains shouldn't be wedged for
    # not formally running each skill workflow (the game-then-stall failure).
    from mcp_server.scan_engine.budget import get_profile
    if get_profile().get("enforce_coverage", True):
        blockers.extend(_st._gate_blockers())
        # Three-phase: advance the phase to saturation first, then block completion until
        # SYNTHESIS (Phase C) so all three phases actually run — a run can't finish early in
        # the deep pass (A) and skip breadth (B) + synthesis (C). Dischargeable by progressing
        # (each phase saturates); the operator's force-complete still bypasses it. CTF/benchmark
        # runs are exempt (single-flag goal — phase bookkeeping is overhead, same as coverage).
        if not _st._has_ctf_flag(data):
            phase_blocker = _phase_completion_blocker()
            if phase_blocker:
                blockers.append(phase_blocker)
    blockers.extend(_st._qa_blockers())
    blockers.extend(_st._escalation_lead_blockers(data))

    # Deep-pivot (danger/benchmark): unscanned internal hosts block completion on every
    # profile/phase. No-op for normal scans.
    dp_blocker = _deep_pivot_host_blocker()
    if dp_blocker:
        blockers.append(dp_blocker)

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
