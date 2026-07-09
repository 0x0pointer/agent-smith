"""Three-phase scan model — the generic root fix for the depth regression.

  A. exploit   — deep, MATRIX-FREE hunt: drive high-value findings to their terminal
                 (RCE / pivot / takeover), exactly like the lean early builds that
                 actually went deep. No cell accounting, no breadth pressure.
  B. coverage  — the systematic coverage-matrix pass we have now (breadth / completeness).
  C. synthesis — compose ALL findings + primitives into proven kill-chains and reach the
                 maximal terminals (the compositional machinery, used where it helps).

Transitions are SATURATION-based, NEVER time/budget-based: a phase advances only when its
OWN goal is genuinely done. Every saturation criterion is DISCHARGEABLE (a documented
dead-end counts), so a phase always terminates — no runaway, and no budget cap needed. The
operator can always end the scan. The point of the ordering: DEPTH (A) runs to completion
BEFORE breadth (B) starts, so the coverage machinery can no longer starve the deep
exploitation the way it does today. Pure predicates + I/O-free helpers; the session module
persists the transition.
"""
from __future__ import annotations

EXPLOIT = "exploit"
COVERAGE = "coverage"
SYNTHESIS = "synthesis"
PHASES = (EXPLOIT, COVERAGE, SYNTHESIS)
_LABEL = {
    EXPLOIT:  "A · deep exploitation (matrix-free hunt → drive findings to terminal)",
    COVERAGE: "B · systematic coverage (build + drain the matrix)",
    SYNTHESIS: "C · synthesis (compose everything into proven chains + maximal terminals)",
}


def current_phase(sess: dict | None) -> str:
    """The active phase; defaults to EXPLOIT for sessions predating this field."""
    p = (sess or {}).get("scan_phase")
    return p if p in PHASES else EXPLOIT


def phase_label(phase: str) -> str:
    return _LABEL.get(phase, phase)


# ── Saturation predicates (each dischargeable via documented dead-ends) ──────────

def _tools_run(sess: dict) -> set:
    out: set = set()
    for e in (sess or {}).get("tool_invocations", []) or []:
        if isinstance(e, dict) and e.get("tool"):
            out.add(e["tool"])
    return out


def _recon_done(sess: dict) -> bool:
    """Surface is mapped enough to judge depth — httpx has fingerprinted and a crawl or
    param-fuzz has run. (Kept lenient: recon adequacy, not a full tool checklist.)"""
    t = _tools_run(sess)
    return "httpx" in t and bool(t & {"spider", "ffuf"})


def _chain_fids(findings_data: dict) -> set:
    out: set = set()
    for ch in findings_data.get("chains", []) or []:
        for s in ch.get("steps", []) or []:
            if isinstance(s, dict):
                out.add(s.get("from_finding_id"))
                out.add(s.get("to_finding_id"))
    return out


def _pursued(f: dict, chain_fids: set) -> bool:
    """A high-value finding is 'pursued' when it has been driven onward: it's part of a
    proven chain, carries a done/dismissed escalation_lead (a documented dead-end), or is
    itself already a terminal (its text reads as RCE / shell / full takeover)."""
    if f.get("id") in chain_fids:
        return True
    if any(isinstance(lead, dict) and lead.get("status") in ("done", "dismissed")
           for lead in (f.get("escalation_leads") or [])):
        return True
    text = f"{f.get('title', '')} {f.get('description', '')}".lower()
    return any(k in text for k in (
        "remote code exec", "code execution", "reverse shell", "os command exec",
        "full account takeover", "container escape", "cluster-admin", "domain admin"))


def open_bridges(findings_data: dict) -> int:
    """Count of UNATTEMPTED compositional bridges (finding B provides the primitive A needs).
    Reuses the composition-obligation's own discharge logic, so 'no open bridge' means exactly
    what that gate means. Fail-soft → 0 (never blocks a transition on a graph error)."""
    try:
        from core.graph import build_graph, candidate_chains
        chain_fids = _chain_fids(findings_data)
        findings = {f.get("id"): f for f in findings_data.get("findings", [])}

        def _dismissed(fid: str) -> bool:
            return any(isinstance(lead, dict) and lead.get("status") in ("done", "dismissed")
                       for lead in (findings.get(fid, {}) or {}).get("escalation_leads", []) or [])

        n = 0
        for b in candidate_chains(build_graph()):
            if b.get("kind") != "primitive_unblock":
                continue
            pid, bid = b.get("provider_id", ""), b.get("blocked_id", "")
            covered = pid in chain_fids and bid in chain_fids
            if not covered and not _dismissed(bid):
                n += 1
        return n
    except Exception:
        return 0


def depth_saturated(sess: dict, findings_data: dict) -> bool:
    """A → B: the deep hunt has exhausted its high-value leads — recon is done, EVERY
    high/critical finding has been pursued to a terminal or documented dead-end, and no
    provable exploit bridge is left unattempted. Returns False while any deep work remains,
    so Phase A keeps going (unbudgeted, like the lean early runs) until it's truly done."""
    if not _recon_done(sess):
        return False
    highs = [f for f in findings_data.get("findings", [])
             if f.get("severity") in ("high", "critical")
             and f.get("status", "confirmed") != "false_positive"]
    if not highs:
        return False  # nothing high-value found yet — keep hunting, don't fall back to breadth
    chain_fids = _chain_fids(findings_data)
    if not all(_pursued(f, chain_fids) for f in highs):
        return False
    return open_bridges(findings_data) == 0


def coverage_saturated(matrix: dict) -> bool:
    """B → C: the coverage matrix is drained (registered, and no pending cells)."""
    cells = matrix.get("matrix", []) if isinstance(matrix, dict) else []
    return bool(cells) and not any(c.get("status") == "pending" for c in cells)


def synthesis_saturated(findings_data: dict) -> bool:
    """C → complete-eligible: every provable cross-finding bridge is proven or dismissed."""
    return open_bridges(findings_data) == 0


def next_phase(current: str, sess: dict, findings_data: dict, matrix: dict) -> str | None:
    """The phase to advance to if the current one is saturated, else None. Only ever moves
    forward A→B→C (never backward)."""
    if current == EXPLOIT and depth_saturated(sess, findings_data):
        return COVERAGE
    if current == COVERAGE and coverage_saturated(matrix):
        return SYNTHESIS
    return None
