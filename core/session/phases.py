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
    """All tool names run this scan. Reads BOTH session lists because they use different
    vocabularies: `tools_called` holds the resolved SCANNER names (httpx/nmap/spider/naabu/... —
    the vocabulary _RECON_TOOLS is written in), while `tool_invocations[].tool` holds the raw
    dispatcher names (http_request/kali/...). Reading only tool_invocations (the original bug) left
    _recon_done permanently False on real scans — the scanner names live in tools_called — so
    depth_saturated was always False and the phase could never advance. Union both so recon is
    detected regardless of which list a tool lands in."""
    out: set = set()
    s = sess or {}
    for t in s.get("tools_called", []) or []:
        if isinstance(t, str) and t:
            out.add(t)
    for e in s.get("tool_invocations", []) or []:
        if isinstance(e, dict) and e.get("tool"):
            out.add(e["tool"])
    return out


# Any assessment skill whose attributable WORK means the deep hunt genuinely ran — web AND
# non-web (network / AD / cloud / mobile / TLS / AI / code), so no target class gets pinned in
# Phase A just because it never runs a web skill.
_HUNT_SKILLS = frozenset({
    "web-exploit", "api-security", "business-logic", "credential-audit", "param-fuzz",
    "post-exploit", "reverse-shell", "ai-redteam", "network-assess", "lateral-movement",
    "ad-assessment", "cloud-security", "container-k8s-security", "ssl-tls-audit",
    "metasploit", "android-security", "ios-security", "osint", "codebase",
})

# Recon-class tools across ALL target types — any one means the surface is mapped enough to
# judge depth (httpx=web, naabu/nmap=network, subfinder=host, mobsf=mobile, testssl=TLS,
# fuzzyai/garak=AI, semgrep/trufflehog=code). Target-agnostic so non-web scans aren't stuck.
_RECON_TOOLS = frozenset({
    "httpx", "spider", "ffuf", "naabu", "nmap", "subfinder", "nuclei", "mobsf", "mobsfscan",
    "testssl", "fuzzyai", "garak", "pyrit", "promptfoo", "semgrep", "trufflehog",
})

# Cell types with no auto-closer — expected to linger pending; must not pin Phase B (mirrors
# mcp_server.session_tools.coverage_gates._NO_AUTOCLOSER_TYPES; duplicated so core stays free
# of an mcp_server import).
_NO_AUTOCLOSER_TYPES = frozenset({"rate_limit", "method_tampering", "jwt", "race", "bfla"})


def _recon_done(sess: dict) -> bool:
    """Surface mapped enough to judge depth — ANY recon-class tool has run (not web-specific,
    so non-web target classes aren't pinned in Phase A)."""
    return bool(_tools_run(sess) & _RECON_TOOLS)


def _hunt_attempted(sess: dict) -> bool:
    """The deep hunt genuinely ran — an assessment skill did attributable WORK (the `worked`
    flag set by gates._mark_active_skill_worked), not merely a set_skill rubber-stamp."""
    return any(isinstance(s, dict) and s.get("skill") in _HUNT_SKILLS and s.get("worked")
               for s in (sess or {}).get("skill_history", []) or [])


def _worked_skills(sess: dict) -> set:
    """The set of skills that have done attributable WORK (a tool fired while active), by the
    same `worked` flag _hunt_attempted uses."""
    return {e.get("skill") for e in (sess or {}).get("skill_history", []) or []
            if isinstance(e, dict) and e.get("worked")}


def _enforce_deep_skills() -> bool:
    """Whether A→B requires the WHOLE applicable-skill sweep (full/enforcing profile) or just
    the single-skill bar (weak local profiles). Forcing the full sweep on a small model
    reproduces the coverage-gate 'game-then-stall', so those profiles keep the lighter bar.
    Fail-safe → True (the deep bar)."""
    try:
        from mcp_server.scan_engine.budget import get_profile
        return bool(get_profile().get("enforce_coverage", True))
    except Exception:
        return True


def _skills_exhausted(sess: dict) -> bool:
    """Every APPLICABLE hunt skill has actually WORKED — the deep-skill sweep is done, so Phase A
    ran all its skills (web-exploit AND param-fuzz AND business-logic AND credential-audit AND the
    conditional post-exploit/cloud/container/lateral ones), not just one. The mandatory
    skill-chain gates ARE the applicability logic: each is opened by a real trigger (an endpoint
    type discovered, or a confirmed RCE / IMDS / container / internal reach), so 'all gates
    satisfied' == 'all applicable skills ran' — no hand-kept list to drift. Reads the per-skill
    `worked` flags directly (not gate.status) so it doesn't depend on reconcile_worked_gates
    having run this cycle. DISCHARGEABLE and never a deadlock: a skill blocked by the environment
    still 'works' by running and documenting the dead-end, and the operator can N/A a gate. On
    weak profiles it delegates to the single-skill bar (already checked by depth_saturated)."""
    if not _enforce_deep_skills():
        return True
    worked = _worked_skills(sess)
    for g in (sess or {}).get("gates", []) or []:
        if g.get("status") == "satisfied":
            continue
        req = set(g.get("required_skills", []) or [])
        if req and not req.issubset(worked):
            return False
    return True


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
    """A → B: the deep hunt has exhausted its high-value leads. Phase A runs UNBUDGETED (like the
    lean early runs that went deep for hours) and advances only when ALL of these hold — each
    dischargeable, so it always terminates, but only once depth is genuinely mined out:
      1. recon has run AND at least one hunt skill did real work (the hunt started);
      2. every APPLICABLE hunt skill has run — all mandatory skill-chain gates worked, i.e. the
         FULL skill sweep, not just one skill (_skills_exhausted);
      3. every high/critical finding is PURSUED — driven to a terminal, or a documented
         dead-end (dismissed escalation_lead);
      4. no provable exploit BRIDGE is left unattempted.
    It deliberately does NOT advance on the model's own 'I want to sweep' signal: that breadth
    pull is the regression being fixed, so only objective depth-exhaustion moves the phase — the
    Phase-A DRAIN refusal instead redirects a premature sweep back into the deep work still owed."""
    if not _recon_done(sess) or not _hunt_attempted(sess):
        return False  # the deep hunt hasn't genuinely run yet — keep hunting
    if not _skills_exhausted(sess):
        return False  # applicable skills still owe their deep pass — keep hunting, don't drift to breadth
    highs = [f for f in findings_data.get("findings", [])
             if f.get("severity") in ("high", "critical")
             and f.get("status", "confirmed") != "false_positive"]
    # No un-pursued high-value finding AND no unattempted bridge → depth is exhausted. (When
    # highs is empty and the hunt has run, this correctly saturates — a hardened target moves
    # on to breadth rather than spinning in Phase A.)
    chain_fids = _chain_fids(findings_data)
    if not all(_pursued(f, chain_fids) for f in highs):
        return False
    return open_bridges(findings_data) == 0


def coverage_saturated(matrix: dict) -> bool:
    """B → C: no CLOSEABLE cell is still open. A cell blocks the transition only if it's
    testable-and-untested — pending OR in_progress (in_progress = started, not concluded) —
    AND of a type that can be closed; no-autocloser types (rate_limit/jwt/race/…) are expected
    to linger and are ignored, else Phase B could never saturate."""
    cells = matrix.get("matrix", []) if isinstance(matrix, dict) else []
    if not cells:
        return False
    return not any(
        c.get("status") in ("pending", "in_progress")
        and c.get("injection_type") not in _NO_AUTOCLOSER_TYPES
        for c in cells
    )


def synthesis_saturated(findings_data: dict) -> bool:
    """C → complete-eligible: every provable cross-finding bridge is proven or dismissed."""
    return open_bridges(findings_data) == 0


def next_phase(current: str, sess: dict, findings_data: dict, matrix: dict) -> str | None:
    """ADVISORY: the phase the current one COULD advance to if saturated, else None. Only ever
    forward A→B→C. Phases no longer AUTO-advance on this — it drives the dashboard 'ready to
    advance?' hint (see gates.maybe_advance_phase). The operator advances via gates.advance_phase."""
    if current == EXPLOIT and depth_saturated(sess, findings_data):
        return COVERAGE
    if current == COVERAGE and coverage_saturated(matrix):
        return SYNTHESIS
    return None


def forced_next(current: str) -> str | None:
    """Operator-forced next phase (IGNORES saturation) — one step forward, exploit→coverage→
    synthesis; None past synthesis. Used by the human-gated advance (gates.advance_phase)."""
    try:
        i = PHASES.index(current)
    except ValueError:
        i = 0
    return PHASES[i + 1] if i + 1 < len(PHASES) else None
