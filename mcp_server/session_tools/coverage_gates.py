"""Coverage-completeness completion gates (floor + findings-mapped)."""
import mcp_server.session_tools as _st
from .integrity_gates import _integrity_blockers


# Coverage gating threshold (percent of cells addressed). With auto-discovery
# producing matrices of 700-900 cells per OpenAPI spec, this is a HARD FLOOR
# only — exceeding it means the scan did real testing, not a wall demanding
# every cell be ground through. Pushing the model past the floor used to drive
# it into a canned-payload treadmill that produced false-negative tested_clean
# closures (see the coverage-grind regression analysis: one HTTP request was
# being reused to "close" 36 different injection cells).
_COVERAGE_FLOOR_PCT = 40

# Cross-cutting cell types that are fanned out for EVERY endpoint (taxonomy.py)
# but have NO automated closer anywhere — not the injection sweep (sweep.py) nor
# the cross-cutting auto-closer (autoclose.py handles only cors/csrf/
# security_headers/cache). Each can only be closed by a bespoke authenticated
# request, so on a 55-endpoint app they alone add 5×55=275 pure-manual cells and
# dominate the matrix. Counting them in the FLOOR denominator makes 40% demand
# hundreds of hand-tests the pipeline can't assist with, so the floor becomes
# practically unreachable and the model rationally abandons it. Exclude them from
# the floor's denominator (they still exist in the matrix and stay visible as
# advisory gaps + are honestly closable by hand) so the floor measures the work
# the automated closers (sweep + auto_crosscutting) CAN actually drive to done.
_NO_AUTOCLOSER_TYPES = {"rate_limit", "method_tampering", "jwt", "race", "bfla"}


def _floor_view(cov: dict, total: int, addressed: int) -> tuple[int, int, float]:
    """Recompute (total, addressed, pct) for the coverage FLOOR over only the cells
    the pipeline can help close — i.e. excluding _NO_AUTOCLOSER_TYPES. Falls back to
    the raw numbers when the matrix list isn't materialised (stub/partial matrices),
    so it never inflates coverage on a matrix it can't see."""
    matrix = cov.get("matrix", [])
    _addressed_states = ("tested_clean", "vulnerable", "not_applicable")
    excl_total = sum(1 for c in matrix if c.get("injection_type") in _NO_AUTOCLOSER_TYPES)
    excl_addr = sum(
        1 for c in matrix
        if c.get("injection_type") in _NO_AUTOCLOSER_TYPES
        and c.get("status") in _addressed_states
    )
    c_total = max(0, total - excl_total)
    c_addr = max(0, addressed - excl_addr)
    c_pct = (c_addr / c_total * 100) if c_total else 100.0
    return c_total, c_addr, c_pct


def _low_coverage_blocker(cov: dict, total: int, addressed: int, pct: float) -> str | None:
    """Block completion while the coverage matrix is substantially unworked.

    The matrix IS the deliverable — testing every endpoint/param is the job, and
    finding bugs happens *while* working it. So a scan does NOT 'complete' just
    because it found vulnerabilities; it completes when the matrix is worked (or a
    human approves the remaining gaps via the stuck-completion HIR). Fires below
    _COVERAGE_FLOOR_PCT; the caller skips it for CTF runs.

    This deliberately fires even for findings-rich scans (the old waiver let a scan
    'finish' at 5/840) and for every model profile (the floor was dormant for all).
    Anti-grind: it fires at COMPLETION — after the exploitation passes — so the
    model exploits first, then covers the rest with REAL probes; the honesty guards
    reject artifact-less / auth-blocked / mass-reused closures, and the message
    drives the next batch instead of inviting bulk not_applicable. The
    stuck-completion HIR (_MAX_COMPLETE_ATTEMPTS) is the safety valve when the model
    genuinely can't reach the floor, so this can't hard-stall.
    """
    # Judge the floor over the cells the automated closers can actually drive to
    # done — not the auto-fanned manual-only cross-cutting cells that inflate the
    # denominator into an unreachable wall.
    f_total, f_addr, f_pct = _floor_view(cov, total, addressed)
    if f_pct >= _COVERAGE_FLOOR_PCT:
        return None
    pending = sum(1 for c in cov.get("matrix", []) if c.get("status", "pending") == "pending")
    return (
        f"SCAN NOT COMPLETE — the coverage matrix is the deliverable and it is only {f_pct:.0f}% worked "
        f"({f_addr}/{f_total} closeable cells; {pending} still untested). Working the matrix IS the "
        f"remaining job, not optional bookkeeping — you do NOT finish by finding some bugs while most "
        f"cells are untested. Close cells FAST with the mechanized closers, not one-by-one: "
        f"(1) report(action='coverage', data={{type:'sweep', max_cells:60}}) repeatedly — it probes + "
        f"auto-closes pending injection cells (sqli/xss/ssti/cmdi/traversal) and hands you oracle-"
        f"positive candidates to confirm+file; (2) report(action='coverage', data={{type:'auto_"
        f"crosscutting'}}) to bulk-close app-wide CORS / security-header / CSRF / cache cells in one "
        f"call. For what remains, report(action='coverage', data={{type:'next_batch'}}) → test with "
        f"REAL probes (sqlmap / nuclei / targeted payloads — never canned filler) → close via "
        f"report(action='coverage', data={{type:'bulk_tested', updates:[...]}}). Mark a cell "
        f"not_applicable ONLY when the injection type is genuinely irrelevant to that param (with a "
        f"specific reason) — do NOT bulk-N/A to clear the count. Keep working the matrix; if you are "
        f"genuinely blocked the scan will pause for a human to approve the gaps."
    )

def _rich_exploitation(data: dict | None) -> bool:
    """True when the scan has found substantial real issues — used to waive the
    coverage floor (a findings-rich scan isn't 'trivially incomplete')."""
    findings = (data or {}).get("findings", []) if isinstance(data, dict) else []
    live = [f for f in findings if f.get("status") != "false_positive"]
    hi_crit = sum(1 for f in live if f.get("severity") in ("high", "critical"))
    return len(live) >= 8 or hi_crit >= 3


# Endpoint-default / cross-cutting cell types — closed by Phase 0 auto-close, NOT
# by the model mapping its exploitation findings. Excluded when checking that
# injection findings are reflected in the matrix.
_CROSSCUTTING_CELL_TYPES = {
    "cors", "csrf", "security_headers", "cache",
    "rate_limit", "method_tampering", "jwt", "race", "bfla",
}
# Keywords that mark a finding as an injection-class exploit — one that SHOULD be
# reflected as a vulnerable injection cell in the matrix.
_INJECTION_FINDING_KEYWORDS = (
    "sql inject", "sqli", "xss", "cross-site script", "ssti", "template inject",
    "command inject", "cmdi", "os command", "ssrf", "server-side request",
    "traversal", "path travers", "lfi", "rfi", "idor", "insecure direct object",
    "mass assign", "prototype pollut", "xxe", "nosql", "injection",
)


def _findings_mapped_blocker(cov: dict, data: dict | None) -> str | None:
    """Require a findings-rich scan to REFLECT its injection findings in the matrix.

    The % coverage floor is intentionally not enforced for a findings-rich scan
    (we don't grind every cell), but a scan that confirmed SQLi/XSS/… and filed
    findings yet marked ZERO injection cells leaves the matrix not reflecting what
    it actually exploited. This requirement is achievable (close one cell per
    finding) and does NOT re-create the grind stall — it asks only that the
    findings be mapped, not that every cell be tested.
    """
    findings = [f for f in (data or {}).get("findings", []) if f.get("status") != "false_positive"]
    inj_findings = [
        f for f in findings
        if f.get("severity") in ("high", "critical")
        and any(k in (f.get("title", "") + " " + f.get("description", "")).lower()
                for k in _INJECTION_FINDING_KEYWORDS)
    ]
    if not inj_findings:
        return None
    vuln_inj_cells = [
        c for c in cov.get("matrix", [])
        if c.get("status") == "vulnerable"
        and c.get("injection_type") not in _CROSSCUTTING_CELL_TYPES
    ]
    if len(vuln_inj_cells) >= len(inj_findings):
        return None
    return (
        f"FINDINGS NOT MAPPED TO MATRIX: {len(inj_findings)} confirmed injection finding(s) "
        f"(SQLi/XSS/SSTI/…) but only {len(vuln_inj_cells)} injection cell(s) marked vulnerable. "
        "The matrix must reflect what you exploited. For each injection finding, close its cell — "
        "find it with report(action='coverage', data={type:'list', injection_type:'sqli'}), then "
        "report(action='coverage', data={type:'tested', cell_id:'<id>', status:'vulnerable', "
        "finding_id:'<finding id>', artifact_id:'<proof>'}). Required even for a findings-rich "
        "scan — don't complete with your exploits unrecorded in the matrix."
    )


def _completeness_blockers(
    cov: dict, data: dict | None, total: int, addressed: int, pct: float,
) -> list[str]:
    """The two coverage-COMPLETENESS gates (low-coverage floor + findings-mapped) —
    they demand the model work MORE of the matrix. The caller applies the
    enforce_coverage profile guard + CTF bypass; for local (medium/small) profiles
    these never run, so the scan completes on findings like V1.0.2."""
    out: list[str] = []
    low_cov = _low_coverage_blocker(cov, total, addressed, pct)
    if low_cov:
        out.append(low_cov)
    mapped = _findings_mapped_blocker(cov, data)
    if mapped:
        out.append(mapped)
    return out


def _coverage_blockers(cov: dict, data: dict | None = None, ctf_mode: bool = False) -> list[str]:
    """Return coverage-related completion blockers for the given matrix state.

    For non-CTF runs, an empty matrix is a hard blocker if web testing happened —
    the agent must register endpoints in the matrix so the methodology is auditable
    and so re-spidering picks up new endpoints later. CTF mode bypasses this because
    benchmarks have a single flag goal where matrix bookkeeping is overhead.
    """
    # Phase A (deep exploitation) is MATRIX-FREE by design — the coverage matrix is built and
    # drained in Phase B. So no coverage pressure while an ACTIVE session is in scan_phase ==
    # exploit; otherwise the empty-matrix gate would wrongly demand matrix bookkeeping during
    # the deep hunt. (No active session → run the normal logic.)
    from core import session as _sess
    from core.session import phases as _phases
    _cur = _sess.get()
    if _cur and _phases.current_phase(_cur) == _phases.EXPLOIT:
        return []

    blockers: list[str] = []
    meta = cov.get("meta", {})
    total = meta.get("total_cells", 0)

    # Empty matrix gate — only enforced for non-CTF runs where web OR AI work happened.
    web_work_done = any(t in _st._effective_tools() for t in ("httpx", "spider", "ffuf", "nuclei"))
    ai_work_done = any(t in _st._effective_tools() for t in ("fuzzyai", "garak", "pyrit", "promptfoo"))
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
        elif not ctf_mode and ai_work_done:
            blockers.append(
                "EMPTY AI COVERAGE MATRIX: AI red-team tools were run "
                "(fuzzyai/garak/pyrit/promptfoo) but no LLM/MCP endpoint was registered. "
                "Register the chat/LLM (or MCP) endpoint so each OWASP LLM/MCP category becomes a "
                "closable cell: report(action='coverage', data={'type':'endpoint', 'path':'/...', "
                "'method':'POST', 'params':[{'name':'message','type':'llm_prompt'}], "
                "'discovered_by':'ai-redteam'}). For MCP tools add params with type 'mcp_tool_arg'. "
                "Then close each category cell with the scan's artifact_id. See /ai-redteam Phase 0."
            )
        return blockers

    # skipped cells do NOT count toward coverage — they are deferrals, not evidence.
    # Only tested_clean, vulnerable, and not_applicable are real coverage signals.
    # Use the pre-computed "addressed" counter from _recount(); fall back to the sum for
    # matrices written before this field existed.
    addressed = meta.get("addressed", meta.get("tested", 0) + meta.get("not_applicable", 0))
    pct = (addressed / total) * 100

    # Coverage-COMPLETENESS gates (low-coverage floor + findings-mapped) demand the
    # model work MORE of the matrix. They are profile-gated via enforce_coverage:
    # ON for full (a capable cloud model can work a 700-cell matrix), OFF for
    # medium/small. A local model has no in-loop injection-sweep tooling to honestly
    # close hundreds of cells, so a hard floor against an auto-fanned 700-cell matrix
    # just forces gaming (false tested_clean on 500s) and then a HIR_NO_PROGRESS
    # stall — V1.0.2 ran the local model coverage-dormant and it completed cleanly on
    # findings. Flip medium→enforce_coverage once the automated endpoint_sweep lands.
    # The current coverage % stays visible in session(status)/recovery, so the gap is
    # still surfaced as an advisory. The closure-INTEGRITY guards below
    # (artifact-backed, suspect-N/A, skipped-no-evidence) stay on for EVERY profile.
    from mcp_server.scan_engine.budget import get_profile
    enforce_cov = bool(get_profile().get("enforce_coverage", True))

    if enforce_cov and not ctf_mode:
        blockers.extend(_completeness_blockers(cov, data, total, addressed, pct))

    blockers.extend(_integrity_blockers(cov.get("matrix", []), enforce_cov, ctf_mode))
    return blockers
