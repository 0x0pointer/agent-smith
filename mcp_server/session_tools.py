"""
Consolidated session tool — replaces scan.py and infra.py
"""
import asyncio
import json
import os
import re
from typing import Any

from core import cost as cost_tracker
from core import findings as findings_store
from core import logger as log
from core import session as scan_session
from core.taxonomy import BYPASS_REQUIRED_TYPES as _BYPASS_REQUIRED_TYPES
from mcp_server._app import mcp, _ensure_dict, _session_tools_called
from mcp.server.fastmcp import Context

_background_tasks: set[asyncio.Task] = set()  # keeps fire-and-forget tasks alive

# Track completion attempts — after _MAX_COMPLETE_ATTEMPTS the scan escalates to HIR
_complete_attempts = 0
_MAX_COMPLETE_ATTEMPTS = 8

# Blocker count from the previous complete() attempt. Under condensed (small/
# medium) profiles, blockers are surfaced ONE AT A TIME, so a model legitimately
# fixing them across several complete() calls would otherwise trip the 8-attempt
# HIR. When the count DROPS (progress), we refund the attempt budget. None = no
# prior attempt this scan.
_last_blocker_count: int | None = None

# Minimum complete() calls required before thorough scans are allowed to finish.
# Each blocked call is one "iteration" — the model must go deeper and try again.
# This is the FULL-profile default; _min_iterations() scales it down by profile.
_THOROUGH_MIN_ITERATIONS = 3


def _min_iterations() -> int:
    """Profile-aware thorough-pass requirement (full=3, medium=2, small=1).

    A 16-32K-token local model cannot hold three deep analysis passes in context;
    capable (full-profile) models keep the full 3, honouring the white-box-3-passes
    rule for them. Small/medium reduce so the run is completable instead of looping.
    """
    try:
        from mcp_server.scan_engine.budget import get_profile
        return int(get_profile().get("thorough_min_passes", _THOROUGH_MIN_ITERATIONS))
    except Exception:
        return _THOROUGH_MIN_ITERATIONS


def _condensed_directives() -> bool:
    """True under medium/small profiles — serialize blockers + emit digest directives."""
    try:
        from mcp_server.scan_engine.budget import get_profile
        return bool(get_profile().get("condensed_directives", False))
    except Exception:
        return False

# Counts complete() calls that passed ALL quality checks (no PoC gaps, no missing reproductions,
# no coverage blockers).  Separate from _complete_attempts so that quality-fix attempts (where
# the model just added missing PoC files) do NOT count as genuine analysis passes.
# The iteration gate uses _analysis_passes, not _complete_attempts.
_analysis_passes = 0

_QA_STATE_FILENAME = "qa_state.json"


# ── CTF flag pattern (e.g. CTF{...}, flag{...}, HTB{...}) ─────────────────────
_FLAG_RE = re.compile(r'\w{2,10}\{[A-Za-z0-9_\-!@#$%^&*()+=,.?]{4,}\}')


def _has_ctf_flag(data: dict) -> bool:
    """Return True when this looks like a CTF/benchmark run.

    CTF/benchmark runs are allowed to skip coverage matrix population because
    the goal is flag extraction, not methodology auditability.  Detection:
      1. Session explicitly started with ctf=True in session.json.
      2. A finding contains a recognisable CTF flag pattern (e.g. CTF{...}).
    """
    current = scan_session.get() or {}
    if current.get("ctf"):
        return True
    for f in data.get("findings", []):
        text = f"{f.get('title', '')} {f.get('evidence', '')} {f.get('description', '')}"
        if _FLAG_RE.search(text):
            return True
    return False


def _effective_tools() -> set[str]:
    """Return the union of in-memory tracked tools and tools persisted in session.json.

    Using only _session_tools_called loses tool history after an MCP process
    restart; using only session.json misses tools added in the current process
    before the next flush.  Merging both gives the correct picture in all cases.
    """
    current = scan_session.get() or {}
    return _session_tools_called | set(current.get("tools_called", []))


def _client_from_ctx(ctx) -> str | None:
    """Map the MCP ``initialize`` handshake's ``clientInfo.name`` to a canonical
    Smith client (claude | opencode | codex). Per-connection and unambiguous —
    unlike TCP/PID scanning it isn't confused by several clients sharing the SSE
    server. Returns None when ctx/clientInfo is absent or unrecognized."""
    try:
        name = (ctx.session.client_params.clientInfo.name or "").lower()
    except Exception:
        return None
    for key in ("opencode", "codex", "claude"):
        if key in name:
            return key
    return None


def _record_handshake_client(ctx) -> None:
    """On session.start(), lock the session to the client the MCP handshake
    names — authoritative, overriding the best-effort TCP/PID detection that
    mislabels the scan when a dev Claude Code session shares the SSE server with
    the opencode scanner. No-op when the handshake doesn't identify a client."""
    name = _client_from_ctx(ctx)
    if not name:
        return
    try:
        from core.session.process_detect import _detect_smith_caller
        caller = _detect_smith_caller(prefer_client=name)
        scan_session.set_smith_proc(caller["pid"], name, "mcp_handshake")
        log.note(f"client locked from MCP handshake: {name} (pid={caller['pid']})")
    except Exception as e:
        log.note(f"handshake client record failed: {e}")


@mcp.tool()
async def session(action: str, options: dict | str | None = None, ctx: Context | None = None) -> str:
    """Scan lifecycle and infrastructure management.

    action  : start | complete | status | recovery | artifact | qa_reply | set_skill | set_step | wishlist_add | wishlist_list | start_kali | stop_kali | start_metasploit | stop_metasploit | pull_images | set_codebase

    wishlist_add options (NON-BLOCKING agent→operator backlog — use instead of
      marking a cell not_applicable when you're blocked by a missing resource):
      need= (required — what you need to go deeper, e.g. "analyst-role creds for /admin"),
      category= (credentials|scope|rate_limit|tooling|access|environment|other),
      rationale=, blocking_cell_ids=[...]. Does NOT pause the scan; keep testing
      other coverage. Auth needs already satisfiable from known_assets are rejected.

    wishlist_list: returns the open wishlist (what you've asked the operator for)

    start options:
      target, depth=standard (recon|standard|thorough), scope=[],
      out_of_scope=[], max_cost_usd=, max_time_minutes=, max_tool_calls=,
      model_profile=full (full|medium|small) — controls output verbosity

    complete options: notes=

    qa_reply options:
      message= (your response to the QA agent's alerts — what you acknowledge and what
                you plan to do. Call this immediately after session(action="status")
                returns qa_alerts so the QA ↔ Smith conversation log is complete.)

    status: returns current scan state (target, tools run, findings, cost)

    recovery: returns compact recovery brief after context compaction — tells you
              exactly what to do next. Call this if you lost context.

    artifact options:
      id= (artifact ID from tool response), mode=summary (summary|head|tail|grep|full),
      max_chars=4000, pattern= (regex for grep mode)

    set_skill options:
      skill= (name of the active skill, e.g. "pentester", "ai-redteam")
      reason= (why this skill was chosen — shown in logs)
      chained_from= (parent skill name when chaining, omit for first skill)

    set_step options:
      step= (current workflow step, e.g. "5_nuclei_scan")

    set_codebase options:
      path= (absolute path to local codebase)

    start_kali, stop_kali, start_metasploit, stop_metasploit, pull_images: no options needed
    """
    opts = _ensure_dict(options) or {}
    # Force-reload from disk on EVERY action.
    #
    # The MCP server runs in its own process with its own _current cache.
    # Three cross-process events can rewrite session.json behind us:
    #   • Dashboard's "Clear All"     → deletes session.json
    #   • Dashboard's "Complete Scan" → flips status to "complete"
    #   • Dashboard HIR resolution    → flips status back to "running"
    #
    # Without force=True, our cache stays at whatever it last wrote (often
    # intervention_required from a prior HIR), and `_do_start` then blocks
    # a fresh scan with "SCAN PAUSED" even though disk is clean. The
    # earlier `if action != "start"` carve-out made start the worst case
    # — it had to be force=True precisely to catch the post-Clear state,
    # but was getting nothing at all.
    #
    # Cost is one stat()+read() per session() call. session() fires ~5-10
    # times per scan (start, status, recovery, complete, qa_reply, …), so
    # the overhead is negligible compared to the cross-process desync it
    # closes.
    scan_session.load_from_disk(force=True)
    result = await _dispatch_async_action(action, opts)
    if result is None:
        result = _dispatch_sync_action(action, opts)
    if action == "start":
        # Lock the session to the client named in the MCP initialize handshake
        # (authoritative, per-connection) — overrides the ambiguous PID scan.
        _record_handshake_client(ctx)
    return result


async def _dispatch_async_action(action: str, opts: dict) -> str | None:
    """Handle async session actions. Returns None if action is not async."""
    if action == "start_kali":
        return await _do_start_kali()
    if action == "stop_kali":
        return await _do_stop_kali()
    if action == "start_metasploit":
        return await _do_start_metasploit()
    if action == "stop_metasploit":
        return await _do_stop_metasploit()
    if action == "pull_images":
        return await _do_pull_images()
    if action == "qa_reply":
        return await _do_qa_reply(opts)
    if action == "oob_start":
        return await _do_oob_start()
    if action == "oob_poll":
        return await _do_oob_poll(opts)
    if action == "complete":
        # Async so we can propagate app-wide cross-cutting verdicts to their cells
        # (best-effort) before the completion gate evaluates coverage.
        await _autoclose_crosscutting_best_effort()
        return _do_complete()
    return None


def _dispatch_sync_action(action: str, opts: dict) -> str:
    """Handle sync session actions."""
    if action == "start":
        return _do_start(opts)
    if action == "status":
        return _do_status()
    if action == "set_skill":
        return _do_set_skill(opts)
    if action == "set_step":
        return _do_set_step(opts)
    if action == "set_codebase":
        return _do_set_codebase(opts)
    if action == "recovery":
        return _do_recovery()
    if action == "artifact":
        return _do_artifact(opts)
    if action == "pre_chain":
        return _do_pre_chain(opts)
    if action == "resume":
        return _do_resume(opts)
    if action == "intervene":
        return _do_intervene(opts)
    if action == "wishlist_add":
        return _do_wishlist_add(opts)
    if action == "wishlist_list":
        return _do_wishlist_list()
    if action == "oob_mint":
        return _do_oob_mint(opts)
    return f"Unknown action '{action}'. Use: start, complete, status, qa_reply, recovery, artifact, pre_chain, set_skill, set_step, resume, wishlist_add, wishlist_list, start_kali, stop_kali, start_metasploit, stop_metasploit, pull_images, set_codebase, oob_start, oob_mint, oob_poll"


def _reset_coverage_matrix(target: str, prev_target: str, has_data: bool) -> bool:
    """Reset/init coverage matrix. Returns True if this is a resume of the same target."""
    from core.coverage import COVERAGE_FILE, _save as _cov_save, get_matrix
    from datetime import datetime, timezone
    import shutil

    if prev_target and prev_target != target and has_data:
        # Different target — archive the old matrix AND archive (not delete) quick_log + qa_state
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        archive_dir = COVERAGE_FILE.parent / "logs"
        archive_dir.mkdir(exist_ok=True)
        archive_path = archive_dir / f"coverage_matrix_{ts}.json"
        shutil.copy2(COVERAGE_FILE, archive_path)
        log.note(f"Coverage matrix archived to {archive_path.name} (previous target: {prev_target})")
        for stale in ("quick_log.json", _QA_STATE_FILENAME):
            p = COVERAGE_FILE.parent / stale
            if p.exists():
                archive_stale = archive_dir / f"{p.stem}_{ts}.json"
                shutil.copy2(p, archive_stale)
                p.unlink()
        _cov_save({
            "meta": {
                "created": datetime.now(timezone.utc).isoformat(),
                "target": target,
                "total_cells": 0, "tested": 0, "in_progress": 0,
                "vulnerable": 0, "not_applicable": 0, "skipped": 0,
            },
            "endpoints": [],
            "matrix": [],
        })
    elif not has_data and not COVERAGE_FILE.exists():
        # No coverage file at all — create an empty one
        _cov_save({
            "meta": {
                "created": datetime.now(timezone.utc).isoformat(),
                "target": target,
                "total_cells": 0, "tested": 0, "in_progress": 0,
                "vulnerable": 0, "not_applicable": 0, "skipped": 0,
            },
            "endpoints": [],
            "matrix": [],
        })
    # Same target with existing data — keep matrix as-is (resume or view results)
    return bool(prev_target and prev_target == target and has_data)


def _norm_target(s) -> str:
    """Normalise a target so http://x/ and HTTP://X compare equal (mirrors report_tools)."""
    return re.sub(r"\s+", " ", str(s or "").strip().lower()).rstrip("/")


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _prior_findings_brief(target: str) -> str:
    """Compact 'already known — don't re-file' brief for prior findings on this target.

    findings.json persists across runs; surfacing what is already recorded lets a
    re-run skip known issues and weight effort toward untested coverage instead of
    re-discovering (and the dedup gate re-blocking) the same app-wide misconfig.
    Prior false_positives are excluded — they should NOT discourage a re-test.
    """
    try:
        data = findings_store._load()
    except Exception:
        return ""
    ntg = _norm_target(target)
    if not ntg:
        return ""
    prior = [
        f for f in data.get("findings", [])
        if _norm_target(f.get("target")) == ntg
        and str(f.get("status") or "").strip().lower() != "false_positive"
    ]
    if not prior:
        return ""
    prior.sort(key=lambda f: _SEV_ORDER.get(str(f.get("severity", "")).lower(), 5))
    lines = [
        f"KNOWN FINDINGS for this target ({len(prior)} on record from prior run(s) — do NOT re-file; "
        "the server deduplicates same target+title+severity). Weight THIS run toward untested "
        "coverage cells and gaps the prior run(s) missed:",
    ]
    lines += [
        f"  - [{str(f.get('severity', '')).upper()}] {f.get('title', '')} (id={f.get('id', '?')})"
        for f in prior[:12]
    ]
    if len(prior) > 12:
        lines.append(f"  - (+{len(prior) - 12} more — see findings.json)")
    return "\n".join(lines)


def _start_first_move(classification: dict, target: str) -> str:
    """Advisory 'recommended first tool call' line, by target kind."""
    kind = classification["kind"]
    if kind == "codebase":
        return f"  session(action='set_codebase', options={{'path': '{target}'}}) then scan(tool='semgrep', target='{target}')"
    if kind == "network":
        return f"  scan(tool='naabu', target='{target}')"
    if kind == "cloud":
        return f"  Invoke {classification['skill_prior']} (cloud posture — no httpx web scan)"
    return f"  scan(tool='httpx', target='{target}')"  # api / web


def _start_response(cfg: dict, classification: dict, target: str, scan_mode: str,
                    depth: str, is_resume: bool) -> str:
    """Build the human-facing scan-start message (advisory routing + EXECUTE NOW)."""
    lim = cfg["limits"]
    cost_str = f"${lim['max_cost_usd']:.2f}" if lim['max_cost_usd'] is not None else "unlimited"
    time_str = f"{lim['max_time_minutes']}min" if lim['max_time_minutes'] is not None else "unlimited"
    call_limit_str = f"{lim['max_tool_calls']} tool calls" if lim['max_tool_calls'] > 0 else "unlimited"
    log.note(
        f"Scan started — target={target}  depth={depth}  "
        f"limits: {cost_str} / {time_str} / {call_limit_str}"
    )
    mode_label = (
        "BENCHMARK (auto-exploit critical findings)" if scan_mode == "benchmark"
        else "Pentest (human-in-the-loop for exploitation decisions)"
    )
    first_move = _start_first_move(classification, target)
    lines = [
        "Scan started.",
        f"  Target: {target} | Depth: {cfg['depth_label']} | Mode: {mode_label} | Limits: {cost_str}/{time_str}/{call_limit_str}",
        f"  Target classification (advisory — override if recon says otherwise): "
        f"kind={classification['kind']} → recommended {classification['skill_prior']} "
        f"({classification['reason']})",
        f"  Model profile: {cfg.get('model_profile', 'full')} "
        f"({cfg.get('model_profile_reason', 'default')}) — scopes context/output budgets. "
        f"Override with options={{model_profile: 'full|medium|small'}} or env SMITH_MODEL_PROFILE.",
        "",
    ]
    if scan_mode == "benchmark":
        lines += [
            "BENCHMARK MODE: On critical/high findings, do NOT pause — exploit the chain autonomously.",
            "Demonstrate full impact: RCE → execute commands, SQLi → dump data, SSRF → pivot internally.",
            "Document every step as a finding. All other safety checks and HIR triggers remain active.",
            "",
        ]
    prior_brief = _prior_findings_brief(target)
    if prior_brief:
        lines += [prior_brief, ""]
    if is_resume:
        lines += [
            "RESUME DETECTED: existing scan state found for this target.",
            "Recovery state follows — read it before issuing any tool calls:",
            "",
            _do_recovery(),
            "",
        ]
    try:
        from core.adjunction import anti_fp_digest
        lines += [anti_fp_digest(), ""]
    except Exception:
        pass
    lines += [
        "EXECUTE NOW (do not ask questions, do not output text):",
        "  report(action='dashboard', data={'port': 7777})",
        first_move if not is_resume else "  Continue from recovery state above — follow EXECUTE_NOW field.",
        "",
        "Then in order (skip steps in tools_already_run if this is a resume):",
        f"  scan(tool='naabu', target='{target}')",
        f"  scan(tool='spider', target='{target}')",
        "  Register endpoints with report(action='coverage', data=...)",
        f"  scan(tool='nuclei', target='{target}')",
        "  Test each coverage cell with http() or kali()",
        "",
        "Skills available for full workflow automation (invoke instead of improvising):",
        "  /pentester /web-exploit /param-fuzz /business-logic /codebase /ai-redteam",
        "  /cloud-security /ad-assessment /network-assess /lateral-movement /credential-audit",
        "  /post-exploit /container-k8s-security /osint /ssl-tls-audit /email-security",
        "  /metasploit /reverse-shell /analyze-cve /threat-modeling /aikido-triage",
        "  /gh-export /remediate /request-cves",
        "  See CLAUDE.md for full skill descriptions and trigger conditions.",
        "",
        "DEFINITION OF DONE: this scan is complete when the COVERAGE MATRIX is worked —",
        "every endpoint/param tested or justified not_applicable — NOT when you've found",
        "some bugs. Finding vulnerabilities happens WHILE you work the matrix; it is not a",
        "substitute for it. After each tool call you'll be handed the next cells to test;",
        "keep working them. Completion is coverage-gated and will be refused while the",
        "matrix is mostly untested.",
    ]
    return "\n".join(lines)


def _do_start(opts):
    global _complete_attempts, _analysis_passes, _last_blocker_count
    existing = scan_session.get() or {}
    if existing.get("status") == "intervention_required":
        return (
            "SCAN PAUSED — awaiting human intervention. "
            "Respond via session(action='resume', options={choice: '...', message: '...'}) "
            "before starting a new scan."
        )
    _complete_attempts = 0
    _analysis_passes = 0
    _last_blocker_count = None
    _session_tools_called.clear()
    target = opts.get("target", "")

    # Coverage matrix lifecycle: only reset when the target changes.
    # Same target = keep matrix (resume interrupted scan or view completed results).
    # Different target = archive old matrix, then reset.
    from core.coverage import get_matrix

    prev = scan_session.get()
    prev_target = prev.get("target", "") if prev else ""
    cov = get_matrix()
    has_data = len(cov.get("matrix", [])) > 0
    is_resume = _reset_coverage_matrix(target, prev_target, has_data)
    depth = opts.get("depth", "standard")
    scan_mode = str(opts.get("scan_mode", "pentest")).lower()
    if scan_mode not in ("pentest", "benchmark"):
        scan_mode = "pentest"
    cfg = scan_session.start(
        target=target, depth=depth,
        scope=opts.get("scope"),
        out_of_scope=opts.get("out_of_scope"),
        max_cost_usd=opts.get("max_cost_usd"),
        max_time_minutes=opts.get("max_time_minutes"),
        max_tool_calls=opts.get("max_tool_calls"),
        skill=opts.get("skill"),
        model_profile=opts.get("model_profile"),  # None → auto-detect from env
        scan_mode=scan_mode,
    )
    # Deterministic target classification — an advisory PRIOR, never a gate. It
    # never overrides the LLM's own skill routing; it just makes the recommended
    # first move fit the target kind so AUTONOMOUS/CI runs don't greet a codebase
    # path or an IP range with a web scan. Stored for the dashboard too.
    from core.target_class import classify_target
    classification = classify_target(target)
    _cur = scan_session.get()
    if _cur is not None:
        _cur["classifier"] = classification
        scan_session._flush()
    try:
        from core.adjunction.log import clear as _adj_log_clear
        _adj_log_clear()
    except Exception:
        pass
    # Purge stale adjudication/triage steering directives on every scan start.
    # These ride get_active() into the spawn prompt (core/api_server/smith.py)
    # and the session status/recovery responses, so an un-acknowledged review
    # directive left over from a prior run (operator triage that never finished,
    # or a legacy FORCE_COMPLETE_ADJUDICATION) would otherwise replay into this
    # fresh run and drive Smith straight into adjudication with no operator
    # action. Starting a scan is a deliberate reset; the operator re-triggers
    # triage via the dashboard button if they want it.
    try:
        from core.steering import steering_queue
        steering_queue.cancel_by_trigger("TRIAGE_ADJUDICATION", "cleared on new scan start")
        steering_queue.cancel_by_trigger("FORCE_COMPLETE_ADJUDICATION", "cleared on new scan start")
    except Exception:
        pass
    return _start_response(cfg, classification, target, scan_mode, depth, is_resume)


# Coverage gating threshold (percent of cells addressed). With auto-discovery
# producing matrices of 700-900 cells per OpenAPI spec, this is a HARD FLOOR
# only — exceeding it means the scan did real testing, not a wall demanding
# every cell be ground through. Pushing the model past the floor used to drive
# it into a canned-payload treadmill that produced false-negative tested_clean
# closures (see the coverage-grind regression analysis: one HTTP request was
# being reused to "close" 36 different injection cells).
_COVERAGE_FLOOR_PCT = 40


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
    if pct >= _COVERAGE_FLOOR_PCT:
        return None
    pending = sum(1 for c in cov.get("matrix", []) if c.get("status", "pending") == "pending")
    return (
        f"SCAN NOT COMPLETE — the coverage matrix is the deliverable and it is only {pct:.0f}% worked "
        f"({addressed}/{total} cells; {pending} still untested). Working the matrix IS the remaining "
        f"job, not optional bookkeeping — you do NOT finish by finding some bugs while most cells are "
        f"untested. Get the next cells + their exact requests with report(action='coverage', "
        f"data={{type:'next_batch'}}), test them with REAL probes (sqlmap / nuclei / targeted "
        f"payloads — never canned filler), then close each with its artifact via "
        f"report(action='coverage', data={{type:'bulk_tested', updates:[...]}}). Mark a cell "
        f"not_applicable ONLY when the injection type is genuinely irrelevant to that param (with a "
        f"specific reason) — do NOT bulk-N/A to clear the count. Keep working the matrix; if you are "
        f"genuinely blocked the scan will pause for a human to approve the gaps."
    )


def _skipped_no_evidence_blocker(all_cells: list[dict]) -> str | None:
    _WAF_KEYWORDS = ("403", "429", "waf", "blocked", "rate limit", "firewall")
    skipped = [
        c for c in all_cells
        if c["status"] == "skipped"
        and not any(kw in c.get("notes", "").lower() for kw in _WAF_KEYWORDS)
    ]
    if not skipped:
        return None
    sample = ", ".join(c["id"] for c in skipped[:5])
    if len(skipped) > 5:
        sample += f" ... ({len(skipped) - 5} more)"
    return (
        f"INTEGRITY: {len(skipped)} cell(s) marked skipped without WAF block "
        f"evidence (403/429/WAF) in notes: {sample}. "
        f"'skipped' is only valid when a WAF blocked the request — add the response evidence or re-test."
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
    blockers: list[str] = []
    meta = cov.get("meta", {})
    total = meta.get("total_cells", 0)

    # Empty matrix gate — only enforced for non-CTF runs where web work happened.
    web_work_done = any(t in _effective_tools() for t in ("httpx", "spider", "ffuf", "nuclei"))
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


def _integrity_blockers(all_cells: list[dict], enforce_cov: bool, ctf_mode: bool) -> list[str]:
    """Closure-INTEGRITY gates — reject cells that LIE about being tested (no
    artifact, suspect-N/A, skipped-without-evidence, N/A-without-bypass). These run
    for EVERY profile (they prevent false data, they don't demand more work).
    Injection-breadth follows enforce_coverage (it demands MORE cells). Extracted
    from _coverage_blockers to keep that function under the cognitive-complexity cap."""
    out: list[str] = []
    from core.coverage import cell_has_test_evidence
    untooled = [c for c in all_cells
                if c["status"] in ("tested_clean", "vulnerable") and not cell_has_test_evidence(c)]
    if untooled:
        out.append(
            f"INTEGRITY: {len(untooled)} cell(s) marked tested/vulnerable but cite no "
            f"artifact_id. Re-test these cells and pass the artifact_id from the tool response."
        )
    suspect_na = _suspect_na_cells(all_cells, _BYPASS_REQUIRED_TYPES)
    if suspect_na:
        sample = ", ".join(suspect_na[:5]) + ("..." if len(suspect_na) > 5 else "")
        out.append(
            f"INTEGRITY: {len(suspect_na)} cell(s) marked N/A without testing bypass "
            f"techniques: {sample}. Test the bypass before marking N/A."
        )
    skipped_blocker = _skipped_no_evidence_blocker(all_cells)
    if skipped_blocker:
        out.append(skipped_blocker)
    na_blocker = _na_untooled_blocker(all_cells, _BYPASS_REQUIRED_TYPES)
    if na_blocker:
        out.append(na_blocker)
    # Injection-breadth is also a completeness gate (demands MORE cells registered/
    # tested), so it follows enforce_coverage too — advisory for local.
    breadth_blocker = _injection_breadth_blocker(all_cells, enforce_cov and not ctf_mode)
    if breadth_blocker:
        out.append(breadth_blocker)
    return out


def _na_untooled_blocker(cells: list[dict], bypass_types: dict) -> str | None:
    """Return a blocker string if any bypass-type N/A cells cite no test evidence."""
    from core.coverage import cell_has_test_evidence
    na_untooled = [
        c for c in cells
        if c["status"] == "not_applicable"
        and not cell_has_test_evidence(c)
        and c.get("injection_type") in bypass_types
    ]
    if not na_untooled:
        return None
    sample = ", ".join(f"{c['id']} ({c['injection_type']})" for c in na_untooled[:5])
    if len(na_untooled) > 5:
        sample += f" ... ({len(na_untooled) - 5} more)"
    return (
        f"INTEGRITY: {len(na_untooled)} injection-type N/A cell(s) cite no artifact_id "
        f"of a bypass attempt: {sample}. Run the bypass technique and pass its artifact_id before marking N/A."
    )


def _injection_breadth_blocker(cells: list[dict], coverage_enforced: bool) -> str | None:
    """Return a blocker if text params have sqli cells but no xss/ssti/ssrf/cmdi cells."""
    _BREADTH_REQUIRED = {"xss", "ssti", "ssrf", "cmdi"}
    _TEXT_PARAM_TYPES = {"query", "body_form", "body_json", "path", "header", "cookie"}
    from collections import defaultdict
    by_param: dict[tuple, set] = defaultdict(set)
    for c in cells:
        if c.get("param_type") in _TEXT_PARAM_TYPES and c.get("param") != "_endpoint":
            by_param[(c["endpoint_id"], c["param"])].add(c["injection_type"])
    breadth_gaps: list[str] = []
    for (_ep_id, param), inj_types in by_param.items():
        if "sqli" not in inj_types:
            continue
        missing = _BREADTH_REQUIRED - inj_types
        if missing:
            breadth_gaps.append(f"'{param}' (missing: {', '.join(sorted(missing))})")
    if not breadth_gaps or not coverage_enforced:
        return None
    sample = "; ".join(breadth_gaps[:5])
    more = f" (+{len(breadth_gaps) - 5} more)" if len(breadth_gaps) > 5 else ""
    return (
        f"INJECTION BREADTH: {len(breadth_gaps)} text param(s) have sqli cells but no "
        f"xss/ssti/ssrf/cmdi cells — these injection types were never registered for these params. "
        f"Re-register the endpoint(s) or add the missing cells with report(action='coverage'): "
        f"{sample}{more}"
    )


def _suspect_na_cells(cells: list[dict], bypass_types: dict) -> list[str]:
    """Return cell IDs/types marked N/A without bypass justification."""
    suspect = []
    for c in cells:
        if c["status"] != "not_applicable" or c["injection_type"] not in bypass_types:
            continue
        cell_notes = c.get("notes", "")
        bypass = bypass_types[c["injection_type"]]
        keywords = bypass.lower().split(", ")
        if not any(kw in cell_notes.lower() for kw in keywords) and len(cell_notes) < 40:
            suspect.append(f"{c['id']} ({c['injection_type']})")
    return suspect


def _qa_blockers() -> list[str]:
    """Return completion blockers from open high-urgency, blocking QA alerts."""
    qa_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), _QA_STATE_FILENAME)
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


def _is_whitebox_scan() -> bool:
    """Return True when the active scan is a white-box code review rather than a live pentest.

    Signals:
    - set_codebase() was called (PENTEST_TARGET_PATH is set to a local directory)
    - semgrep or trufflehog appear in the tools called this session
    - The active or most-recent skill is 'codebase'
    """
    if os.environ.get("PENTEST_TARGET_PATH"):
        return True
    effective = _effective_tools()
    if effective & {"semgrep", "trufflehog"}:
        return True
    current = scan_session.get() or {}
    skill_history = current.get("skill_history", [])
    if skill_history:
        last_skill = skill_history[-1].get("skill", "")
        if last_skill == "codebase":
            return True
        if any(s.get("skill") == "codebase" for s in skill_history):
            return True
    return False


def _deepen_brief_condensed(iteration: int, whitebox: bool) -> str:
    """Short deepen brief for medium/small profiles — 3 concrete next actions, no prose.

    The full multi-thousand-char briefs overwhelm a small-context model; under a
    condensed profile the thorough gate also requires fewer passes (_min_iterations),
    so the brief only needs to point at the highest-value next moves.
    """
    data = findings_store._load()
    criticals = [f for f in data.get("findings", []) if f.get("severity") == "critical"]
    mi = _min_iterations()
    if whitebox:
        actions = [
            "Trace each injection-class finding source-to-sink and confirm the sanitizer is "
            "actually bypassable; attach the call chain to the finding's evidence.",
            "Read the trust-boundary interfaces between the top components — what attacker-"
            "controlled value crosses, and is it re-validated on arrival?",
            "For each critical, determine what an attacker reaches AFTER exploiting it and "
            "record escalation_leads.",
        ]
    else:
        actions = [
            "Re-test every tested_clean cell with a deeper technique (higher sqlmap level/risk, "
            "filter-bypass XSS, blind/OOB) — these are your likely false negatives.",
            "Test the next pending coverage cells; mark each in_progress before testing.",
            "Chain the criticals to maximum impact: record escalation_leads + a kill-chain via "
            "report(action='chain').",
        ]
    numbered = "\n".join(f"  {i + 1}. {a}" for i, a in enumerate(actions))
    return (
        f"⛔ ITERATION GATE: analysis pass {iteration}/{mi} done — one condensed deepening pass "
        f"required ({len(criticals)} critical finding(s) on record). Do these, then call "
        f"session(action='complete') again:\n{numbered}"
    )


def _deepen_brief_whitebox(analysis_pass: int) -> str:
    """
    Generate a mandatory re-run brief for white-box code-review iteration gates.
    Each pass deepens the analysis rather than re-running live exploitation tools.
    analysis_pass is 1-indexed: 1 = just finished pass 1, need pass 2; 2 = need pass 3.
    """
    if _condensed_directives():
        return _deepen_brief_condensed(analysis_pass, whitebox=True)
    data = findings_store._load()
    findings = data.get("findings", [])
    criticals = [f for f in findings if f.get("severity") == "critical"]
    highs = [f for f in findings if f.get("severity") == "high"]
    finding_summary = f"{len(findings)} findings ({len(criticals)} critical, {len(highs)} high)"

    steps: list[str] = []

    if analysis_pass == 1:
        # Pass 2: deeper cross-component tracing and ASVS gap coverage
        intro = (
            f"⛔ WHITEBOX ITERATION GATE: Analysis pass 1/{_THOROUGH_MIN_ITERATIONS} done — "
            f"thorough white-box review requires {_THOROUGH_MIN_ITERATIONS} passes. "
            "Pass 2 must go deeper: cross-component data flow tracing, ASVS gap coverage, "
            "and second-order flaws. Execute ALL steps below before calling complete() again:"
        )
        steps.append(
            "SOURCE-TO-SINK TRACING — for every injection-class finding (SQL injection, "
            "command injection, SSTI, path traversal, deserialization), trace the full data "
            "flow from the HTTP entry point through every function call to the dangerous sink. "
            "Read each intermediate function to verify whether sanitization actually occurs "
            "or is bypassable. Document the complete call chain in the finding's evidence field."
        )
        steps.append(
            "CROSS-COMPONENT ANALYSIS — read the interfaces between the top 5 highest-risk "
            "components (e.g. FHIRdoor → Aidbox, medikit-experiment → K8s API, "
            "Keycloak/Zitadel → Aidbox). For each interface: what data crosses the trust "
            "boundary? What validation is performed on arrival? What can an attacker-controlled "
            "value at the source become at the destination? Log any new findings from this analysis."
        )
        steps.append(
            "ASVS GAP COVERAGE — go through each ASVS 5.0 chapter not yet covered in pass 1 "
            "and explicitly verify each requirement against the code. Minimum chapters to cover "
            "if not already done: V6 (Authentication), V7 (Session Management), V8 (Authorization), "
            "V9 (Self-contained Tokens), V10 (OAuth/OIDC), V11 (Cryptography), V13 (Configuration), "
            "V14 (Data Protection), V16 (Security Logging). For each chapter, read the relevant "
            "source files and log a finding or note confirming whether each requirement is met."
        )
        steps.append(
            "SECOND-ORDER AND STORED FLAWS — identify all places where user-supplied data is "
            "stored (database, cache, files, K8s secrets, FHIR resources) and then later "
            "retrieved and used in a security-sensitive operation. Does the retrieval path "
            "re-validate the data? Can a value stored safely now be used dangerously later "
            "(stored XSS, second-order SQLi, YAML/pickle deserialization of stored blobs)?"
        )
        steps.append(
            "DEPENDENCY AUDIT — run scan(tool='semgrep') again with 'p/security-audit' and "
            "'p/owasp-top-ten' rulesets if not already run. For every high-severity CVE-tagged "
            "dependency found, trace whether the vulnerable code path is actually reachable "
            "from the application's attack surface."
        )
        if criticals:
            unchained = [f for f in criticals if not f.get("escalation_leads")]
            if unchained:
                titles = ", ".join(f["title"][:50] for f in unchained[:3])
                steps.append(
                    f"KILL CHAIN COMPLETION — {len(unchained)} critical finding(s) have no "
                    f"escalation_leads set ({titles}{'...' if len(unchained) > 3 else ''}). "
                    "For each: read the relevant code to determine what an attacker can do AFTER "
                    "exploiting this finding. What data can be exfiltrated? What next component "
                    "can be reached? What is the maximum blast radius? Update each finding with "
                    "escalation_leads pointing to the next step in the kill chain."
                )

    elif analysis_pass == 2:
        # Pass 3: adversarial mindset — chained attacks, edge cases, maximum coverage
        intro = (
            f"⛔ WHITEBOX ITERATION GATE: Analysis pass 2/{_THOROUGH_MIN_ITERATIONS} done — "
            "one final pass required at maximum adversarial depth. "
            "Pass 3 must find what passes 1 and 2 missed by combining findings and "
            "attacking edge cases. Execute ALL steps below before calling complete() again:"
        )
        steps.append(
            "CHAINED EXPLOIT PATHS — take the top 3 pairs of findings and reason through "
            "whether exploiting finding A makes finding B easier or newly exploitable. "
            "Example patterns: committed secret → auth bypass → RBAC escalation → bulk data read; "
            "CORS bypass + weak session token → cross-site PHI exfiltration; "
            "IMDS access → managed identity → ACR write → supply chain → all pods compromised. "
            "For each viable chain: read the relevant code to confirm the path is real, "
            "then log a new finding (or update existing ones) with the full chain evidence."
        )
        steps.append(
            "BUSINESS LOGIC EDGE CASES — for every FHIR operation and access-control decision "
            "in the codebase, ask: what happens at the boundary? Can a null/empty/zero value "
            "bypass a check? Can a list with zero items pass an 'all items must satisfy X' check? "
            "Can a race condition between two concurrent requests produce an inconsistent state? "
            "Read the relevant policy evaluation code and test edge cases analytically."
        )
        steps.append(
            "CONFIGURATION VS CODE MISMATCHES — compare what the infrastructure configuration "
            "(K8s manifests, ArgoCD values, Terraform) declares vs. what the application code "
            "actually expects. Look for: environment variables the code reads but the manifest "
            "doesn't set (falls back to insecure default); secrets the code expects to be "
            "present but may be absent in some environments; TLS settings the code assumes "
            "but the infra doesn't enforce."
        )
        steps.append(
            "REMAINING ASVS VERIFICATION — go through any ASVS chapters still unverified "
            "from passes 1 and 2. For each unmet requirement, either confirm it is met by "
            "reading the code or log it as a finding. Produce a final ASVS coverage note "
            "using report(action='note') summarising which chapters are covered, which are "
            "partially covered, and which are absent."
        )
        steps.append(
            "END-TO-END POC SCRIPTS — for each critical finding that has only an HTTP template "
            "PoC, write a self-contained Python or shell script that executes the full exploit "
            "from scratch (no manual steps). Save each with http(action='save_poc') and link "
            "it to the finding_id. The script must include: credential/token acquisition, "
            "the exploit request, and verification of impact."
        )

    else:
        intro = (
            f"⛔ WHITEBOX ITERATION GATE: Pass {analysis_pass}/{_THOROUGH_MIN_ITERATIONS} — "
            "quality gates still blocking. Re-run all code review activities at maximum depth."
        )
        steps.append(
            "Re-read every component not yet fully analyzed, deepen every finding with "
            "additional code evidence, and ensure all high/critical findings have complete "
            "source-to-sink call chains documented in their evidence field."
        )

    steps.append(
        f"Current state: {finding_summary}. "
        "After completing ALL steps above, call session(action='complete') again."
    )
    numbered = "\n".join(f"  {i + 1}. {step}" for i, step in enumerate(steps))
    return f"{intro}\n{numbered}"


def _deepen_steps_pass1(
    has_ai_ep: bool, skills_run: set, unchained: list
) -> list[str]:
    steps: list[str] = []
    steps.append(
        "Re-invoke /web-exploit (SECOND PASS) — reset all tested_clean cells to pending "
        "and re-test them with deeper payloads: sqlmap --level=4 --risk=3, "
        "XSS with CSP/filter bypass variants, SSTI with all engine templates, "
        "blind/OOB SQLi with out-of-band callbacks, second-order injection testing. "
        "Every endpoint that returned tested_clean in pass 1 is a candidate for a "
        "false negative — test again with a different technique."
    )
    steps.append(
        "Re-invoke /param-fuzz (SECOND PASS) — run with larger wordlists "
        "(burp-parameter-names.txt + raft-large-words.txt), test every parameter "
        "for HTTP verb tampering, auth header stripping, type confusion "
        "(string→int→array→null), and mass assignment on ALL endpoints including "
        "those that returned 4xx in pass 1 (try different HTTP methods)."
    )
    steps.append(
        "Re-invoke /business-logic (SECOND PASS) — run all 9 phases again: "
        "send concurrent requests (10 parallel) to every state-changing endpoint, "
        "test negative/zero/overflow values on EVERY numeric field found, "
        "replay all one-time tokens and confirmation codes, test BOLA on every "
        "resource ID found in the app, enumerate sequential IDs across all "
        "resource types."
    )
    if has_ai_ep or "ai-redteam" in skills_run:
        steps.append(
            "Re-invoke /ai-redteam (SECOND PASS) — run PyRIT crescendo (10 turns), "
            "Garak with full probe set (dan,encoding,promptinject,leakreplay,gcg,glitch,"
            "grandma,goodside,snowball,misleading,packagehallucination,malwaregen), "
            "and manual multi-objective authority-marker payloads on all AI endpoints."
        )
    steps.append(
        "Re-run nuclei with ALL template categories: "
        "scan(tool='nuclei', templates='cve,exposure,misconfig,default-login,takeovers,"
        "technologies,token-spray,file-upload,xss,sqli,ssrf,lfi,rce,generic'). "
        "Also run scan(tool='ffuf') on every endpoint with raft-large-words.txt to "
        "discover hidden parameters and paths missed in pass 1."
    )
    if unchained:
        titles = ", ".join(f['title'][:40] for f in unchained[:3])
        steps.append(
            f"Chain {len(unchained)} unchained critical finding(s) to maximum impact "
            f"({titles}{'...' if len(unchained) > 3 else ''}): "
            "SQLi → dump all tables → crack hashes → use creds everywhere; "
            "SSRF → scan internal network → hit cloud metadata → exfil IAM keys; "
            "RCE → establish reverse shell → run LinPEAS → escalate to root."
        )
    return steps


def _deepen_steps_pass2(
    criticals: list, has_ai_ep: bool, skills_run: set
) -> list[str]:
    steps: list[str] = []
    steps.append(
        "Re-invoke /web-exploit (THIRD PASS — MAXIMUM AGGRESSION) — "
        "sqlmap --level=5 --risk=3 --technique=BEUSTQ --tamper=space2comment,between,"
        "randomcase,charunicodeencode on every injection point; "
        "run commix on ALL parameter inputs for blind OS command injection; "
        "test HTTP request smuggling (CL.TE and TE.CL) on every HTTP/1.1 endpoint; "
        "probe all endpoints for CRLF injection and web cache poisoning; "
        "test deserialization on every cookie and binary parameter (pickle, Java, PHP)."
    )
    steps.append(
        "Re-invoke /param-fuzz (THIRD PASS) — fuzz with the full "
        "10-million-password-list as a parameter wordlist; test parameter pollution "
        "(duplicate params in query string + body simultaneously); inject into "
        "HTTP headers (X-Forwarded-For, X-Original-URL, X-Rewrite-URL, "
        "X-Custom-IP-Authorization) on every auth-gated endpoint; "
        "test GraphQL introspection and batching abuse if any /graphql endpoint exists."
    )
    steps.append(
        "Re-invoke /business-logic (THIRD PASS) — run Phase 5 (idempotency) with "
        "50 concurrent requests on every state-changing endpoint; "
        "test all time-based attacks (expired token reuse, cooldown bypass); "
        "perform full multi-tenant isolation testing across all user accounts; "
        "enumerate ALL resource IDs sequentially (orders, transfers, loans, cards, "
        "payments) across EVERY user to confirm or deny BOLA at scale."
    )
    if has_ai_ep or "ai-redteam" in skills_run:
        steps.append(
            "Re-invoke /ai-redteam (THIRD PASS) — run PyRIT with jailbreak + "
            "crescendo + multi-turn prompt injection (15 turns each); "
            "test excessive agency by attempting tool invocations with hidden params "
            "(include_internal=True, admin=True, debug=True, show_all=True); "
            "test indirect prompt injection via every data field the AI reads "
            "(usernames, transaction notes, profile fields, filenames)."
        )
    steps.append(
        "Run kali(command='nikto -h TARGET -C all -maxtime 300') for full server "
        "misconfiguration scan; run testssl.sh against every HTTPS endpoint; "
        "run enum4linux-ng if any SMB/LDAP ports are open; "
        "run wapiti with all modules against the full app."
    )
    steps.append(
        f"Produce one end-to-end chain PoC for EACH critical finding ({len(criticals)} total) "
        "that demonstrates the full kill chain from initial access to maximum impact. "
        "Each PoC must be a single executable curl/python script that requires zero "
        "manual steps. Save every PoC with http(action='save_poc') linked to its finding_id."
    )
    return steps


def _deepen_brief(iteration: int) -> str:
    """
    Generate a mandatory re-run brief for thorough-depth iteration gates.
    Each iteration re-executes ALL applicable skills and tools with escalating
    aggressiveness — not advisory hints, but concrete ordered commands.
    """
    if _condensed_directives():
        return _deepen_brief_condensed(iteration, whitebox=False)
    from core.coverage import get_matrix
    data      = findings_store._load()
    current   = scan_session.get() or {}
    findings  = data.get("findings", [])
    criticals = [f for f in findings if f.get("severity") == "critical"]
    highs     = [f for f in findings if f.get("severity") == "high"]
    cov       = get_matrix()

    pending_cells  = [c for c in cov.get("matrix", []) if c["status"] == "pending"]
    clean_cells    = [c for c in cov.get("matrix", []) if c["status"] == "tested_clean"]

    skills_run = {s["skill"] for s in current.get("skill_history", [])}
    endpoints  = current.get("known_assets", {}).get("endpoints", [])
    has_ai_ep  = any("ai" in ep or "chat" in ep or "llm" in ep for ep in endpoints)

    unchained  = [f for f in criticals if not f.get("escalation_leads")]
    finding_summary = (
        f"{len(findings)} findings ({len(criticals)} critical, {len(highs)} high)"
    )

    # ── Build the ordered mandatory re-run list ─────────────────────────────────
    if iteration == 1:
        steps = _deepen_steps_pass1(has_ai_ep, skills_run, unchained)
        intro = (
            f"⛔ ITERATION GATE: Pass 1/{_THOROUGH_MIN_ITERATIONS} done — "
            "thorough depth requires {_THOROUGH_MIN_ITERATIONS} full passes. "
            "RE-RUN ALL TOOLS NOW, harder than pass 1. "
            "Execute every step below before calling complete() again:"
        ).format(_THOROUGH_MIN_ITERATIONS=_THOROUGH_MIN_ITERATIONS)
    elif iteration == 2:
        steps = _deepen_steps_pass2(criticals, has_ai_ep, skills_run)
        intro = (
            f"⛔ ITERATION GATE: Pass 2/{_THOROUGH_MIN_ITERATIONS} done — "
            "one more full pass required at MAXIMUM aggression. "
            "Execute every step below before calling complete() again:"
        )
    else:
        steps = [
            f"Iteration {iteration}: re-run ALL skills at maximum depth again — "
            "the scan has not yet passed quality gates. "
            "Focus on any cells still pending or skipped, any findings without end-to-end PoCs, "
            "and any skill not invoked since the last iteration."
        ]
        intro = (
            f"⛔ ITERATION GATE: Pass {iteration}/{_THOROUGH_MIN_ITERATIONS} done — "
            "quality gates still blocking. "
            "Execute every step below before calling complete() again:"
        )

    steps.append(
        f"Current state: {finding_summary}, "
        f"{len(pending_cells)} cells pending, "
        f"{len(clean_cells)} cells marked clean (potential false negatives). "
        "After completing ALL steps above, call session(action='complete') again."
    )

    numbered = "\n".join(f"  {i + 1}. {step}" for i, step in enumerate(steps))
    return f"{intro}\n{numbered}"


def _collect_completion_blockers(data: dict, effective: set) -> list[str]:
    """Run all completion gate checks and return the list of blocker strings."""
    blockers: list[str] = []

    blockers.extend(_gate_blockers())
    blockers.extend(_qa_blockers())
    blockers.extend(_escalation_lead_blockers(data))

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
    quality_blocker = _finding_quality_blockers(high_findings)
    if quality_blocker:
        blockers.append(quality_blocker)

    # ── Final-QA adjudication ─────────────────────────────────────────────────
    # Always-on senior-review pass: every high/critical finding must carry a
    # reproducibility + recalibrated-severity verdict before completion. Runs
    # here (at completion) on purpose — never mid-scan, so discovery is not
    # interrupted and findings are judged with full chained context.
    from core.adjunction import adjudication_blockers
    blockers.extend(adjudication_blockers(data, digest=_condensed_directives()))

    from core.coverage import get_matrix
    blockers.extend(_coverage_blockers(get_matrix(), data=data, ctf_mode=_has_ctf_flag(data)))

    return blockers


def _persist_completion_counters() -> dict:
    """Flush attempt/pass counters to session.json and return current session."""
    current = scan_session.get() or {}
    if current:
        current["complete_attempts"] = _complete_attempts
        current["analysis_passes"] = _analysis_passes
        scan_session._flush()
    return current


def _apply_thorough_depth_gate(blockers: list, current: dict) -> list:
    """Increment analysis pass counter when quality-clean and append iteration blocker if needed.

    Returns the (possibly appended) blockers list.
    """
    global _analysis_passes
    depth = (scan_session.get() or {}).get("depth", "")
    if blockers or depth != "thorough":
        return blockers
    _analysis_passes += 1
    if current:
        current["analysis_passes"] = _analysis_passes
        scan_session._flush()
    if _analysis_passes < _min_iterations():
        brief = (
            _deepen_brief_whitebox(_analysis_passes)
            if _is_whitebox_scan()
            else _deepen_brief(_analysis_passes)
        )
        blockers.append(brief)
    return blockers


def _pending_steer_block() -> str:
    """Return a formatted block of pending steering directives, or ''.

    session() responses bypass the envelope wrapper, which is where
    steering directives are normally injected. When Smith is stuck in a
    complete()→HIR→resume loop, it never makes an envelope-wrapped tool
    call, so HUMAN_STEER messages from the dashboard pile up in
    steering_queue.json with status='pending' and are never seen.
    This helper surfaces them inline so the blocked path delivers them
    too. mark_injected is called so the envelope's nag mode picks up
    from here on the next non-session tool call.
    """
    try:
        from core.steering import steering_queue
        active = steering_queue.get_active()
        if not active:
            return ""
        # Prioritise HUMAN_STEER messages — those are the human waiting
        # for a reply. Other directives (QA-emitted) come below.
        human = [d for d in active if d.trigger == "HUMAN_STEER"]
        other = [d for d in active if d.trigger != "HUMAN_STEER"]
        lines = []
        for d in human:
            lines.append(f"  ⚠ HUMAN MESSAGE [{d.priority.upper()}]: {d.message}")
            steering_queue.mark_injected(d.id)
        for d in other:
            lines.append(f"  ⚠ STEERING [{d.priority.upper()}]: {d.message}")
            steering_queue.mark_injected(d.id)
        nag = (
            "REPLY TO THE HUMAN NOW so they see your response on the dashboard: "
            "call session(action='qa_reply', options={message: '<your reply>'}). "
            "Without this call your reply never reaches the human."
        ) if human else (
            "Acknowledge with session(action='qa_reply', options={message: '<your reply>'}) "
            "after acting on these directives."
        )
        return "\n\nPENDING DIRECTIVES (act on these BEFORE retrying complete()):\n" + \
               "\n".join(lines) + "\n" + nag
    except Exception:
        # Steering failures must never break tool dispatch.
        return ""


# Priority for surfacing ONE blocker at a time under condensed (small/medium)
# profiles — lower number = fix first. Concrete data prerequisites and required
# verdicts come before the "re-run deeper" iteration brief.
_BLOCKER_PRIORITY = (
    ("QA BLOCKER", 0),
    ("GATE [", 1),
    ("EMPTY COVERAGE MATRIX", 2),
    ("LOW COVERAGE", 2),
    ("INJECTION BREADTH", 3),
    ("INTEGRITY", 3),
    ("ADJUDICATION REQUIRED", 4),
    ("NO POC FILES", 5),
    ("FINDING QUALITY", 5),
    ("PENDING LEADS", 6),
    ("NO SPIDER", 7),
    ("NO DIAGRAM", 8),
    ("ITERATION GATE", 9),
)


def _blocker_priority(b: str) -> int:
    for key, pri in _BLOCKER_PRIORITY:
        if key in b:
            return pri
    return 5


def _build_blocker_response(blockers: list) -> str:
    """Build the blocked-completion response string or HIR JSON."""
    steer_block = _pending_steer_block()
    if _complete_attempts >= _MAX_COMPLETE_ATTEMPTS:
        attempts = _complete_attempts
        log.note(f"HIR triggered after {attempts} blocked complete() attempts. Blockers: {'; '.join(b[:80] for b in blockers)}")
        # Reframed situation text: blockers-first, options-are-for-human.
        # Earlier copy emphasised SKIP_CELLS / ACCEPT_PARTIAL which Smith
        # interpreted as "easy out" options for itself rather than human
        # override switches, leading to the 29-attempt cascade where
        # Smith picked the cheap "retry complete" path instead of doing
        # the actual blocker-fix work.
        scan_session.trigger_intervention(
            code="HIR_FORCE_COMPLETE",
            situation=(
                f"{len(blockers)} real quality-gate blocker(s) require actual work, "
                f"not retries. Smith called complete() {attempts} times instead of "
                "addressing them. The options below are HUMAN OVERRIDES — Smith "
                "should keep doing blocker work (re-test cells, chain required "
                "skills, file missing artifacts) until you tell it otherwise."
            ),
            tried=[f"complete() attempt {i+1}/{attempts}" for i in range(min(attempts, 5))],
            options=[
                "CONTINUE: Give Smith specific instructions to resolve the remaining blockers and it will retry (recommended)",
                "SKIP_CELLS: Tell Smith which specific cells or endpoint types to mark as skipped",
                "REDUCE_SCOPE: Specify which checks to drop (e.g. 'skip all rate_limit cells')",
                "ACCEPT_PARTIAL: Force-complete with current coverage; unresolved items flagged in the report",
            ],
        )
        payload = {
            "status": "HUMAN_INTERVENTION_REQUIRED",
            "code": "HIR_FORCE_COMPLETE",
            "situation": (
                f"complete() BLOCKED by {len(blockers)} real quality gates after "
                f"{attempts} attempts. DO NOT retry — address the blockers first. "
                "If a pending HUMAN MESSAGE is present, REPLY first via qa_reply."
            ),
            "blockers": blockers[:5],
            "options": [
                "CONTINUE — human gives specific blocker-fix instructions (recommended)",
                "SKIP_CELLS — specify cells/endpoint types to skip",
                "REDUCE_SCOPE — drop specific checks",
                "ACCEPT_PARTIAL — force-complete with documented gaps",
            ],
            "how_to_respond": "Use the dashboard 'Send to Smith' panel, or call session(action='resume', options={choice: '...', message: '...'})",
            "scan_paused": True,
        }
        result = json.dumps(payload, indent=2)
        if steer_block:
            result = result + steer_block
        return result
    depth = (scan_session.get() or {}).get("depth", "")
    total = len(blockers)
    if _condensed_directives() and total > 1:
        # Serialize: surface only the highest-priority blocker so it fits a small
        # context window. The progress-aware counter in _do_complete refunds the
        # attempt budget as the count drops, so one-per-call fixing won't trip HIR.
        shown = [min(blockers, key=_blocker_priority)]
        header = (
            f"complete BLOCKED — {total} blockers remain; fixing them ONE AT A TIME so each "
            f"fits your context. Fix THIS one, then call session(action='complete') again for "
            f"the next:\n\n"
        )
    elif depth == "thorough" and _analysis_passes < _min_iterations():
        shown = blockers
        _mi = _min_iterations()
        header = (
            f"complete BLOCKED — thorough scan requires {_mi} analysis passes "
            f"(quality-clean passes: {_analysis_passes}/{_mi}):\n\n"
        )
    else:
        shown = blockers
        header = f"complete BLOCKED (attempt {_complete_attempts}/{_MAX_COMPLETE_ATTEMPTS}) — fix the following first:\n\n"
    msg = header + "\n\n".join(f"  [{i+1}] {b}" for i, b in enumerate(shown))
    if steer_block:
        msg = msg + steer_block
    log.note(
        f"complete blocked (attempt {_complete_attempts}, analysis_passes={_analysis_passes}, "
        f"blockers={total}, shown={len(shown)}): {'; '.join(b[:80] for b in blockers)}"
    )
    return msg


async def _autoclose_crosscutting_best_effort() -> None:
    """Propagate app-wide cross-cutting verdicts to their cells before completion.

    The matrix fans cors/csrf/security_headers across every endpoint, but their
    verdict is app-wide — the model files the finding ("Wildcard CORS on all
    endpoints") yet rarely marks the 50+ per-endpoint cells, so the coverage gate
    sees an empty matrix and the scan wedges (the overnight no-progress loop).
    Running the honest propagator here (links the finding, cites a real response,
    marks GET-endpoint CSRF N/A) means a completion attempt automatically reflects
    the work already done. Best-effort + idempotent — only touches pending
    cross-cutting cells and never blocks completion.
    """
    try:
        from core import coverage as _cov
        from mcp_server.report_tools import _do_coverage_auto_crosscutting
        res = await _do_coverage_auto_crosscutting({"type": "auto_crosscutting"}, _cov)
        log.note(f"auto_crosscutting (pre-complete): {str(res)[:200]}")
    except Exception:
        log.note("auto_crosscutting (pre-complete) failed — non-fatal")


def _do_complete():
    global _complete_attempts, _analysis_passes, _last_blocker_count
    _complete_attempts += 1

    data = findings_store._load()
    current = _persist_completion_counters()

    effective = _effective_tools()
    blockers = _collect_completion_blockers(data, effective)
    blockers = _apply_thorough_depth_gate(blockers, current)

    # Progress-aware HIR (condensed profiles): blockers are surfaced one at a
    # time, so a model clearing them across several complete() calls is making
    # progress, not stalling. When the count DROPS, refund the attempt budget so
    # serialized fixing doesn't trip the 8-attempt HIR; HIR still fires when the
    # count is stuck (genuine inability to progress).
    if _condensed_directives() and blockers:
        n = len(blockers)
        if _last_blocker_count is not None and n < _last_blocker_count:
            _complete_attempts = 1
        _last_blocker_count = n
    elif not blockers:
        _last_blocker_count = None

    if blockers:
        # Log the adjudication directive whenever the gate fires so the Activity
        # tab reflects that a review pass is owed.
        try:
            from core.adjunction import pending_findings
            from core.adjunction.log import log_directive
            pending = pending_findings(data)
            if pending:
                log_directive(pending)
        except Exception:
            pass
        return _build_blocker_response(blockers)

    _complete_attempts = 0
    _analysis_passes = 0

    # Only the human operator can mark a scan complete.
    # Smith passes all quality gates here — the scan is ready — but completion
    # is deliberately reserved for the human via the dashboard "Complete Scan"
    # button or the Instruct Smith panel.
    log.note(
        f"complete() called by Smith (attempt {_complete_attempts}) — "
        "all quality gates passed; awaiting human completion via dashboard."
    )

    # Inject any active steering directives directly into this response so
    # Smith sees them immediately without needing another tool call.
    # (session() bypasses the envelope pipeline, so directives won't reach
    # Smith otherwise if it stops making scan tool calls here.)
    try:
        from core.steering import steering_queue
        active = steering_queue.get_active()
        if active:
            directive_lines = "\n".join(
                f"  ⚠ STEERING [{d.priority.upper()}]: {d.message}" for d in active
            )
            steering_queue.mark_injected(active[0].id)
            return (
                "COMPLETION HELD — human sign-off required via dashboard.\n"
                "Do NOT summarise findings. Do NOT explain the situation to the user.\n"
                "EXECUTE NOW: act on the pending human instructions below, then call "
                "session(action='status') to check for more directives.\n\n"
                f"{directive_lines}"
            )
    except Exception:
        pass

    return (
        "COMPLETION HELD — human sign-off required via dashboard.\n"
        "Do NOT summarise findings. Do NOT explain the situation to the user. "
        "Do NOT call session(action='complete') again.\n"
        "EXECUTE NOW: call session(action='status') to check for pending QA alerts "
        "and steering directives, then act on them. Keep making tool calls."
    )


def _record_metrics(findings_data: dict, completion_blockers: list[str], force_completed: bool) -> None:
    try:
        import core.metrics as metrics_mod
        from core.quick_log import quick_log
        from core.steering import steering_queue
        from core.coverage import get_matrix
        metrics_mod.record(
            session=scan_session.get() or {},
            cost_summary=cost_tracker.get_summary(),
            findings_data=findings_data,
            coverage=get_matrix(),
            force_completed=force_completed,
            completion_blockers=completion_blockers,
            quick_log_entries=quick_log.read_all(),
            steering_history=steering_queue.get_history(),
        )
    except Exception:
        pass


async def _do_qa_reply(opts):
    """Log Smith's response to a QA steering directive and acknowledge it.

    Optionally references a specific directive_id to acknowledge. If omitted,
    the most recently injected directive is acknowledged automatically.
    """
    from core.quick_log import quick_log
    from core.steering import steering_queue
    message = str(opts.get("message", "")).strip()
    directive_id = str(opts.get("directive_id", "")).strip()
    if not message:
        return "qa_reply requires a non-empty message= option."

    ack_id: str | None = None
    if directive_id:
        if steering_queue.acknowledge(directive_id, message):
            ack_id = directive_id
    else:
        ack_id = steering_queue.acknowledge_latest_injected(message)

    await quick_log.append({
        "type":         "QA_REPLY",
        "message":      message,
        "directive_id": ack_id,
    })

    if ack_id:
        return f"QA reply logged. Directive {ack_id} acknowledged."
    return "QA reply logged. (No active directive to acknowledge — reply recorded for audit trail.)"


def _oob_config():
    """Read OOB backend config from env: (mode, server_url, token, poll_template)."""
    import os
    server = os.environ.get("OOB_SERVER_URL", "").strip()
    mode = _oob_module().resolve_mode(os.environ.get("OOB_MODE", ""))
    token = os.environ.get("OOB_SERVER_TOKEN", "").strip()
    poll_template = os.environ.get("OOB_POLL_URL", "").strip()
    return mode, server, token, poll_template


def _oob_module():
    from core import oob
    return oob


async def _do_oob_start():
    """Start/confirm the OOB backend. interactsh → launch the Kali client and
    return the minted domain; http → record the callback-logger base URL.

    Takes no options — the backend is configured entirely from env (_oob_config)."""
    from tools import kali_runner
    from core.session import assets as sess_assets
    oob = _oob_module()
    mode, server, token, poll_template = _oob_config()

    if mode == "http":
        if not server:
            return (
                "OOB_MODE=http needs OOB_SERVER_URL set to your HTTP request logger's base URL "
                "(e.g. https://oob-logger.example.com). Set it in .env and restart, or unset "
                "OOB_MODE to use interactsh's public servers."
            )
        sess_assets.set_oob_listener(server, mode="http", poll_url=poll_template)
        poll_note = (
            f"auto-poll via {poll_template}" if poll_template
            else "no OOB_POLL_URL set → polling will tell you to check the logger's own UI/logs"
        )
        return (
            f"OOB backend ready (mode=http, logger={server}; {poll_note}).\n"
            "Next: session(action='oob_mint', options={'cell_id': '<blind cell id>'}) to get a "
            "unique callback URL, embed it in your blind HTTP/SSRF payload, then "
            "session(action='oob_poll', options={'correlation_id': '<id>'}). NOTE: http mode is "
            "HTTP(S)-only — for DNS-based blind exfil use interactsh mode."
        )

    # interactsh mode
    cmd = oob.build_start_command(server_url=server, token=token)
    raw = await kali_runner.exec_command(cmd, timeout=60)
    base = oob.parse_base_domain(raw)
    if not base:
        return (
            "OOB listener start attempted, but no collaborator domain could be parsed from "
            "interactsh-client output. Check that the Kali container is up and OOB_SERVER_URL "
            "(if set) is reachable.\n--- interactsh output ---\n" + raw[:600]
        )
    sess_assets.set_oob_listener(base, out_file=oob.OOB_OUT_FILE, mode="interactsh")
    src = f"self-hosted {server}" if server else "public interactsh servers (oast.fun)"
    return (
        f"OOB listener ready (mode=interactsh, DNS+HTTP). Base collaborator domain: {base}  "
        f"(server: {src}).\n"
        "Next: session(action='oob_mint', options={'cell_id': '<blind cell id>'}) to get a unique "
        "callback host, embed it in your blind payload (SSRF/RCE/XXE/OAST-SQLi/DNS exfil), then "
        "session(action='oob_poll', options={'correlation_id': '<id>'}) to confirm the callback."
    )


def _do_oob_mint(opts):
    """Mint a unique callback (subdomain for interactsh, URL for http) under the
    active listener. Pure session-state work — no I/O, hence not async."""
    import uuid
    from datetime import datetime, timezone
    from core.session import assets as sess_assets
    oob = _oob_module()

    listener = sess_assets.get_oob_listener()
    base = (listener or {}).get("base_domain", "")
    if not base:
        return "No OOB listener running. Call session(action='oob_start') first."
    mode = (listener or {}).get("mode", "interactsh")
    correlation_id = uuid.uuid4().hex[:12]
    if mode == "http":
        callback = oob.mint_http_callback(base, correlation_id)
        embed_hint = f"Embed this URL in your blind HTTP/SSRF payload: {callback}"
    else:
        callback = oob.mint_subdomain(base, correlation_id)
        embed_hint = (
            f"Embed it in your blind payload — e.g. http://{callback}/ , a DNS lookup of "
            f"{callback}, or an XXE/SSRF target."
        )
    sess_assets.update_known_assets("oob_interactions", [{
        "subdomain": callback,
        "correlation_id": correlation_id,
        "linked_cell_id": str(opts.get("cell_id", "")),
        "minted_at": datetime.now(timezone.utc).isoformat(),
        "polled": False,
        "hits": 0,
    }])
    return (
        f"OOB callback minted: {callback}  (correlation_id={correlation_id}).\n"
        f"{embed_hint}\n"
        f"After firing, run session(action='oob_poll', options={{'correlation_id': "
        f"'{correlation_id}'}}). Registered in known_assets so it survives context compaction."
    )


async def _do_oob_poll(opts):
    """Poll the active backend for interactions matching a minted correlation id."""
    import json as _json
    from tools import kali_runner
    from core.session import assets as sess_assets
    from mcp_server.scan_engine.artifacts import store_artifact
    oob = _oob_module()

    correlation_id = str(opts.get("correlation_id", "")).strip()
    if not correlation_id:
        return "Missing correlation_id. Use the id returned by session(action='oob_mint')."
    listener = sess_assets.get_oob_listener()
    mode = (listener or {}).get("mode", "interactsh")

    if mode == "http":
        poll_url = oob.http_poll_url((listener or {}).get("poll_url", ""), correlation_id)
        if not poll_url:
            base = (listener or {}).get("base_domain", "")
            return (
                f"This OOB logger ({base}) has no OOB_POLL_URL configured, so the callback can't "
                f"be fetched automatically. Check the logger's own UI/logs for a request to a path "
                f"containing '{correlation_id}'. If it arrived, that confirms the blind vuln — save "
                "the log line as a PoC and file the finding."
            )
        raw = await kali_runner.exec_command(oob.build_http_poll_command(poll_url), timeout=30)
        hits = oob.parse_http_hits(raw, correlation_id)
    else:
        out_file = (listener or {}).get("out_file", oob.OOB_OUT_FILE)
        raw = await kali_runner.exec_command(oob.build_poll_command(out_file), timeout=30)
        hits = oob.parse_interactions(raw, correlation_id)

    sess_assets.mark_oob_polled(correlation_id, len(hits))
    if not hits:
        return (
            f"No OOB interactions for correlation_id={correlation_id} yet. Blind callbacks can "
            "lag — if you just fired the payload, wait and poll again. No callback after a "
            "reasonable wait is evidence the injection did NOT reach an OOB sink."
        )
    artifact_id = store_artifact("oob_interaction", _json.dumps(hits, indent=2))
    protos = ", ".join(sorted({str(h.get("protocol", "?")) for h in hits}))
    return (
        f"OOB CONFIRMED: {len(hits)} interaction(s) for {correlation_id} (protocols: {protos}). "
        f"artifact_id={artifact_id}. This is proof of a blind vulnerability — file "
        "report(action='finding', ...) for it, then close the blind cell vulnerable with this "
        "artifact_id and the returned finding_id."
    )


def _do_resume(opts: dict) -> str:
    """Human responded to a HUMAN_INTERVENTION_REQUIRED event.

    Transitions the scan back to 'running', records the human's choice,
    and injects a steering directive so Smith immediately knows what to do.
    """
    from core.steering import steering_queue, RESUME_REQUIRED
    choice  = str(opts.get("choice", "")).strip()
    message = str(opts.get("message", "")).strip()
    if not choice and not message:
        return (
            "resume requires choice= and/or message=. "
            "Example: session(action='resume', options={choice: 'ACCEPT_PARTIAL', message: 'Complete with documented gaps'})"
        )
    current = scan_session.get() or {}
    if current.get("status") not in ("intervention_required", "running"):
        return f"No active intervention to resolve. Current status: {current.get('status', 'none')}"

    scan_session.resolve_intervention(choice, message)
    human_instruction = f"Human resolved HIR with choice='{choice}'" + (f": {message}" if message else "")
    log.note(f"HIR resolved by human: {human_instruction}")
    steering_queue.add_directive(
        code=RESUME_REQUIRED,
        message=(
            f"HUMAN RESPONSE: {human_instruction}. "
            "Act on this instruction now, then call session(action='complete') when ready."
        ),
        priority="high",
        skill=None,
        trigger="HIR_RESOLVED",
    )
    return json.dumps({
        "status": "resumed",
        "message": "Scan resumed. Human instruction injected as steering directive.",
        "choice": choice,
        "instruction": message,
        "next": "Call session(action='recovery') to get your current position, then follow the steering directive.",
    }, indent=2)


def _do_intervene(opts: dict) -> str:
    """Manually trigger a HUMAN_INTERVENTION_REQUIRED event.

    Useful for QA checks that detect conditions warranting human review
    (repeated tool failure, auth expiry, etc.).
    """
    code      = str(opts.get("code", "HIR_MANUAL")).strip()
    situation = str(opts.get("situation", "Manual intervention requested.")).strip()
    tried     = opts.get("tried", [])
    options   = opts.get("options", [
        "CONTINUE — provide instructions to proceed",
        "ABORT — stop the scan",
    ])
    current = scan_session.get() or {}
    if not current or current.get("status") != "running":
        return f"No running scan to pause. Status: {current.get('status', 'none')}"
    scan_session.trigger_intervention(code, situation, tried, options)
    log.note(f"HIR manually triggered: {code} — {situation}")
    return json.dumps({
        "status": "HUMAN_INTERVENTION_REQUIRED",
        "code":      code,
        "situation": situation,
        "options":   options,
        "scan_paused": True,
        "how_to_respond": "session(action='resume', options={choice: '...', message: '...'})",
    }, indent=2)


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
    all_tools = sorted(_effective_tools())
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
    web_work_done = any(t in _effective_tools() for t in ("httpx", "spider", "ffuf", "nuclei"))
    if meta.get("total_cells", 0) == 0 and web_work_done and not _has_ctf_flag(data):
        result["coverage_warning"] = (
            "MATRIX EMPTY: web tools have run but no endpoints are registered. "
            "Register every discovered endpoint with report(action='coverage', "
            "data={'type': 'endpoint', 'path': ..., 'method': ..., 'params': [...], "
            "'discovered_by': 'spider'}). The matrix drives Phase 2's systematic "
            "per-cell testing and prevents you from forgetting which params you tested. "
            "complete_scan will be blocked until at least one endpoint is registered."
        )
    if remaining:
        result["remaining"] = {
            "cost_usd": remaining.get("cost_remaining_usd", 0),
            "time_min": remaining.get("time_remaining_minutes", 0),
            "calls": remaining.get("calls_remaining", -1),
        }
    spider_failures = scan_session.get_spider_failures()
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

    unsatisfied = scan_session.pending_gates()
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
    _qa_path = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), _QA_STATE_FILENAME)
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
        leads = [l for l in f.get("escalation_leads", []) if l.get("status") == "pending"]
        if leads:
            pending_escalations.append({
                "finding_id": f["id"],
                "title": f["title"],
                "pending_leads": [l["lead"] for l in leads],
            })

    tools_run = _effective_tools()
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
    try:
        return json.dumps(result, indent=2)
    except TypeError as e:
        # In-memory state can drift over long MCP uptimes (e.g. dict keys that
        # are tuples). Falling back to default=str lets the recovery brief
        # serialize so Smith can resume, rather than failing the whole call.
        log.note(f"recovery: json encoding fallback ({e}) — reloading from disk")
        scan_session.load_from_disk()
        return json.dumps(result, indent=2, default=str)


def _recovery_iter_status(current: dict) -> str | None:
    """Thorough-scan analysis-pass progress line for the recovery brief, or None."""
    if current.get("depth") != "thorough":
        return None
    analysis_iter = current.get("analysis_passes", _analysis_passes)
    mi = _min_iterations()
    remaining = max(0, mi - analysis_iter)
    return (
        f"Analysis pass {analysis_iter}/{mi} "
        f"({'complete — quality gates only' if remaining == 0 else f'{remaining} more required'})"
    )


def _recovery_auth_context(known_assets: dict) -> dict:
    """Compact auth context (creds / JWTs / login endpoints) for the recovery brief.

    Surfaced so Smith authenticates before testing auth-protected endpoints
    instead of marking them tested_clean on a 401/403.
    """
    creds = known_assets.get("credentials", [])
    tokens = known_assets.get("auth_tokens", [])
    auth_eps = known_assets.get("auth_endpoints", [])
    ctx: dict = {}
    if creds:
        ctx["credentials"] = creds[-5:]          # most recent 5
    if tokens:
        ctx["jwt_tokens"] = tokens[-3:]          # most recent 3, keep brief compact
    if auth_eps:
        ctx["login_endpoints"] = auth_eps[:3]
    if ctx:
        ctx["how_to_use"] = (
            "When an endpoint returns 401/403, send the JWT as 'Authorization: Bearer <value>'. "
            "If no token is valid, POST to a login endpoint with credentials to mint a new one. "
            "DO NOT mark cells tested_clean on 401/403 — the server returns 'REJECTED' now."
        )
    return ctx


def _build_recovery_result(
    current: dict,
    cov: dict,
    data: dict,
    extra_cells: int,
    unsatisfied_gates: list,
    pending_escalations: list,
    integrity_warnings: list,
    target: str,
    tools_run: set,
    action_list: list,
    next_call: str,
    resume_step: str,
) -> dict:
    meta = cov.get("meta", {})
    iter_status = _recovery_iter_status(current)
    auth_context = _recovery_auth_context(current.get("known_assets", {}))

    result = {
        "EXECUTE_NOW": next_call,
        "target": target,
        "phase": resume_step,
        "tools_already_run": sorted(tools_run),
        "coverage": f"{meta.get('tested', 0)}/{meta.get('total_cells', 0)}",
        "findings": len(data.get("findings", [])),
        "action_required": action_list,
        "TOOLS": (
            "Only use these 5 MCP tools. Do NOT use Skill or Read tools. "
            "scan(tool, target) | kali(command) | http(action, url) | "
            "report(action, data) | session(action)"
        ),
    }
    if auth_context:
        result["auth_context"] = auth_context
    if iter_status:
        result["iteration_progress"] = iter_status

    # Include known assets summary
    known_assets = current.get("known_assets", {})
    compact_assets = {k: v[:10] for k, v in known_assets.items() if v}
    if compact_assets:
        result["known_assets"] = compact_assets

    # Include recent tool invocations for context
    invocations = current.get("tool_invocations", [])
    if invocations:
        result["recent_tools"] = [
            {"tool": i["tool"], "summary": i["summary"]}
            for i in invocations[-5:]
        ]

    if extra_cells > 0:
        result["more_in_progress_cells"] = extra_cells

    if unsatisfied_gates:
        result["pending_gates"] = unsatisfied_gates
    if pending_escalations:
        result["pending_escalations"] = pending_escalations
    if integrity_warnings:
        result["integrity_warnings"] = integrity_warnings

    # Open wishlist items — needs Smith raised for the operator. Surfaced so a
    # fulfilled need (operator dropped in creds/scope) is picked up after
    # compaction and the linked cells get reopened instead of forgotten.
    try:
        from core.wishlist import wishlist_queue
        open_wish = wishlist_queue.list_open()
        if open_wish:
            result["wishlist_open"] = [
                {"id": w.id, "need": w.need, "category": w.category,
                 "blocking_cell_ids": w.blocking_cell_ids}
                for w in open_wish[:8]
            ]
    except Exception:
        pass

    return result


def _concrete_next_call(target: str, tools_run: set, in_progress: list, pending_count: int) -> str:
    """Return a single concrete tool call string the model should execute next."""
    if in_progress:
        cell = in_progress[0]
        return (
            f"Continue testing {cell['injection']} on {cell['endpoint']} param={cell['param']} "
            f"(cell {cell['cell_id']})"
        )
    if "httpx" not in tools_run:
        return f"scan(tool='httpx', target='{target}')"
    if "naabu" not in tools_run:
        return f"scan(tool='naabu', target='{target}')"
    if "spider" not in tools_run:
        return f"scan(tool='spider', target='{target}')"
    if "nuclei" not in tools_run:
        return f"scan(tool='nuclei', target='{target}')"
    if pending_count > 0:
        # Concrete next action so a respawned/recovered model doesn't flounder
        # (it kept looking for in_progress work, found none, and idled). Give a
        # specific high-value probe AND the finish-up path — never a vague nudge.
        return (
            f"{pending_count} cells still pending. Do ONE of these now — do NOT idle: "
            f"(A) test a high-value endpoint: {_next_pending_probe(target)}; or "
            "(B) if exploitation is done, FINISH — adjudicate each high/critical finding "
            "(report(action='update_finding', data={id, adjudication:{reproducible, rationale, "
            "artifact_id}})), then session(action='complete')."
        )
    return "session(action='complete', options={\"notes\": \"all testing complete\"})"


def _next_pending_probe(target: str) -> str:
    """One concrete test request for the highest-priority pending cell (best
    effort) — so recovery hands the model an exact next move, not a vague hint."""
    try:
        from core.coverage import get_matrix
        from mcp_server.scan_engine.planner import _concrete_test_command
        cov = get_matrix()
        eps = {e["id"]: e for e in cov.get("endpoints", [])}
        pending = [c for c in cov.get("matrix", []) if c.get("status") == "pending"]
        if not pending:
            return "report(action='coverage', data={type:'list', status:'pending', limit:20})"
        prio = ["sqli", "xss", "ssti", "cmdi", "ssrf", "xxe", "nosqli", "idor"]
        best = next((c for it in prio for c in pending if c.get("injection_type") == it), pending[0])
        ep = eps.get(best.get("endpoint_id"), {})
        cmd = _concrete_test_command(
            best.get("injection_type", ""), target, ep.get("path", "/"),
            ep.get("method", "GET"), best.get("param", "_endpoint"), best.get("param_type", "query"),
        )
        return f"{cmd} (cell {best.get('id')})"
    except Exception:
        return "report(action='coverage', data={type:'list', status:'pending', limit:20})"


def _do_artifact(opts):
    """Retrieve raw tool output stored by the scan engine."""
    from mcp_server.scan_engine.artifacts import retrieve_artifact
    artifact_id = opts.get("id", "")
    if not artifact_id:
        return "Error: 'id' option is required"
    mode = opts.get("mode", "summary")
    max_chars = opts.get("max_chars", 4000)
    pattern = opts.get("pattern", "")
    return retrieve_artifact(artifact_id, mode=mode, max_chars=max_chars, pattern=pattern)


def _build_action_list(
    integrity_warnings: list[str],
    in_progress_cells: list[dict],
    pending_escalations: list[dict],
    resume_step: str,
    unsatisfied_gates: list[dict] | None = None,
) -> list[str]:
    """Build prioritized action list for recovery."""
    actions: list[str] = []

    # Gates are highest priority — they block completion
    for gate in (unsatisfied_gates or []):
        actions.append(
            f"GATE BLOCKED [{gate['gate_id']}]: chain into {', '.join(gate['missing_skills'])} "
            f"— {gate['trigger']}"
        )

    if integrity_warnings:
        actions.append(
            f"FIX {len(integrity_warnings)} INTEGRITY WARNING(S): cells marked tested/clean "
            f"without tool evidence. Re-test these cells with actual tools before proceeding."
        )
    if in_progress_cells:
        actions.append(
            f"Resume {len(in_progress_cells)} in-progress test cell(s) — read their notes for technique state"
        )
    if pending_escalations:
        actions.append(
            f"Follow up on {len(pending_escalations)} finding(s) with pending escalation leads"
        )
    if resume_step.startswith("6a"):
        actions.append(
            "Chain /web-exploit — endpoint inventory exists but systematic testing not started"
        )
    if not actions:
        actions.append(f"Resume from step {resume_step}")
    return actions


def _do_pre_chain(opts):
    """Checkpoint state before chaining to a new skill.

    Persists all state to disk so it survives compaction, then returns
    a summary of what the next skill needs to know.
    """
    next_skill = opts.get("next_skill", "")
    if not next_skill:
        return "Error: 'next_skill' option is required"

    current = scan_session.get() or {}
    prev_skill = current.get("skill", "unknown")

    # Persist cost state
    cost_tracker.flush()

    # Calculate context savings estimate
    from core.coverage import get_matrix
    cov = get_matrix()
    meta = cov.get("meta", {})
    data = findings_store._load()

    # Set the new skill and log the chain decision
    chain_reason = f"chained from /{prev_skill}"
    scan_session.set_skill(next_skill, reason=chain_reason, chained_from=prev_skill)
    log.skill_start(next_skill, reason=chain_reason, chained_from=prev_skill)

    result = {
        "action": "pre_chain",
        "previous_skill": prev_skill,
        "next_skill": next_skill,
        "state_persisted": {
            "findings": len(data.get("findings", [])),
            "diagrams": len(data.get("diagrams", [])),
            "coverage_cells": meta.get("total_cells", 0),
            "coverage_tested": meta.get("tested", 0),
            "coverage_pending": sum(1 for c in cov.get("matrix", []) if c["status"] == "pending"),
        },
        "context_recommendation": (
            f"RECOMMEND COMPACTION: The /{prev_skill} skill and its tool results are "
            f"no longer needed in context. All state is persisted to disk "
            f"(session.json, findings.json, coverage_matrix.json). "
            f"Compacting before loading /{next_skill} would free ~50-80k tokens "
            f"(~40% of context window). The /{next_skill} skill can recover "
            f"full state via session(action='recovery')."
        ),
    }

    return json.dumps(result, indent=2)


def _manage_skill_gates(skill_name: str, result: dict) -> list[str]:
    """Satisfy gates requiring skill_name, defer others. Returns list of satisfied gate IDs."""
    satisfied_gates: list[str] = []
    for gate in result.get("gates", []):
        if gate["status"] == "pending" and skill_name in gate["required_skills"]:
            scan_session.satisfy_gate(gate["id"], skill_name)
            satisfied_gates.append(gate["id"])

    # Restore all previously deferred gates, then defer any that don't require THIS skill.
    # This ensures only the one gate relevant to the active skill fires per response.
    scan_session.restore_gates()
    remaining_pending = scan_session.pending_gates()
    gates_to_defer = [
        g["id"] for g in remaining_pending
        if skill_name not in g.get("required_skills", [])
    ]
    if gates_to_defer:
        scan_session.defer_gates(gates_to_defer)
    return satisfied_gates


def _do_set_skill(opts):
    skill_name = opts.get("skill", "")
    reason = opts.get("reason", "")
    chained_from = opts.get("chained_from", "")
    if not skill_name:
        return "Error: 'skill' option is required"

    # Check for resume BEFORE set_skill appends (set_skill deduplicates silently)
    prior = scan_session.get() or {}
    is_resume = skill_name in [
        (e["skill"] if isinstance(e, dict) else e)
        for e in prior.get("skill_history", [])
    ]

    result = scan_session.set_skill(skill_name, reason=reason, chained_from=chained_from)
    if result is None:
        return "No active running session — cannot set skill."

    satisfied_gates = _manage_skill_gates(skill_name, result)

    log.skill_start(skill_name, reason=reason, chained_from=chained_from)

    # Append SKILL entry to quick_log (fire-and-forget via asyncio)
    try:
        from core.quick_log import quick_log as _qlog
        _t = asyncio.create_task(_qlog.append({
            "type":         "SKILL",
            "name":         skill_name,
            "reason":       reason,
            "chained_from": chained_from or None,
        }))
        _background_tasks.add(_t)
        _t.add_done_callback(_background_tasks.discard)
    except Exception:
        pass

    # Auto-satisfy any CHAIN_REQUIRED steering directives for this skill
    try:
        from core.steering import steering_queue
        steering_queue.auto_satisfy(skill_name)
    except Exception:
        pass

    # Detect post-compaction resume: skill was already in history before this call
    if is_resume:
        recovery_brief = _do_recovery()
        msg = (
            f"RESUME DETECTED: '{skill_name}' was already in skill history — "
            f"post-compaction context likely. Full recovery state follows:\n\n{recovery_brief}"
        )
        if satisfied_gates:
            msg += f"\n\n(satisfied gate(s): {', '.join(satisfied_gates)})"
        return msg

    msg = f"Skill '{skill_name}' logged"
    if satisfied_gates:
        msg += f" (satisfied gate(s): {', '.join(satisfied_gates)})"
    return msg


def _do_set_step(opts):
    step = opts.get("step", "")
    if not step:
        return "Error: 'step' option is required"
    result = scan_session.set_step(step)
    if result is None:
        return "No active running session — cannot set step."
    log.note(f"Step checkpoint: {step}")
    return f"Step checkpoint: {step}"


async def _do_start_kali():
    from tools import kali_runner
    log.tool_call("start_kali", {})
    ok, msg = await kali_runner.ensure_running()
    result = (
        f"Kali container ready at {kali_runner.KALI_API} ({msg})"
        if ok else f"Failed to start Kali container: {msg}"
    )
    log.tool_result("start_kali", result)
    return result


async def _do_stop_kali():
    from tools import kali_runner
    log.tool_call("stop_kali", {})
    result = await kali_runner.stop()
    log.tool_result("stop_kali", result)
    return result


async def _do_start_metasploit():
    from tools import metasploit_runner
    log.tool_call("start_metasploit", {})
    ok, msg = await metasploit_runner.ensure_running()
    result = (
        f"Metasploit container ready at {metasploit_runner.MSF_API} ({msg})"
        if ok else f"Failed to start Metasploit container: {msg}"
    )
    log.tool_result("start_metasploit", result)
    return result


async def _do_stop_metasploit():
    from tools import metasploit_runner
    log.tool_call("stop_metasploit", {})
    result = await metasploit_runner.stop()
    log.tool_result("stop_metasploit", result)
    return result


async def _do_pull_images():
    from tools import REGISTRY
    from tools.docker_cli import docker_executable
    log.tool_call("pull_images", {})
    images = [tool.image for tool in REGISTRY.values() if not tool.needs_mount]
    seen: set[str] = set()
    unique = [img for img in images if not (img in seen or seen.add(img))]  # type: ignore[func-returns-value]
    lines: list[str] = []
    for image in unique:
        proc = await asyncio.create_subprocess_exec(
            docker_executable(), "pull", image,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        _, _ = await proc.communicate()
        status = "ok" if proc.returncode == 0 else "FAILED"
        lines.append(f"[{status}] {image}")
    result = "\n".join(lines)
    log.tool_result("pull_images", result)
    return result


def _do_set_codebase(opts):
    path = opts.get("path", "")
    abs_path = os.path.abspath(path)
    if not os.path.isdir(abs_path):
        return f"Error: '{abs_path}' is not a directory"
    os.environ["PENTEST_TARGET_PATH"] = abs_path
    log.note(f"codebase target set to {abs_path}")
    return f"Codebase target set to: {abs_path}"


# ── Wishlist: non-blocking agent→operator backlog ──────────────────────────────
# Terms that mean "I want auth Smith may already hold". A wishlist for these is
# rejected when known_assets already has usable auth — so Smith can't quietly
# route around the 401/403 re-test gate by asking the operator for creds.
_AUTH_NEED_TERMS = (
    "credential", "password", "login as", "auth token", "jwt", "bearer token",
    "api key", "apikey", "session token", "valid account", "sign in", "sign-in", "log in",
)


def _wishlist_already_satisfiable(need: str) -> str | None:
    """If the need is for auth Smith already holds, point at known_assets instead.

    Closes the moral-hazard hole: without this, Smith could wishlist 'admin creds'
    to sidestep the auth re-test gate rather than using auth already captured.
    """
    n = need.lower()
    if not any(t in n for t in _AUTH_NEED_TERMS):
        return None
    ka = (scan_session.get() or {}).get("known_assets", {})
    have: list[str] = []
    if ka.get("credentials"):
        have.append(f"{len(ka['credentials'])} credential pair(s)")
    if ka.get("auth_tokens"):
        have.append(f"{len(ka['auth_tokens'])} JWT/token(s)")
    if ka.get("auth_endpoints"):
        have.append(f"{len(ka['auth_endpoints'])} login endpoint(s)")
    if not have:
        return None
    return (
        "NOT QUEUED — you already hold auth context for this target: " + ", ".join(have) + ". "
        "Use it instead of asking the operator: attach the JWT as 'Authorization: Bearer <value>' "
        "(see session(action='recovery') → auth_context), or POST known credentials to a login "
        "endpoint to mint a fresh token. Only wishlist auth if those are exhausted/expired — and "
        "say so in the rationale."
    )


def _do_wishlist_add(opts):
    from core.wishlist import wishlist_queue
    need = str(opts.get("need", "")).strip()
    if not need:
        return (
            "wishlist_add requires need= — what you need to go deeper "
            "(e.g. 'valid analyst-role creds to reach /admin', 'scope expanded to the staging API', "
            "'rate-limit relief on the login endpoint'). Optional: category= "
            "(credentials|scope|rate_limit|tooling|access|environment|other), rationale=, "
            "blocking_cell_ids=[...]."
        )
    guard = _wishlist_already_satisfiable(need)
    if guard:
        return guard
    blocking = opts.get("blocking_cell_ids") or []
    item_id = wishlist_queue.add(
        need=need,
        category=str(opts.get("category", "other")),
        rationale=str(opts.get("rationale", "")),
        blocking_cell_ids=blocking if isinstance(blocking, list) else [],
    )
    if item_id is None:
        return "Already on the wishlist (an open item with this need exists) — not duplicated."
    log.note(f"wishlist add: {need}")
    link = f" Linked to {len(blocking)} blocked cell(s)." if blocking else ""
    return (
        f"Wishlist item {item_id} recorded (NON-BLOCKING) — the operator sees it on the dashboard "
        f"and can fulfill it without pausing the scan.{link} Keep testing other coverage; do NOT "
        "mark the blocked cells not_applicable just because the resource is missing — they stay "
        "pending until the need is fulfilled."
    )


def _do_wishlist_list():
    from core.wishlist import wishlist_queue
    open_items = wishlist_queue.list_open()
    return json.dumps({
        "open": len(open_items),
        "items": [
            {
                "id": i.id, "need": i.need, "category": i.category,
                "rationale": i.rationale, "blocking_cell_ids": i.blocking_cell_ids,
            }
            for i in open_items
        ],
    }, indent=2)
