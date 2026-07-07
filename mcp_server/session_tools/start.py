"""session(action='start') — scan bootstrap + human-facing start message."""
from core import logger as log
from core import session as scan_session
from mcp_server._app import _session_tools_called

import mcp_server.session_tools as _st
from .start_helpers import (
    _reset_coverage_matrix,
    _prior_findings_brief,
    _start_first_move,
)


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
    # Freshly minted in _do_start(); the token rides the URL *fragment* so it
    # never hits an HTTP access log. Surface the whole link here so the operator
    # can open the dashboard even if the agent runs report(action='dashboard')
    # silently (the failure the operator hit: dashboard started, token never shown).
    try:
        from core import dashboard_auth
        _tok = dashboard_auth.read_token()
    except Exception:
        _tok = None
    dash_url = f"http://localhost:7777/#k={_tok}" if _tok else "http://localhost:7777/"
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
        "  ┌─ DASHBOARD ─────────────────────────────────────────────────────────",
        f"  │  {dash_url}",
        "  │  Open in a browser to watch this scan live. The #k=… token is the",
        "  │  dashboard key — it is REQUIRED to load data, and a new scan mints a",
        "  │  new one. Show this link to the operator before you go silent.",
        "  └─────────────────────────────────────────────────────────────────────",
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
            _st._do_recovery(),
            "",
        ]
    try:
        from core.adjunction import anti_fp_digest
        lines += [anti_fp_digest(), ""]
    except Exception:
        pass
    lines += [
        "EXECUTE NOW (do not ask questions): first give the operator the DASHBOARD",
        "link shown above, then continue silently from here.",
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


# Reason string recorded on every steering directive cancelled at scan start.
_CLEARED_ON_START = "cleared on new scan start"


def _purge_stale_steering() -> None:
    """Purge stale adjudication/triage/skill-chain steering directives on scan start.

    These ride get_active() into the spawn prompt (core/api_server/smith.py) and
    the session status/recovery responses, so an un-acknowledged directive left
    over from a prior run (operator triage that never finished, a legacy
    FORCE_COMPLETE_ADJUDICATION, or a MISSING_WEB_EXPLOIT mandate) would otherwise
    replay into — and hijack — this fresh run. Starting a scan is a deliberate
    reset; the operator re-triggers triage via the dashboard button if they want it.
    """
    try:
        from core.steering import steering_queue
        steering_queue.cancel_by_trigger("TRIAGE_ADJUDICATION", _CLEARED_ON_START)
        steering_queue.cancel_by_trigger("FORCE_COMPLETE_ADJUDICATION", _CLEARED_ON_START)
        for _trig in ("MISSING_WEB_EXPLOIT", "MISSING_PARAM_FUZZ", "MISSING_BUSINESS_LOGIC"):
            steering_queue.cancel_by_trigger(_trig, _CLEARED_ON_START)
    except Exception:
        pass


def _archive_qa_state() -> None:
    """Archive + clear the QA daemon's input log and alert state so a prior scan's
    entries don't re-derive stale skill-chain alerts against this run. Archive
    rather than delete."""
    try:
        import shutil
        from datetime import datetime as _dt, timezone as _tz
        from core.coverage import COVERAGE_FILE
        base = COVERAGE_FILE.parent
        arch = base / "logs"; arch.mkdir(exist_ok=True)
        _ts = _dt.now(_tz.utc).strftime("%Y%m%d_%H%M%S")
        for stale in ("quick_log.json", _st._QA_STATE_FILENAME):
            p = base / stale
            if p.exists():
                shutil.copy2(p, arch / f"{p.stem}_{_ts}.json")
                p.unlink()
    except Exception:
        pass


def _do_start(opts):
    existing = scan_session.get() or {}
    if existing.get("status") == "intervention_required":
        return (
            "SCAN PAUSED — awaiting human intervention. "
            "Respond via session(action='resume', options={choice: '...', message: '...'}) "
            "before starting a new scan."
        )
    # Capture persisted completion progress BEFORE the reset so a same-target RESUME
    # (e.g. after an MCP daemon restart zeroed these process-global counters) keeps its
    # attempt/pass progress instead of silently starting the thorough passes over.
    _prev_complete_attempts = existing.get("complete_attempts", 0) or 0
    _prev_analysis_passes = existing.get("analysis_passes", 0) or 0
    _st._complete_attempts = 0
    _st._analysis_passes = 0
    _st._last_blocker_count = None
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
    # Mint a fresh per-session dashboard token (new session == new dashboard key).
    # The dashboard URL is later surfaced with it in the URL fragment; the
    # FastAPI middleware requires it as a bearer token on every /api/* call.
    try:
        from core import dashboard_auth
        _tok = dashboard_auth.mint_token()
        # Print the dashboard link (token in the URL *fragment*) to the MCP
        # server's stderr — the operator's own console / `docker logs`. This is
        # the one channel that does NOT depend on the agent choosing to relay the
        # report(action='dashboard') result, which the EXECUTE-NOW block otherwise
        # tells it to run silently. A fragment never reaches an HTTP access log
        # (see dashboard_auth docstring); stderr is operator-facing by design.
        import sys as _sys
        print(
            f"\n[agent-smith] Dashboard → http://localhost:7777/#k={_tok}\n"
            "[agent-smith]   open in a browser; the #k=… token is required to load "
            "scan data (a new scan mints a new token).\n",
            file=_sys.stderr, flush=True,
        )
    except Exception:
        pass
    # Deterministic target classification — an advisory PRIOR, never a gate. It
    # never overrides the LLM's own skill routing; it just makes the recommended
    # first move fit the target kind so AUTONOMOUS/CI runs don't greet a codebase
    # path or an IP range with a web scan. Stored for the dashboard too.
    from core.target_class import classify_target
    classification = classify_target(target)
    _cur = scan_session.get()
    if _cur is not None:
        _cur["classifier"] = classification
        # Same-target resume: restore the completion counters scan_session.start()
        # just zeroed, so an MCP restart mid-thorough-scan doesn't lose pass progress.
        if is_resume and (_prev_complete_attempts or _prev_analysis_passes):
            _st._complete_attempts = _prev_complete_attempts
            _st._analysis_passes = _prev_analysis_passes
            _cur["complete_attempts"] = _prev_complete_attempts
            _cur["analysis_passes"] = _prev_analysis_passes
        scan_session._flush()
    try:
        from core.adjunction.log import clear as _adj_log_clear
        _adj_log_clear()
    except Exception:
        pass
    _purge_stale_steering()
    # On a NON-resume start, reset the QA daemon's input log + alert state so a
    # prior scan's SPIDER/SKILL/TOOL entries don't re-derive stale skill-chain
    # alerts against this run (the cross-session bleed that hijacked a fresh
    # ai-redteam scan into /web-exploit). Archive rather than delete.
    if not is_resume:
        _archive_qa_state()
    return _start_response(cfg, classification, target, scan_mode, depth, is_resume)
