"""
Dashboard HTTP routes.

All endpoints are registered on a single APIRouter that ``core.api_server``
includes onto the FastAPI ``app`` at import time. Handlers reach shared
state, helpers, and the Smith-supervision functions through the package
(the ``_api`` alias) so the dashboard's tests can patch any of them.
"""
from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, JSONResponse

import core.api_server as _api

_log = logging.getLogger(__name__)

router = APIRouter()


# ── Dashboard UI + static assets ────────────────────────────────────────────

@router.get("/")
async def dashboard_ui(request: Request):
    """Render the dashboard shell — index.html {% include %}s the per-tab
    partials; CSS/JS load from the /static mount."""
    return _api.templates.TemplateResponse(request, "index.html")


@router.get("/healthz")
async def healthz() -> JSONResponse:
    """Unauthenticated liveness probe used by serve() to detect a healthy
    dashboard. Returns no scan data, so it stays reachable when the /api/*
    control plane requires the per-session bearer token."""
    return JSONResponse({"ok": True})


@router.get("/logo.png")
async def logo() -> FileResponse:
    return FileResponse(_api._TEMPLATES_DIR / "FullLogo_Transparent.png", media_type="image/png")


@router.get("/favicon.ico")
async def favicon() -> FileResponse:
    """Real .ico file served with the correct media type. Browsers that
    auto-probe /favicon.ico (Safari, every IE-lineage thing) want this
    exact path and content-type to avoid logging a 404 on every page load."""
    return FileResponse(
        _api._TEMPLATES_DIR / "favicon.ico",
        media_type="image/vnd.microsoft.icon",
    )


@router.get("/favicon-32x32.png")
async def favicon_png() -> FileResponse:
    """Sized PNG favicon for modern browsers — referenced explicitly from
    the <link rel="icon" sizes="32x32"> tag in index.html. Modern
    rendering pipelines prefer this over the .ico when both are available."""
    return FileResponse(
        _api._TEMPLATES_DIR / "favicon-32x32.png",
        media_type="image/png",
    )


# ── Read APIs ───────────────────────────────────────────────────────────────

@router.get("/api/findings")
async def api_findings() -> JSONResponse:
    data = _api._read_json(_api._FINDINGS_FILE)
    # Render diagram + exploit-chain SVGs server-side so the topology tab matches
    # the threat-model theme.
    for d in [*data.get("diagrams", []), *data.get("chains", [])]:
        if d.get("mermaid") and "svg" not in d:
            wrapped = f"```mermaid\n{d['mermaid']}\n```"
            svgs = _api._render_mermaid_svgs(wrapped)
            d["svg"] = svgs.get("0", "")
    return JSONResponse(data)


@router.get("/api/session")
async def api_session() -> JSONResponse:
    data = _api._read_json(_api._SESSION_FILE)
    # Self-heal the triage banner + expose the live pending count so the dashboard
    # can show progress (and a "stalled" warning if Smith goes idle mid-pass).
    if isinstance(data, dict) and data.get("triage_requested"):
        try:
            import time
            from core.findings import _load as _load_findings
            from core.adjunction import pending_findings
            from core import session as scan_session
            pending = pending_findings(_load_findings())
            data["pending_adjudication"] = len(pending)
            if not pending:
                # Every in-scope finding has a verdict — clear the flag so the
                # banner doesn't linger after Smith finishes the pass.
                scan_session.load_from_disk(force=True)
                scan_session.set_triage_requested(False)
                # Also acknowledge the steering directive itself. Clearing only
                # the session flag (above) hid the banner but left the directive
                # live in get_active(), so it kept replaying into Smith's spawn
                # prompt / status / recovery responses — driving an unwanted
                # adjudication pass on the next run. Ack it here, on completion,
                # so a finished triage leaves nothing behind.
                try:
                    from core.steering import steering_queue
                    steering_queue.cancel_by_trigger(
                        "TRIAGE_ADJUDICATION", "all findings adjudicated"
                    )
                except Exception:
                    pass
                data = _api._read_json(_api._SESSION_FILE)
            else:
                # Advance the stall clock on real progress, then expose how long
                # the pass has gone without recording a verdict. The dashboard
                # uses this (not just the MCP heartbeat) to flip the banner to a
                # "stalled" warning when Smith abandons the pass with findings
                # still awaiting a verdict — even if it stays busy elsewhere.
                scan_session.load_from_disk(force=True)
                scan_session.note_triage_progress(len(pending))
                data = _api._read_json(_api._SESSION_FILE)
                data["pending_adjudication"] = len(pending)
                progressed_at = (
                    data.get("triage_progress_at")
                    or data.get("triage_requested_at")
                )
                if progressed_at:
                    data["triage_idle_s"] = int(time.time() - progressed_at)
        except Exception:
            pass
    return JSONResponse(data)


@router.get("/api/cost")
async def api_cost() -> JSONResponse:
    return JSONResponse(_api._read_json(_api._COST_FILE))


@router.get("/api/coverage")
async def api_coverage() -> JSONResponse:
    return JSONResponse(_api._read_json(_api._COVERAGE_FILE))


@router.get("/api/threat-model")
async def api_get_threat_model(file: str = "") -> JSONResponse:
    md_paths: list = []
    if _api._THREAT_MODEL_DIR.exists():
        # Sort by modification time (most recent first) so the active scan's
        # threat model appears as the default selection.
        md_paths = list(_api._THREAT_MODEL_DIR.glob("*.md"))
        md_paths.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    files = [p.name for p in md_paths]

    if not file and files:
        file = files[0]

    content = ""
    if file:
        if "/" in file or "\\" in file or ".." in file:
            return JSONResponse({"error": "invalid file"}, status_code=400)
        # Look up the Path from the trusted glob results — user-controlled `file`
        # is used only as a filter key, never directly in a path expression.
        safe_path = next((p for p in md_paths if p.name == file), None)
        if safe_path is not None:
            content = safe_path.read_text(encoding="utf-8")

    svgs = {}
    if content:
        svgs = _api._render_mermaid_svgs(content)

    return JSONResponse({"files": files, "file": file, "content": content, "svgs": svgs})


@router.patch("/api/findings/{finding_id}")
async def api_patch_finding(finding_id: str, request: Request) -> JSONResponse:
    from core.findings import update_finding
    try:
        body = await request.json()
        updated = await update_finding(
            finding_id,
            severity=body.get("severity"),
            title=body.get("title"),
            description=body.get("description"),
            evidence=body.get("evidence"),
            status=body.get("status"),
            gh_issue=body.get("gh_issue"),
            remediation=body.get("remediation"),
            reproduction=body.get("reproduction"),
            escalation_leads=body.get("escalation_leads"),
        )
        return JSONResponse({"ok": updated})
    except Exception:
        _log.exception("api_update_finding failed")
        return JSONResponse({"ok": False, "error": _api._ERR_REQUEST_FAILED}, status_code=400)


@router.delete("/api/findings/{finding_id}")
async def api_delete_finding(finding_id: str) -> JSONResponse:
    from core.findings import delete_finding
    try:
        archived = await delete_finding(finding_id)
        return JSONResponse({"ok": archived})
    except Exception:
        _log.exception("api_delete_finding failed")
        return JSONResponse({"ok": False, "error": _api._ERR_REQUEST_FAILED}, status_code=400)


# ── Scan-state mutation ─────────────────────────────────────────────────────

@router.delete("/api/clear")
async def api_clear() -> JSONResponse:
    """Wipe all scan state — findings, session, coverage, logs, quick_log, qa_state."""
    from core.findings import _save

    # findings.json
    _save({"meta": {"created": "", "target": ""}, "findings": [], "diagrams": []})

    # coverage_matrix.json — reset to empty (keep the file so /api/coverage returns valid JSON)
    try:
        from core.coverage import reset as _reset_coverage
        await _reset_coverage()
    except Exception:
        pass

    _RECOVERY_SNAP = _api._REPO_ROOT / "recovery_latest.json"
    _METRICS_FILE  = _api._REPO_ROOT / "pentest_metrics.jsonl"
    # _COVERAGE_FILE is intentionally omitted — reset() above already wrote the empty state.
    # Deleting it would cause /api/coverage to return {} instead of an empty-but-valid matrix.
    # _SMITH_PID_FILE + _SMITH_CLIENT_FILE are scan-tied pointers — a stale
    # PID from the previous scan biases _detect_active_client() toward the old
    # client and clutters smith-status diagnostics for the next scan.
    for path in (_api._SESSION_FILE, _api._QUICK_LOG_FILE, _api._QA_STATE_FILE,
                 _api._COST_FILE, _api._STEERING_FILE, _RECOVERY_SNAP, _METRICS_FILE,
                 _api._SMITH_PID_FILE, _api._SMITH_CLIENT_FILE):
        _api._safe_unlink(path)

    # log files in logs/
    try:
        from core.logger import _LOG_DIR
        _api._clear_log_files(_LOG_DIR)
    except Exception:
        pass

    # pocs/ — clear .http files so PoC count doesn't bleed between sessions
    try:
        pocs_dir = _api._REPO_ROOT / "pocs"
        if pocs_dir.exists():
            for poc_file in pocs_dir.glob("*.http"):
                _api._safe_unlink(poc_file)
    except Exception:
        pass

    # artifacts/ — raw scanner output files
    _api._clear_dir_files(_api._REPO_ROOT / "artifacts")

    # threat-model/ — generated HTML/MD reports
    _api._clear_dir_files(_api._REPO_ROOT / "threat-model")

    # gh-issues.md — exported GitHub issue blocks
    _api._safe_unlink(_api._REPO_ROOT / "gh-issues.md")

    await _api._cleanup_tunnels()
    return JSONResponse({"ok": True})


@router.delete("/api/tunnels")
async def api_cleanup_tunnels() -> JSONResponse:
    """Kill chisel tunnels in Kali. Remote clients disconnect automatically."""
    result = await _api._cleanup_tunnels()
    return JSONResponse({"ok": True, "message": result})


@router.get("/api/intervention")
async def api_intervention() -> JSONResponse:
    """Return current HIR state if the scan is paused, else {active: false}.

    Force-reloads from disk: the MCP process (separate from this dashboard
    uvicorn process) writes session.json on every tool call, so our cached
    _current would otherwise stay stuck on the snapshot taken at startup.
    """
    try:
        from core import session as scan_session
        scan_session.load_from_disk(force=True)
        iv = scan_session.get_intervention()
        if iv:
            return JSONResponse({"active": True, **iv})
    except Exception:
        pass
    return JSONResponse({"active": False})


@router.post("/api/intervention/respond")
async def api_intervention_respond(request: Request) -> JSONResponse:
    """Human responds to an HIR event from the dashboard.

    Body: {"choice": "ACCEPT_PARTIAL", "message": "optional free text"}
    Transitions scan back to running and injects a steering directive for Smith.
    """
    try:
        body   = await request.json()
        choice  = str(body.get("choice", "")).strip()
        message = str(body.get("message", "")).strip()
        if not choice and not message:
            return JSONResponse({"ok": False, "error": "choice or message required"}, status_code=400)
        from core import session as scan_session
        from core.steering import steering_queue, RESUME_REQUIRED
        # Force-reload before mutating — see api_intervention docstring for why.
        scan_session.load_from_disk(force=True)
        scan_session.resolve_intervention(choice, message)
        human_instruction = f"Human resolved HIR — choice='{choice}'" + (f": {message}" if message else "")
        steering_queue.add_directive(
            code=RESUME_REQUIRED,
            message=(
                f"HUMAN RESPONSE: {human_instruction}. "
                "Act on this instruction now, then continue the scan."
            ),
            priority="high",
            skill=None,
            trigger="HIR_RESOLVED",
        )
        return JSONResponse({"ok": True, "resumed": True, "instruction": human_instruction})
    except Exception:
        _log.exception("api_intervention_respond failed")
        return JSONResponse({"ok": False, "error": _api._ERR_REQUEST_FAILED}, status_code=500)


@router.post("/api/steer")
async def api_steer(request: Request) -> JSONResponse:
    """Human sends a free-form steering instruction outside of an HIR event.

    Creates a high-priority steering directive so Smith sees it on the next tool call.
    Body: {"message": "..."}
    """
    try:
        body    = await request.json()
        message = str(body.get("message", "")).strip()
        if not message:
            return JSONResponse({"ok": False, "error": "message required"}, status_code=400)
        from core.steering import steering_queue, RESUME_REQUIRED
        steering_queue.add_directive(
            code=RESUME_REQUIRED,
            message=f"HUMAN INSTRUCTION: {message}",
            priority="high",
            skill=None,
            trigger="HUMAN_STEER",
            force=True,  # human instructions always go through — never deduped
        )
        return JSONResponse({"ok": True})
    except Exception:
        _log.exception("api_steer failed")
        return JSONResponse({"ok": False, "error": _api._ERR_REQUEST_FAILED}, status_code=500)


@router.get("/api/wishlist")
async def api_wishlist() -> JSONResponse:
    """The agent→operator resource backlog (open + resolved), newest first."""
    try:
        from core.wishlist import wishlist_queue
        return JSONResponse({"items": wishlist_queue.get_all()})
    except Exception:
        _log.exception("api_wishlist failed")
        return JSONResponse({"items": []})


@router.post("/api/wishlist/{item_id}/fulfill")
async def api_wishlist_fulfill(item_id: str, request: Request) -> JSONResponse:
    """Operator supplied a wished-for resource.

    Marks the item fulfilled and injects a steering directive so Smith reopens
    the blocked cells and uses the new resource — closing the loop without an HIR.
    Body: {"note": "the credential / scope / detail Smith should use"}
    """
    try:
        body = await request.json()
        note = str(body.get("note", "")).strip()
        from core.wishlist import wishlist_queue
        from core.steering import steering_queue, RESUME_REQUIRED
        item = wishlist_queue.fulfill(item_id, note=note)
        if not item:
            return JSONResponse({"ok": False, "error": "not found or already resolved"}, status_code=404)
        cells = item.get("blocking_cell_ids") or []
        cell_hint = f" Reopen and re-test these blocked cell(s) now: {', '.join(cells)}." if cells else ""
        steering_queue.add_directive(
            code=RESUME_REQUIRED,
            message=(
                f"WISHLIST FULFILLED — the operator supplied what you asked for: {item.get('need', '')}."
                + (f" Details: {note}." if note else "")
                + cell_hint
                + " Use it to go deeper; do NOT mark those cells not_applicable."
            ),
            priority="high",
            skill=None,
            trigger="WISHLIST_FULFILLED",
            force=True,
        )
        return JSONResponse({"ok": True, "item": item})
    except Exception:
        _log.exception("api_wishlist_fulfill failed")
        return JSONResponse({"ok": False, "error": _api._ERR_REQUEST_FAILED}, status_code=500)


@router.post("/api/wishlist/{item_id}/dismiss")
async def api_wishlist_dismiss(item_id: str, request: Request) -> JSONResponse:
    """Operator declined a wishlist item (won't/can't supply it)."""
    try:
        body = await request.json()
        note = str(body.get("note", "")).strip()
        from core.wishlist import wishlist_queue
        item = wishlist_queue.dismiss(item_id, note=note)
        if not item:
            return JSONResponse({"ok": False, "error": "not found or already resolved"}, status_code=404)
        return JSONResponse({"ok": True, "item": item})
    except Exception:
        _log.exception("api_wishlist_dismiss failed")
        return JSONResponse({"ok": False, "error": _api._ERR_REQUEST_FAILED}, status_code=500)


@router.post("/api/setup-gates/{gate_id}/elect")
async def api_setup_gate_elect(gate_id: str, request: Request) -> JSONResponse:
    """Operator elects a manual-setup gate: now | defer | skip.

    Body: {"choice": "now|defer|skip"}. Non-blocking — election just records the
    operator's decision; it never completes or blocks the scan.
    """
    try:
        body = await request.json()
        choice = str(body.get("choice", "")).strip()
        if choice not in ("now", "defer", "skip"):
            return JSONResponse({"ok": False, "error": "choice must be now|defer|skip"}, status_code=400)
        from core import session as scan_session
        scan_session.load_from_disk(force=True)
        gate = scan_session.record_election(gate_id, choice)
        if not gate:
            return JSONResponse({"ok": False, "error": "gate not found"}, status_code=404)
        return JSONResponse({"ok": True, "gate": gate})
    except Exception:
        _log.exception("api_setup_gate_elect failed")
        return JSONResponse({"ok": False, "error": _api._ERR_REQUEST_FAILED}, status_code=500)


@router.post("/api/setup-gates/{gate_id}/recheck")
async def api_setup_gate_recheck(gate_id: str) -> JSONResponse:
    """Operator re-runs a gate's readiness probe (the "I've set it up — verify" button).

    On a pass that clears a DEFERRED gate, wake Smith so it resumes the gated
    work — this is the headless re-check actuator (closes PLAN_REVIEW_GAPS G08).
    Smith's own subsequent MCP `check` produces the audit artifact; this operator
    path just flips state and nudges.
    """
    try:
        from core import session as scan_session, probe_runner
        scan_session.load_from_disk(force=True)
        gate = scan_session.setup_gate_by_id(gate_id)
        if not gate:
            return JSONResponse({"ok": False, "error": "gate not found"}, status_code=404)
        was_deferred = gate.get("election") == "defer"
        out = await probe_runner.check_gate(gate_id)  # artifact_store=None in the dashboard process
        woke = False
        if out["status"] == "ok" and was_deferred:
            woke = await _wake_smith_if_idle()

        # Do not expose raw probe execution output/error details to remote clients.
        probe_result = out.get("result")
        safe_probe = None
        if isinstance(probe_result, dict):
            safe_probe = dict(probe_result)
            safe_probe["stdout"] = ""
            safe_probe["stderr"] = ""
            if safe_probe.get("error"):
                safe_probe["error"] = _api._ERR_REQUEST_FAILED

        return JSONResponse({
            "ok": True, "status": out["status"], "gate": out["gate"],
            "probe": safe_probe, "smith_woken": woke,
        })
    except Exception:
        _log.exception("api_setup_gate_recheck failed")
        return JSONResponse({"ok": False, "error": _api._ERR_REQUEST_FAILED}, status_code=500)


@router.post("/api/complete")
async def api_complete(request: Request) -> JSONResponse:
    """Human-triggered scan completion.

    Only this endpoint (called from the dashboard) can mark a scan complete.
    Smith cannot complete a scan autonomously — session(action='complete') is blocked.
    Body: {"notes": "optional completion notes"}

    Completion is unconditional — it does NOT run the adjudication pass. Triaging
    findings is a separate, operator-chosen step via POST /api/triage (the
    "Triage findings" button). This keeps the two decisions independent: review
    findings when you want, finish the scan when you want.

    Side-effect cleanup mirrors Clear All but narrower: scan-tied operational
    pointers (smith.pid, smith.client, quick_log heartbeat) are wiped so the
    dashboard immediately reflects "smith stopped" instead of waiting 5 min
    for the activity signal to age out. Deliverables (findings.json,
    coverage_matrix.json, session.json, artifacts/, pocs/, pentest.log) are
    intentionally preserved — they're the report you'll export from."""
    try:
        from core import session as scan_session
        # Force-reload so we mutate against the freshest disk state, not a
        # cached _current snapshot.
        scan_session.load_from_disk(force=True)
        body  = await request.json()
        notes = str(body.get("notes", "")).strip()

        cfg    = scan_session.complete(notes)
        status = cfg.get("status", "complete")

        # Clean up operational pointers now that the scan is terminal.
        # The watchdog gates on `session.status == "running"`, so flipping
        # to "complete" first (above) means it won't fire a "smith stopped"
        # alert from these deletions.
        for path in (_api._SMITH_PID_FILE, _api._SMITH_CLIENT_FILE, _api._QUICK_LOG_FILE):
            _api._safe_unlink(path)

        return JSONResponse({"ok": True, "status": status})
    except Exception:
        _log.exception("api_complete failed")
        return JSONResponse({"ok": False, "error": _api._ERR_REQUEST_FAILED}, status_code=500)


async def _wake_smith_if_idle() -> bool:
    """Spawn a fresh Smith run iff no live Smith process exists.

    A queued steering directive is inert: it reaches Smith only by riding the
    envelope on Smith's *next* tool call. When the operator triggers triage,
    Smith has usually gone quiet — its non-interactive `claude -p` /
    `opencode run` turn has exited — so no tool call ever consumes the directive
    and the pass never starts. The watchdog won't help promptly either (it keeps
    Smith "alive" for the full _SMITH_IDLE_SECONDS quick_log grace before
    respawning).

    So if no live Smith *process* exists we spawn one now; its recovery prompt
    appends steering_queue.get_active(), delivering the directive verbatim
    (client-agnostic via _detect_active_client). We gate on process liveness,
    NOT quick_log freshness — a just-exited `-p` turn leaves a <grace quick_log
    yet has no process to consume the directive. When a live process IS present
    we abstain: a looping Smith picks the directive up on its next call, and a
    second `-p` Smith alongside a live one would dual-write state.
    """
    try:
        smith_alive = (
            _api._signal_pid_file_alive()
            or _api._signal_process_scan_finds_client()
        )
        if smith_alive:
            return False
        client = _api._detect_active_client()
        if _api._client_installed(client):
            ok, _result = await _api._spawn_smith(client, source="api")
            return bool(ok)
    except Exception:
        # Never fail the request on a spawn error — the directive is still
        # queued and the watchdog remains a fallback.
        _log.exception("triage wake-spawn failed")
    return False


@router.post("/api/triage")
async def api_triage(request: Request) -> JSONResponse:
    """Operator-triggered adjudication (triage) pass — does NOT complete the scan.

    Injects the senior-review directive for every un-adjudicated in-scope
    finding and wakes Smith if it has gone idle. Smith records a verdict per
    finding, then resumes normal testing — the scan stays open. Completion is a
    separate decision (POST /api/complete).
    """
    try:
        from core import session as scan_session
        scan_session.load_from_disk(force=True)

        try:
            from core.findings import _load as _load_findings
            from core.adjunction import pending_findings
            pending = pending_findings(_load_findings())
        except Exception:
            pending = []

        if not pending:
            return JSONResponse({"ok": True, "status": "nothing_to_triage", "pending_adjudication": 0})
        sess = scan_session.get() or {}
        if not sess.get("target"):
            return JSONResponse({"ok": False, "error": "no scan to triage"}, status_code=409)

        # Triage is now a POST-scan step: it runs against a STOPPED scan and
        # (re)spawns Smith to adjudicate. A running scan is also tolerated (the
        # legacy mid-scan path), but the dashboard only surfaces the button once
        # the scan has stopped. The directive wording branches on that so a
        # terminal-scan triage tells Smith to stop afterwards, not resume.
        terminal = sess.get("status") in (
            "complete", "incomplete_with_unresolved_blockers", "limit_reached",
        )

        scan_session.set_triage_requested(True)

        from core.adjunction.directive import build_adjudication_directive
        from core.steering import steering_queue, RESUME_REQUIRED
        if terminal:
            closing_note = (
                "\n\nNOTE: This is a post-scan TRIAGE pass requested by the human "
                "operator on a STOPPED scan. After you have adjudicated ALL findings "
                "above, STOP — do NOT resume testing and do NOT call "
                "session(action='start'). The scan stays complete."
            )
        else:
            closing_note = (
                "\n\nNOTE: This is a standalone TRIAGE pass requested by the human "
                "operator. After you have adjudicated ALL findings above, DO NOT "
                "complete the scan — resume normal testing where you left off. The "
                "scan stays open."
            )
        directive_body = build_adjudication_directive(pending) + closing_note
        steering_queue.add_directive(
            code=RESUME_REQUIRED,
            message=directive_body,
            priority="high",
            skill=None,
            trigger="TRIAGE_ADJUDICATION",
            force=True,
        )
        try:
            from core.adjunction.log import log_directive
            log_directive(pending)
        except Exception:
            pass

        smith_spawned = await _wake_smith_if_idle()
        return JSONResponse({
            "ok": True,
            "status": "triaging",
            "pending_adjudication": len(pending),
            "smith_spawned": smith_spawned,
        })
    except Exception:
        _log.exception("api_triage failed")
        return JSONResponse({"ok": False, "error": _api._ERR_REQUEST_FAILED}, status_code=500)


# ── Smith lifecycle ─────────────────────────────────────────────────────────

@router.get("/api/smith-status")
async def api_smith_status() -> JSONResponse:
    """Smith liveness + activity heartbeat.

    `running` is true if any Smith process exists (incl. an idle interactive one
    sitting at a prompt). `heartbeat_age_s` is how long since the last MCP
    tool-call (quick_log mtime) — the true *activity* signal — and `idle` flags
    when that exceeds the heartbeat window. A live-but-idle Smith (running=true,
    idle=true) is one that has stopped working and is likely awaiting input.
    """
    import time
    heartbeat_age = None
    try:
        if _api._QUICK_LOG_FILE.exists():
            heartbeat_age = int(time.time() - _api._QUICK_LOG_FILE.stat().st_mtime)
    except OSError:
        pass
    # Soft "stopped working" threshold — deliberately shorter than the watchdog's
    # _SMITH_IDLE_SECONDS respawn grace so the UI can warn before a respawn.
    _HEARTBEAT_IDLE_S = 120
    idle = heartbeat_age is not None and heartbeat_age >= _HEARTBEAT_IDLE_S
    running = _api._smith_running()
    # `adjudicating` lets the UI label a post-complete triage relaunch as
    # "adjudicating" instead of a plain "running" — so a Smith spun back up to
    # re-verify findings isn't mistaken for a hung/stuck scan.
    adjudicating = False
    if running:
        try:
            from core import session as scan_session
            scan_session.load_from_disk(force=True)
            adjudicating = bool((scan_session.get() or {}).get("triage_requested"))
        except Exception:
            pass
    return JSONResponse({
        "running": running,
        "adjudicating": adjudicating,
        "heartbeat_age_s": heartbeat_age,
        "idle": idle,
    })


@router.post("/api/triage-cancel")
async def api_triage_cancel() -> JSONResponse:
    """Clear an in-flight triage pass — operator escape hatch for the banner.

    Drops the triage_requested flag and removes any un-consumed
    TRIAGE_ADJUDICATION steering directives so the banner disappears and Smith
    won't pick up a stale review directive. Does NOT touch findings or verdicts
    already recorded.
    """
    try:
        from core import session as scan_session
        scan_session.load_from_disk(force=True)
        scan_session.set_triage_requested(False)
        removed = 0
        try:
            from core.steering import steering_queue
            removed = steering_queue.cancel_by_trigger(
                "TRIAGE_ADJUDICATION", "triage cancelled by operator"
            )
            # Also clear legacy force-complete directives, which otherwise have
            # no cleanup path at all and would replay into the next run.
            removed += steering_queue.cancel_by_trigger(
                "FORCE_COMPLETE_ADJUDICATION", "triage cancelled by operator"
            )
        except Exception:
            _log.exception("api_triage_cancel: directive cleanup failed")
        return JSONResponse({"ok": True, "removed_directives": removed})
    except Exception:
        _log.exception("api_triage_cancel failed")
        return JSONResponse({"ok": False, "error": _api._ERR_REQUEST_FAILED}, status_code=500)


@router.post("/api/force-stop")
async def api_force_stop() -> JSONResponse:
    """Hard stop — the "just stop it now" control.

    Unlike /api/complete (which finalizes the session but leaves a
    mid-adjudication Smith still running) and /api/triage-cancel (which only
    drops the triage flag), this flips the session terminal, cancels any triage
    pass, AND kills the running Smith process so it can neither keep working nor
    be respawned by the watchdog. Deliverables (findings, coverage, PoCs) are
    preserved — only the live process + operational pointers are torn down."""
    _reason = "force-stopped by operator"
    try:
        from core import session as scan_session
        scan_session.load_from_disk(force=True)
        # Capture a live Smith PID BEFORE the kill + pointer-wipe below.
        pid = _api._live_pid_from_pid_file() or _api._live_pid_from_process_scan()
        # Force-stop is the operator override — it must finalize from ANY non-terminal
        # state. complete() only transitions from 'running', so a scan wedged in
        # intervention_required (an open HIR — exactly when you most need to kill it)
        # couldn't be stopped at all. Clear the HIR first so complete() flips it terminal.
        if (scan_session.get() or {}).get("status") == "intervention_required":
            scan_session.resolve_intervention("FORCE_STOP", _reason)
        # Terminal status first so the watchdog won't respawn after the kill.
        cfg = scan_session.complete(_reason)
        scan_session.set_triage_requested(False)
        removed = 0
        try:
            from core.steering import steering_queue
            removed = steering_queue.cancel_by_trigger("TRIAGE_ADJUDICATION", _reason)
            removed += steering_queue.cancel_by_trigger("FORCE_COMPLETE_ADJUDICATION", _reason)
        except Exception:
            _log.exception("api_force_stop: directive cleanup failed")
        killed = bool(pid) and _api._kill_hung_smith(pid)
        # _kill_hung_smith clears smith.pid/client on success; wipe the rest too.
        for path in (_api._SMITH_PID_FILE, _api._SMITH_CLIENT_FILE, _api._QUICK_LOG_FILE):
            _api._safe_unlink(path)
        return JSONResponse({
            "ok": True,
            "status": cfg.get("status", "complete"),
            "killed": killed,
            "pid": pid,
            "removed_directives": removed,
        })
    except Exception:
        _log.exception("api_force_stop failed")
        return JSONResponse({"ok": False, "error": _api._ERR_REQUEST_FAILED}, status_code=500)


@router.get("/api/smith-clients")
async def api_smith_clients() -> JSONResponse:
    """Return available clients and the auto-detected active one."""
    return JSONResponse({
        "claude":   _api._client_installed("claude"),
        "opencode": _api._client_installed("opencode"),
        "codex":    _api._client_installed("codex"),
        "active":   _api._detect_active_client(),
    })


@router.get("/api/watchdog")
async def api_watchdog_status() -> JSONResponse:
    """Diagnostic: report watchdog state — last restart, count in last hour."""
    import time as _time
    now = _time.time()
    recent = [t for t in _api._watchdog_restart_count_window if now - t < 3600]
    return JSONResponse({
        "enabled": _api._watchdog_task is not None and not (_api._watchdog_task and _api._watchdog_task.done()),
        "last_restart_ago_s": int(now - _api._watchdog_last_restart_ts) if _api._watchdog_last_restart_ts else None,
        "restarts_in_last_hour": len(recent),
        "max_per_hour": _api._WATCHDOG_MAX_PER_HOUR,
        "poll_seconds": _api._WATCHDOG_POLL_SECONDS,
        "min_gap_seconds": _api._WATCHDOG_MIN_GAP_SECONDS,
    })


@router.post("/api/restart-smith")
async def api_restart_smith(request: Request) -> JSONResponse:
    """Spawn a new Smith process (claude or opencode) to continue the active scan.

    Body: {"client": "claude" | "opencode", "force": bool}

    Builds a recovery prompt that includes any pending HUMAN_STEER directives
    so Smith acts on them immediately after recovering its position.
    Blocked when Smith is already running to prevent duplicate sessions.
    """
    try:
        body = await request.json() if request.headers.get("content-length") else {}
    except Exception:
        body = {}
    force = bool(body.get("force", False))
    if not force and _api._smith_running():
        return JSONResponse({"ok": False, "error": "Smith is already running. Pass force=true to override."}, status_code=409)
    client = (body.get("client") or _api._detect_active_client()).lower()
    if client not in _api._KNOWN_CLIENTS:
        return JSONResponse({"ok": False, "error": f"Unknown client: {client}"}, status_code=400)
    if not _api._client_installed(client):
        return JSONResponse(
            {"ok": False, "error": f"{client} is not installed on this host"},
            status_code=400,
        )

    ok, result = await _api._spawn_smith(client, source="api")
    if ok:
        return JSONResponse({"ok": True, "pid": result, "client": client})
    return JSONResponse({"ok": False, "error": str(result)}, status_code=500)


# ── QA / steering / metrics / logs ──────────────────────────────────────────

@router.get("/api/qa")
async def api_qa() -> JSONResponse:
    return JSONResponse(_api._read_json(_api._QA_STATE_FILE))


@router.get("/api/steering")
async def api_steering() -> JSONResponse:
    return JSONResponse(_api._read_json(_api._STEERING_FILE))


@router.get("/api/adjudication-log")
async def api_adjudication_log() -> JSONResponse:
    try:
        from core.adjunction.log import read_all
        return JSONResponse(read_all())
    except Exception:
        return JSONResponse([])


@router.get("/api/metrics")
async def api_metrics() -> JSONResponse:
    import core.metrics as metrics_mod
    return JSONResponse(metrics_mod.load_all())


@router.get("/api/quicklog")
async def api_quicklog() -> JSONResponse:
    if not _api._QUICK_LOG_FILE.exists():
        return JSONResponse([])
    entries: list[dict] = []
    for line in _api._QUICK_LOG_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                entries.append(json.loads(line))
            except Exception:
                pass
    return JSONResponse(entries)


@router.get("/api/logs")
async def api_logs(file: str = "") -> JSONResponse:
    from core.logger import log_path, _LOG_DIR
    try:
        log_paths = sorted(_LOG_DIR.glob("*.log"), key=lambda p: p.name, reverse=True)
        all_files = [p.name for p in log_paths]
        # Resolve target from trusted glob results — never construct a path
        # from the user-supplied `file` string directly.
        if file:
            target = next((p for p in log_paths if p.name == file), None)
            if target is None:
                return JSONResponse({"lines": [], "files": all_files, "error": "invalid path"})
        else:
            target = log_path
        lines = target.read_text(encoding="utf-8").splitlines() if target.exists() else []
        return JSONResponse({"lines": lines, "file": target.name, "files": all_files})
    except Exception:
        _log.exception("api_logs failed")
        return JSONResponse({"lines": [], "files": [], "error": "failed to read log"})
