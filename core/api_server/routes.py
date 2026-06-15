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
    return _api.templates.TemplateResponse("index.html", {"request": request})


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
    # Render diagram SVGs server-side so topology tab matches threat model theme
    for d in data.get("diagrams", []):
        if d.get("mermaid") and "svg" not in d:
            wrapped = f"```mermaid\n{d['mermaid']}\n```"
            svgs = _api._render_mermaid_svgs(wrapped)
            d["svg"] = svgs.get("0", "")
    return JSONResponse(data)


@router.get("/api/session")
async def api_session() -> JSONResponse:
    return JSONResponse(_api._read_json(_api._SESSION_FILE))


@router.get("/api/cost")
async def api_cost() -> JSONResponse:
    return JSONResponse(_api._read_json(_api._COST_FILE))


@router.get("/api/coverage")
async def api_coverage() -> JSONResponse:
    return JSONResponse(_api._read_json(_api._COVERAGE_FILE))


@router.get("/api/threat-model")
async def api_get_threat_model(file: str = "") -> JSONResponse:
    files: list[str] = []
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
        candidate = (_api._THREAT_MODEL_DIR / file).resolve()
        if not str(candidate).startswith(str(_api._THREAT_MODEL_DIR.resolve())):
            return JSONResponse({"error": "invalid file"}, status_code=400)
        if candidate.exists():
            content = candidate.read_text(encoding="utf-8")

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


@router.post("/api/complete")
async def api_complete(request: Request) -> JSONResponse:
    """Human-triggered scan completion.

    Only this endpoint (called from the dashboard) can mark a scan complete.
    Smith cannot complete a scan autonomously — session(action='complete') is blocked.
    Body: {"notes": "optional completion notes"}

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
        cfg   = scan_session.complete(notes)
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


# ── Smith lifecycle ─────────────────────────────────────────────────────────

@router.get("/api/smith-status")
async def api_smith_status() -> JSONResponse:
    return JSONResponse({"running": _api._smith_running()})


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
        all_files = sorted(
            [p.name for p in _LOG_DIR.glob("*.log")],
            reverse=True,
        )
        target = _LOG_DIR / file if file else log_path
        if not target.resolve().is_relative_to(_LOG_DIR.resolve()):
            return JSONResponse({"lines": [], "files": all_files, "error": "invalid path"})
        lines = target.read_text(encoding="utf-8").splitlines() if target.exists() else []
        return JSONResponse({"lines": lines, "file": target.name, "files": all_files})
    except Exception as exc:
        return JSONResponse({"lines": [], "files": [], "error": str(exc)})
