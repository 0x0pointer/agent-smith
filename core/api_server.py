"""
FastAPI web server
==================
Serves the dashboard UI and REST API on the same port (default 7777).

Routes
------
  GET /               → dashboard UI
  GET /api/findings   → current scan findings + diagrams (findings.json)
  GET /api/session    → current scan session state (session.json)
  GET /api/cost       → current scan cost breakdown (session_cost.json)
  GET /api/logs       → current session log lines

Usage
-----
  from core.api_server import serve
  url = await serve(port=7777)
  # → "http://localhost:7777"
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from pathlib import Path

_log = logging.getLogger(__name__)

_REPO_ROOT         = Path(__file__).parent.parent
_FINDINGS_FILE     = _REPO_ROOT / "findings.json"
_SESSION_FILE      = _REPO_ROOT / "session.json"
_COST_FILE         = _REPO_ROOT / "session_cost.json"
_COVERAGE_FILE     = _REPO_ROOT / "coverage_matrix.json"
_QA_STATE_FILE     = _REPO_ROOT / "qa_state.json"
_STEERING_FILE     = _REPO_ROOT / "steering_queue.json"
_QUICK_LOG_FILE    = _REPO_ROOT / "quick_log.json"
_METRICS_FILE      = _REPO_ROOT / "pentest_metrics.jsonl"
_TEMPLATES_DIR     = _REPO_ROOT / "templates"
_THREAT_MODEL_DIR  = _REPO_ROOT / "threat-model"
_SMITH_PID_FILE    = _REPO_ROOT / "logs" / "smith.pid"
_SMITH_CLIENT_FILE = _REPO_ROOT / "logs" / "smith.client"

# ── FastAPI app ───────────────────────────────────────────────────────────────

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse

app = FastAPI(title="pentest-agent")

_qa_task:        asyncio.Task | None = None  # kept alive to prevent GC
_watchdog_task:  asyncio.Task | None = None
# Auto-restart watchdog state
_watchdog_last_restart_ts: float = 0.0
_watchdog_restart_count_window: list[float] = []  # epoch seconds of restarts in trailing hour
_WATCHDOG_POLL_SECONDS  = 60
_WATCHDOG_MIN_GAP_SECONDS = 90       # min seconds between auto-restarts
_WATCHDOG_MAX_PER_HOUR  = 20         # safety cap to avoid restart storms


@app.on_event("startup")
async def _start_background_tasks() -> None:
    global _qa_task, _watchdog_task
    from mcp_server._app import _load_dotenv
    _load_dotenv()
    from core.qa_agent import qa_daemon
    _qa_task = asyncio.create_task(qa_daemon.run(interval_s=120))
    _watchdog_task = asyncio.create_task(_smith_watchdog_loop())


# ── Helpers ───────────────────────────────────────────────────────────────────

def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text()) if path.exists() else {}
    except Exception:
        return {}


_svg_cache: dict[str, dict[str, str]] = {}  # content_hash -> svgs dict

# Remap light-theme inline styles to dark-mode equivalents
_DARK_REMAP = {
    # Reds (danger/critical)
    "fill:#f44": "fill:#5c1a1a", "fill:#f88": "fill:#6b1a1a",
    "fill:#faa": "fill:#5c1a1a", "fill:#fcc": "fill:#4d1a1a",
    "fill:#e53e3e": "fill:#7f1d1d", "fill:#fc8181": "fill:#6b2020",
    # Yellows/oranges (warning)
    "fill:#ffd": "fill:#3d3000", "fill:#ffa": "fill:#3d3000",
    # Greens (safe/mitigated)
    "fill:#68d391": "fill:#14532d", "fill:#48bb78": "fill:#14532d",
    # Blues
    "fill:#ddf": "fill:#1a2a4a", "fill:#bbf": "fill:#1a2040",
    "fill:#63b3ed": "fill:#1e3a5f",
    # Strokes
    "stroke:#c00": "stroke:#ff6666", "stroke:#a00": "stroke:#ff5555",
    "stroke:#c44": "stroke:#ff8888", "stroke:#aa0": "stroke:#ddcc00",
    "stroke:#44a": "stroke:#6699ff", "stroke:#c53030": "stroke:#f87171",
    "stroke:#e53e3e": "stroke:#f87171", "stroke:#38a169": "stroke:#4ade80",
    # Text color overrides — force light text
    "color:#fff": "color:#e5e7eb", "color:#000": "color:#e5e7eb",
}

def _remap_mermaid_dark(src: str) -> str:
    for light, dark in _DARK_REMAP.items():
        src = src.replace(light, dark)
    return src


def _render_mermaid_svgs(content: str) -> dict[str, str]:
    """Extract mermaid blocks from markdown and render each to SVG via mmdc.
    Results are cached by content hash to avoid blocking on every poll."""
    import hashlib
    import re
    import subprocess
    import tempfile

    content_hash = hashlib.sha256(content.encode()).hexdigest()
    if content_hash in _svg_cache:
        return _svg_cache[content_hash]

    blocks = re.findall(r'```mermaid\n(.*?)```', content, re.DOTALL)
    svgs: dict[str, str] = {}
    config_path = _REPO_ROOT / 'core' / 'mermaid-config.json'

    for i, block in enumerate(blocks):
        try:
            with tempfile.NamedTemporaryFile(suffix='.mmd', mode='w', delete=False) as f:
                f.write(_remap_mermaid_dark(block))
                inp = f.name
            out = inp.replace('.mmd', '.svg')
            subprocess.run(
                ['npx', '@mermaid-js/mermaid-cli', '-i', inp, '-o', out,
                 '-c', str(config_path),
                 '--backgroundColor', 'transparent'],
                capture_output=True, text=True, timeout=60,
                cwd=str(_REPO_ROOT),
            )
            if os.path.exists(out):
                svgs[str(i)] = Path(out).read_text()
                os.unlink(out)
            os.unlink(inp)
        except Exception:
            pass

    _svg_cache[content_hash] = svgs
    return svgs


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/")
async def dashboard_ui() -> FileResponse:
    return FileResponse(_TEMPLATES_DIR / "dashboard.html")


@app.get("/logo.png")
async def logo() -> FileResponse:
    return FileResponse(_TEMPLATES_DIR / "FullLogo_Transparent.png", media_type="image/png")


@app.get("/favicon.ico")
async def favicon() -> FileResponse:
    # Browser default favicon probe. Serve the existing transparent logo so
    # we stop spamming the access log with 404s on every page load.
    return FileResponse(_TEMPLATES_DIR / "FullLogo_Transparent.png", media_type="image/png")


@app.get("/api/findings")
async def api_findings() -> JSONResponse:
    data = _read_json(_FINDINGS_FILE)
    # Render diagram SVGs server-side so topology tab matches threat model theme
    for d in data.get("diagrams", []):
        if d.get("mermaid") and "svg" not in d:
            wrapped = f"```mermaid\n{d['mermaid']}\n```"
            svgs = _render_mermaid_svgs(wrapped)
            d["svg"] = svgs.get("0", "")
    return JSONResponse(data)


@app.get("/api/session")
async def api_session() -> JSONResponse:
    return JSONResponse(_read_json(_SESSION_FILE))


@app.get("/api/cost")
async def api_cost() -> JSONResponse:
    return JSONResponse(_read_json(_COST_FILE))


@app.get("/api/coverage")
async def api_coverage() -> JSONResponse:
    return JSONResponse(_read_json(_COVERAGE_FILE))


@app.get("/api/threat-model")
async def api_get_threat_model(file: str = "") -> JSONResponse:
    files: list[str] = []
    if _THREAT_MODEL_DIR.exists():
        # Sort by modification time (most recent first) so the active scan's
        # threat model appears as the default selection.
        md_paths = list(_THREAT_MODEL_DIR.glob("*.md"))
        md_paths.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        files = [p.name for p in md_paths]

    if not file and files:
        file = files[0]

    content = ""
    if file:
        if "/" in file or "\\" in file or ".." in file:
            return JSONResponse({"error": "invalid file"}, status_code=400)
        candidate = (_THREAT_MODEL_DIR / file).resolve()
        if not str(candidate).startswith(str(_THREAT_MODEL_DIR.resolve())):
            return JSONResponse({"error": "invalid file"}, status_code=400)
        if candidate.exists():
            content = candidate.read_text(encoding="utf-8")

    svgs = {}
    if content:
        svgs = _render_mermaid_svgs(content)

    return JSONResponse({"files": files, "file": file, "content": content, "svgs": svgs})


@app.patch("/api/findings/{finding_id}")
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
    except Exception as exc:
        _log.error("api_update_finding failed: %s", exc)
        return JSONResponse({"ok": False, "error": "Request failed"}, status_code=400)


@app.delete("/api/findings/{finding_id}")
async def api_delete_finding(finding_id: str) -> JSONResponse:
    from core.findings import delete_finding
    try:
        archived = await delete_finding(finding_id)
        return JSONResponse({"ok": archived})
    except Exception as exc:
        _log.error("api_delete_finding failed: %s", exc)
        return JSONResponse({"ok": False, "error": "Request failed"}, status_code=400)


def _safe_unlink(path) -> None:
    """Unlink a file, ignoring errors."""
    try:
        path.unlink(missing_ok=True)
    except Exception:
        pass


def _clear_dir_files(directory) -> None:
    """Delete all regular files inside a directory, ignoring errors."""
    try:
        if not directory.exists():
            return
        for f in directory.iterdir():
            try:
                if f.is_file():
                    f.unlink()
            except Exception:
                pass
    except Exception:
        pass


def _clear_log_files(log_dir) -> None:
    """Truncate all *.log files in log_dir to zero bytes."""
    try:
        for log_file in log_dir.glob("*.log"):
            try:
                log_file.write_text("")
            except Exception:
                pass
    except Exception:
        pass


@app.delete("/api/clear")
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

    _RECOVERY_SNAP = _REPO_ROOT / "recovery_latest.json"
    _METRICS_FILE  = _REPO_ROOT / "pentest_metrics.jsonl"
    # _COVERAGE_FILE is intentionally omitted — reset() above already wrote the empty state.
    # Deleting it would cause /api/coverage to return {} instead of an empty-but-valid matrix.
    for path in (_SESSION_FILE, _QUICK_LOG_FILE, _QA_STATE_FILE,
                 _COST_FILE, _STEERING_FILE, _RECOVERY_SNAP, _METRICS_FILE):
        _safe_unlink(path)

    # log files in logs/
    try:
        from core.logger import _LOG_DIR
        _clear_log_files(_LOG_DIR)
    except Exception:
        pass

    # pocs/ — clear .http files so PoC count doesn't bleed between sessions
    try:
        pocs_dir = _REPO_ROOT / "pocs"
        if pocs_dir.exists():
            for poc_file in pocs_dir.glob("*.http"):
                _safe_unlink(poc_file)
    except Exception:
        pass

    # artifacts/ — raw scanner output files
    _clear_dir_files(_REPO_ROOT / "artifacts")

    # threat-model/ — generated HTML/MD reports
    _clear_dir_files(_REPO_ROOT / "threat-model")

    # gh-issues.md — exported GitHub issue blocks
    _safe_unlink(_REPO_ROOT / "gh-issues.md")

    await _cleanup_tunnels()
    return JSONResponse({"ok": True})


@app.delete("/api/tunnels")
async def api_cleanup_tunnels() -> JSONResponse:
    """Kill chisel tunnels in Kali. Remote clients disconnect automatically."""
    result = await _cleanup_tunnels()
    return JSONResponse({"ok": True, "message": result})


async def _cleanup_tunnels() -> str:
    """Kill chisel server in the Kali container.

    When the server dies, remote chisel clients lose their connection
    and exit on their own — no need to reach back into the target.
    """
    import asyncio

    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "inspect", "--format={{.State.Running}}", "pentest-kali",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await proc.communicate()
        if stdout.strip() != b"true":
            return "no kali container running"

        proc = await asyncio.create_subprocess_exec(
            "docker", "exec", "pentest-kali",
            "sh", "-c", "pkill -f 'chisel server' 2>/dev/null && echo 'chisel stopped' || echo 'no chisel running'",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await proc.communicate()
        return stdout.decode().strip()
    except Exception as exc:
        _log.error("cleanup_tunnels failed: %s", exc)
        return "cleanup error"


@app.get("/api/intervention")
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


@app.post("/api/intervention/respond")
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
        return JSONResponse({"ok": False, "error": "Request failed"}, status_code=500)


@app.post("/api/steer")
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
        return JSONResponse({"ok": False, "error": "Request failed"}, status_code=500)


@app.post("/api/complete")
async def api_complete(request: Request) -> JSONResponse:
    """Human-triggered scan completion.

    Only this endpoint (called from the dashboard) can mark a scan complete.
    Smith cannot complete a scan autonomously — session(action='complete') is blocked.
    Body: {"notes": "optional completion notes"}
    """
    try:
        from core import session as scan_session
        # Force-reload so we mutate against the freshest disk state, not a
        # cached _current snapshot.
        scan_session.load_from_disk(force=True)
        body  = await request.json()
        notes = str(body.get("notes", "")).strip()
        cfg   = scan_session.complete(notes)
        status = cfg.get("status", "complete")
        return JSONResponse({"ok": True, "status": status})
    except Exception:
        _log.exception("api_complete failed")
        return JSONResponse({"ok": False, "error": "Request failed"}, status_code=500)


_SMITH_IDLE_SECONDS = 180  # >3 min with no scan activity → Smith is considered stopped


def _smith_running() -> bool:
    """Return True if any Smith (claude OR opencode, dashboard- or manually-launched) is active.

    Two signals — either is sufficient:
      1. The tracked PID (from a dashboard restart) is still alive.
      2. session.json / quick_log.json was modified within _SMITH_IDLE_SECONDS,
         meaning some MCP client is actively making tool calls.

    The activity signal catches Smith processes the dashboard didn't spawn
    (e.g. user started opencode or claude manually) while still using PID
    tracking for the immediate-feedback case after the Restart Smith button.
    """
    # PID file (dashboard-spawned process). Cap the parsed PID at 2**22 (the
    # POSIX kernel.pid_max upper bound on common Linux/macOS) so a maliciously
    # large value in the file can't blow up os.kill with an OverflowError.
    try:
        raw_pid = _SMITH_PID_FILE.read_text().strip()
        pid = int(raw_pid)
        if 0 < pid < (1 << 22):
            os.kill(pid, 0)
            return True
    except (FileNotFoundError, ValueError, ProcessLookupError, PermissionError) as e:
        _log.debug("smith_running: pid file check skipped: %s", e)
    except OSError as e:
        _log.debug("smith_running: os.kill failed: %s", e)

    # Activity signal: quick_log.json mtime only. session.json is mutated by
    # dashboard endpoints (resolve_intervention, complete, etc.) which would
    # falsely make _smith_running() return True. quick_log is written only
    # when an MCP client makes a tool call, so it's a true Smith heartbeat.
    import time
    now = time.time()
    try:
        if _QUICK_LOG_FILE.exists() and now - _QUICK_LOG_FILE.stat().st_mtime < _SMITH_IDLE_SECONDS:
            return True
    except OSError as e:
        _log.debug("smith_running: quick_log mtime check failed: %s", e)
    return False


@app.get("/api/smith-status")
async def api_smith_status() -> JSONResponse:
    return JSONResponse({"running": _smith_running()})


def _client_installed(name: str) -> bool:
    import shutil
    if name == "claude":
        return bool(shutil.which("claude") or os.path.exists("/opt/homebrew/bin/claude"))
    if name == "opencode":
        return bool(shutil.which("opencode") or os.path.exists("/Users/gibson/.opencode/bin/opencode"))
    return False


def _client_process_running(name: str) -> bool:
    """Check whether any process for the given client is currently running."""
    import subprocess
    try:
        r = subprocess.run(
            ["pgrep", "-f", name],
            capture_output=True, text=True, timeout=2,
        )
        return bool(r.stdout.strip())
    except Exception:
        return False


def _detect_active_client() -> str:
    """Detect which client (claude or opencode) should be used for restart.

    Resolution order:
      1. Last client persisted in logs/smith.client (from a previous restart)
      2. The client whose process is currently running on this host
      3. opencode if installed (preferred when both are available, since claude
         is the default elsewhere)
      4. claude as last resort
    """
    try:
        saved = _SMITH_CLIENT_FILE.read_text().strip().lower()
        if saved in ("claude", "opencode") and _client_installed(saved):
            return saved
    except Exception:
        pass
    if _client_process_running("opencode") and _client_installed("opencode"):
        return "opencode"
    if _client_process_running("claude") and _client_installed("claude"):
        return "claude"
    if _client_installed("opencode"):
        return "opencode"
    return "claude"


@app.get("/api/smith-clients")
async def api_smith_clients() -> JSONResponse:
    """Return available clients and the auto-detected active one."""
    return JSONResponse({
        "claude":   _client_installed("claude"),
        "opencode": _client_installed("opencode"),
        "active":   _detect_active_client(),
    })


async def _spawn_smith(client: str, source: str = "api") -> tuple[bool, int | str]:
    """Core spawn logic shared by the /api/restart-smith endpoint and the
    watchdog. Returns (ok, pid_or_error_message). source is logged so the
    audit trail distinguishes manual restarts from auto-restarts.
    """
    try:
        from core.steering import steering_queue
        active = steering_queue.get_active()
        directive_text = ""
        if active:
            directive_text = "\n\nAct on these pending human instructions immediately after recovery:\n" + \
                "\n".join(f"- {d.message}" for d in active)

        from core import session as scan_session
        scan_session.load_from_disk(force=True)
        current = scan_session.get() or {}
        if current.get("status") == "intervention_required":
            scan_session.resolve_intervention(
                "CONTINUE",
                f"Smith restarted (source={source})",
            )

        prompt = (
            "Recover the active pentest scan. "
            "Call session(action='recovery') to get your current position, "
            "then immediately execute the EXECUTE_NOW field — do NOT ask for confirmation, "
            "do NOT summarise what you plan to do, just start tool calls. "
            "If session(action='status') returns qa_alerts, answer them with "
            "session(action='qa_reply') before continuing. "
            "Keep working autonomously until you are genuinely blocked and cannot "
            "proceed without new human input. Do NOT stop to ask questions."
            + directive_text
        )

        log_path = _REPO_ROOT / "logs" / "smith_restart.log"
        log_path.parent.mkdir(exist_ok=True)
        # Audit marker so watchdog vs manual restarts are visible in the log
        with open(log_path, "a") as f:
            f.write(f"\n=== [{source}] spawning {client} at {asyncio.get_event_loop().time()} ===\n")

        import shutil
        if client == "claude":
            binary = shutil.which("claude") or "/opt/homebrew/bin/claude"
            args = [binary, "--dangerously-skip-permissions", "-p", prompt]
        else:
            binary = shutil.which("opencode") or "/Users/gibson/.opencode/bin/opencode"
            args = [binary, "run", prompt]

        if not os.path.exists(binary):
            return False, f"{client} binary not found at {binary}"

        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=open(log_path, "a"),
            stderr=open(log_path, "a"),
            cwd=str(_REPO_ROOT),
            start_new_session=True,
        )
        _SMITH_PID_FILE.write_text(str(proc.pid))
        _SMITH_CLIENT_FILE.write_text(client)
        return True, proc.pid
    except Exception:
        _log.exception("spawn_smith failed")
        return False, "spawn failed"


async def _mcp_sse_alive() -> bool:
    """Quick liveness check on the MCP SSE server (port 7778).

    Used by the watchdog to skip restarts when MCP is dead — restarting
    Smith into a dead MCP causes a 30–60s burn of subprocess fallbacks
    that always fail and end the opencode -p run with a text response.

    Socket is wrapped in contextlib.closing so the file descriptor is
    released even when settimeout/connect_ex raises before our own .close().
    """
    import contextlib
    import socket
    try:
        with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.settimeout(0.8)
            return sock.connect_ex(("127.0.0.1", 7778)) == 0
    except (OSError, socket.gaierror) as e:
        _log.debug("mcp_sse_alive check failed: %s", e)
        return False


async def _smith_watchdog_loop() -> None:
    """Background task: auto-restart Smith when it dies mid-scan.

    Conditions for an auto-restart:
      - session.status == "running"
      - no active intervention (HIR_*) — human still needs to resolve
      - Smith process is not alive (per _smith_running)
      - at least _WATCHDOG_MIN_GAP_SECONDS since the last auto-restart
      - fewer than _WATCHDOG_MAX_PER_HOUR restarts in the trailing hour

    Idle when status != "running" or session is gone. Runs forever as long
    as the dashboard process lives. Safety cap prevents storms when Smith
    dies immediately on startup repeatedly (e.g. config error).
    """
    global _watchdog_last_restart_ts
    import time as _time
    while True:
        try:
            await asyncio.sleep(_WATCHDOG_POLL_SECONDS)
            session_data = _read_json(_SESSION_FILE)
            if session_data.get("status") != "running":
                continue
            if (session_data.get("intervention") or {}).get("code"):
                continue
            if _smith_running():
                continue
            # Gate on MCP SSE health. Without MCP, restarted Smith burns a turn
            # bouncing off "Invalid request parameters" and producing a text
            # response that ends the opencode -p run — causing the watchdog to
            # respawn into the same wall every minute.
            if not await _mcp_sse_alive():
                _log.warning("watchdog suppressed: MCP SSE server unreachable on 127.0.0.1:7778")
                continue
            now = _time.time()
            if now - _watchdog_last_restart_ts < _WATCHDOG_MIN_GAP_SECONDS:
                continue
            # Prune restarts older than 1h
            _watchdog_restart_count_window[:] = [
                t for t in _watchdog_restart_count_window if now - t < 3600
            ]
            if len(_watchdog_restart_count_window) >= _WATCHDOG_MAX_PER_HOUR:
                _log.warning(
                    "watchdog suppressed: %d restarts in last hour exceeds cap %d",
                    len(_watchdog_restart_count_window), _WATCHDOG_MAX_PER_HOUR,
                )
                continue

            client = _detect_active_client()
            _log.info("watchdog: smith stopped while scan running — auto-restart (%s)", client)
            ok, result = await _spawn_smith(client, source="watchdog")
            if ok:
                _watchdog_last_restart_ts = now
                _watchdog_restart_count_window.append(now)
                _log.info("watchdog: spawned pid=%s", result)
        except asyncio.CancelledError:
            return
        except Exception:
            _log.exception("watchdog loop error (continuing)")


@app.get("/api/watchdog")
async def api_watchdog_status() -> JSONResponse:
    """Diagnostic: report watchdog state — last restart, count in last hour."""
    import time as _time
    now = _time.time()
    recent = [t for t in _watchdog_restart_count_window if now - t < 3600]
    return JSONResponse({
        "enabled": _watchdog_task is not None and not (_watchdog_task and _watchdog_task.done()),
        "last_restart_ago_s": int(now - _watchdog_last_restart_ts) if _watchdog_last_restart_ts else None,
        "restarts_in_last_hour": len(recent),
        "max_per_hour": _WATCHDOG_MAX_PER_HOUR,
        "poll_seconds": _WATCHDOG_POLL_SECONDS,
        "min_gap_seconds": _WATCHDOG_MIN_GAP_SECONDS,
    })


@app.post("/api/restart-smith")
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
    if not force and _smith_running():
        return JSONResponse({"ok": False, "error": "Smith is already running. Pass force=true to override."}, status_code=409)
    client = (body.get("client") or _detect_active_client()).lower()
    if client not in ("claude", "opencode"):
        return JSONResponse({"ok": False, "error": f"Unknown client: {client}"}, status_code=400)
    if not _client_installed(client):
        return JSONResponse(
            {"ok": False, "error": f"{client} is not installed on this host"},
            status_code=400,
        )

    ok, result = await _spawn_smith(client, source="api")
    if ok:
        return JSONResponse({"ok": True, "pid": result, "client": client})
    return JSONResponse({"ok": False, "error": str(result)}, status_code=500)


@app.get("/api/qa")
async def api_qa() -> JSONResponse:
    return JSONResponse(_read_json(_QA_STATE_FILE))


@app.get("/api/steering")
async def api_steering() -> JSONResponse:
    return JSONResponse(_read_json(_STEERING_FILE))


@app.get("/api/metrics")
async def api_metrics() -> JSONResponse:
    import core.metrics as metrics_mod
    return JSONResponse(metrics_mod.load_all())


@app.get("/api/quicklog")
async def api_quicklog() -> JSONResponse:
    if not _QUICK_LOG_FILE.exists():
        return JSONResponse([])
    entries: list[dict] = []
    for line in _QUICK_LOG_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                entries.append(json.loads(line))
            except Exception:
                pass
    return JSONResponse(entries)


@app.get("/api/logs")
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


# ── Server lifecycle ──────────────────────────────────────────────────────────

_PID_FILE = _REPO_ROOT / "logs" / "dashboard.pid"


def _read_pid() -> int | None:
    try:
        return int(_PID_FILE.read_text().strip())
    except Exception:
        return None


def _write_pid(pid: int) -> None:
    _PID_FILE.write_text(str(pid))


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)  # NOSONAR - signal 0 is a POSIX liveness probe, not a real signal
        return True
    except OSError:
        return False


def _port_healthy(port: int) -> bool:
    """Return True only if our FastAPI dashboard is responding on this port."""
    import urllib.request
    try:
        with urllib.request.urlopen(f"http://localhost:{port}/api/session", timeout=2) as r:
            return r.status == 200
    except Exception:
        return False


async def serve(port: int = 7777) -> str:
    """
    Start the dashboard server as an independent background process.
    Survives MCP server restarts — uses a PID file to detect and reuse
    a previously spawned dashboard instead of killing it.
    """
    import signal

    # Check PID file first — survives MCP server restarts
    saved_pid = _read_pid()
    if saved_pid and _pid_alive(saved_pid) and _port_healthy(port):
        return f"http://localhost:{port}"

    # Old process died or never existed — clean up stale PID on port
    if saved_pid and _pid_alive(saved_pid):
        try:
            os.kill(saved_pid, signal.SIGTERM)  # NOSONAR - SIGTERM sent only to our own spawned dashboard child process
            await asyncio.sleep(0.3)
        except OSError:
            pass

    # Fire-and-forget: process runs independently in a new session.
    # stdout/stderr → /dev/null so the MCP stdio pipe is never touched.
    # start_new_session=True detaches from MCP server's process group.
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "uvicorn",
        "core.api_server:app",
        "--host", "0.0.0.0",
        "--port", str(port),
        "--no-access-log",
        "--log-level", "critical",
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
        cwd=str(_REPO_ROOT),
        start_new_session=True,
    )
    _write_pid(proc.pid)

    await asyncio.sleep(1.5)     # give uvicorn time to bind the port
    if not _port_healthy(port):
        return f"Dashboard failed to start on port {port}"
    return f"http://localhost:{port}"
