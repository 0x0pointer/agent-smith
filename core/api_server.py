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
_ERR_REQUEST_FAILED = "Request failed"

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
_status_task:    asyncio.Task | None = None
# Auto-restart watchdog state
_watchdog_last_restart_ts: float = 0.0
_watchdog_restart_count_window: list[float] = []  # epoch seconds of restarts in trailing hour
_WATCHDOG_POLL_SECONDS  = 60
_WATCHDOG_MIN_GAP_SECONDS = 90       # min seconds between auto-restarts
_WATCHDOG_MAX_PER_HOUR  = 20         # safety cap to avoid restart storms

# Periodic status update — interval is configurable via .env so an operator
# can dial it down for a long-running engagement. 0 disables the loop.
_STATUS_UPDATE_DEFAULT_MINUTES = 30


@app.on_event("startup")
async def _start_background_tasks() -> None:
    global _qa_task, _watchdog_task, _status_task
    from mcp_server._app import _load_dotenv
    _load_dotenv()
    from core.qa_agent import qa_daemon
    _qa_task = asyncio.create_task(qa_daemon.run(interval_s=120))
    _watchdog_task = asyncio.create_task(_smith_watchdog_loop())
    _status_task = asyncio.create_task(_status_update_loop())


async def _status_update_loop() -> None:
    """Fire a notifier status update every STATUS_UPDATE_INTERVAL_MINUTES.

    Skips when no scan is running so operators don't get idle pings.
    Reads the interval from env at startup so editing .env takes effect
    on the next dashboard restart (cheaper than re-reading every tick).
    Set STATUS_UPDATE_INTERVAL_MINUTES=0 to disable entirely.
    """
    import os
    raw = os.environ.get("STATUS_UPDATE_INTERVAL_MINUTES", "").strip()
    try:
        interval_min = int(raw) if raw else _STATUS_UPDATE_DEFAULT_MINUTES
    except ValueError:
        interval_min = _STATUS_UPDATE_DEFAULT_MINUTES
    if interval_min <= 0:
        return  # disabled
    interval_s = interval_min * 60

    from core import notifiers, status_reporter
    while True:
        try:
            await asyncio.sleep(interval_s)
            if not status_reporter.should_emit():
                continue
            msg = status_reporter.compose_status_message()
            if msg:
                notifiers.notify(**msg)
        except asyncio.CancelledError:
            raise
        except Exception:
            # Never let a status-update failure kill the loop — the
            # operator notices the next tick anyway. Log and continue.
            import logging
            logging.getLogger(__name__).exception(
                "status update tick failed"
            )


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
    """Real .ico file served with the correct media type. Browsers that
    auto-probe /favicon.ico (Safari, every IE-lineage thing) want this
    exact path and content-type to avoid logging a 404 on every page load."""
    return FileResponse(
        _TEMPLATES_DIR / "favicon.ico",
        media_type="image/vnd.microsoft.icon",
    )


@app.get("/favicon-32x32.png")
async def favicon_png() -> FileResponse:
    """Sized PNG favicon for modern browsers — referenced explicitly from
    the <link rel="icon" sizes="32x32"> tag in dashboard.html. Modern
    rendering pipelines prefer this over the .ico when both are available."""
    return FileResponse(
        _TEMPLATES_DIR / "favicon-32x32.png",
        media_type="image/png",
    )


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
    except Exception:
        _log.exception("api_update_finding failed")
        return JSONResponse({"ok": False, "error": _ERR_REQUEST_FAILED}, status_code=400)


@app.delete("/api/findings/{finding_id}")
async def api_delete_finding(finding_id: str) -> JSONResponse:
    from core.findings import delete_finding
    try:
        archived = await delete_finding(finding_id)
        return JSONResponse({"ok": archived})
    except Exception:
        _log.exception("api_delete_finding failed")
        return JSONResponse({"ok": False, "error": _ERR_REQUEST_FAILED}, status_code=400)


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
    # _SMITH_PID_FILE + _SMITH_CLIENT_FILE are scan-tied pointers — a stale
    # PID from the previous scan biases _detect_active_client() toward the old
    # client and clutters smith-status diagnostics for the next scan.
    for path in (_SESSION_FILE, _QUICK_LOG_FILE, _QA_STATE_FILE,
                 _COST_FILE, _STEERING_FILE, _RECOVERY_SNAP, _METRICS_FILE,
                 _SMITH_PID_FILE, _SMITH_CLIENT_FILE):
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
    except Exception:
        _log.exception("cleanup_tunnels failed")
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
        return JSONResponse({"ok": False, "error": _ERR_REQUEST_FAILED}, status_code=500)


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
        return JSONResponse({"ok": False, "error": _ERR_REQUEST_FAILED}, status_code=500)


@app.post("/api/complete")
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
        for path in (_SMITH_PID_FILE, _SMITH_CLIENT_FILE, _QUICK_LOG_FILE):
            _safe_unlink(path)

        return JSONResponse({"ok": True, "status": status})
    except Exception:
        _log.exception("api_complete failed")
        return JSONResponse({"ok": False, "error": _ERR_REQUEST_FAILED}, status_code=500)


# >5 min with no scan activity → Smith is considered stopped.
# Was 60s previously, but Qwen3.6-A3B thinking-mode reasoning regularly runs
# 2–3 min between tool calls. 60s caused steady false positives during
# normal thinking pauses, sending bogus WATCHDOG_SMITH_STOPPED alerts to
# Telegram/Slack/Discord. 300s catches real Smith deaths within 5 min while
# tolerating long internal reasoning blocks.
_SMITH_IDLE_SECONDS = 300

# Process patterns a psutil-based fallback considers "Smith is alive".
# Used by _smith_running() as a last-resort signal after the PID-file and
# activity-mtime checks both fail. Matches against the joined cmdline of
# each running process. Anchored to project-specific binaries (claude with
# its dangerous flag, opencode runners, codex MCP launches) so unrelated
# processes don't false-positive.
_SMITH_PROC_NEEDLES = (
    # claude CLI driving an agent-smith scan
    "claude --dangerously-skip-permissions",
    # opencode run (direct binary OR wrapped via node)
    ".opencode/bin/opencode",
    "opencode run",
    # codex MCP-server launches
    "codex run",
    "codex mcp",
)


def _signal_pid_file_alive() -> bool:
    """Signal #1: tracked PID from a dashboard-managed spawn is still alive.

    Caps the parsed PID at 2**22 so a malformed value can't blow up the
    liveness probe. psutil.pid_exists works identically on macOS/Linux/
    Windows — the older os.kill(pid, 0) probe was POSIX-only.
    """
    try:
        import psutil
        pid = int(_SMITH_PID_FILE.read_text().strip())
    except (FileNotFoundError, ValueError, PermissionError) as e:
        _log.debug("smith_running: pid file check skipped: %s", e)
        return False
    except ImportError:
        _log.debug("smith_running: psutil missing; skipping pid-file check")
        return False
    if not (0 < pid < (1 << 22)):
        return False
    try:
        return bool(psutil.pid_exists(pid))
    except OSError as e:
        _log.debug("smith_running: pid_exists failed: %s", e)
        return False


def _signal_quick_log_fresh() -> bool:
    """Signal #2: quick_log.json mtime is within the idle window.

    Written only by MCP tool calls, never by dashboard endpoints, so it's
    a true Smith activity heartbeat.
    """
    import time
    try:
        if not _QUICK_LOG_FILE.exists():
            return False
        age = time.time() - _QUICK_LOG_FILE.stat().st_mtime
        return age < _SMITH_IDLE_SECONDS
    except OSError as e:
        _log.debug("smith_running: quick_log mtime check failed: %s", e)
        return False


def _signal_session_recently_started() -> bool:
    """Signal #2b: quick_log is missing AND session.json says we started
    within the last 2 hours. Only fires when quick_log is completely
    absent (cleared by /api/clear or archived on target change) — a
    stale-but-present quick_log means Smith was active and stopped.
    """
    if _QUICK_LOG_FILE.exists():
        return False
    try:
        import json as _json
        from datetime import datetime as _dt, timezone as _tz
        sd = _json.loads(_SESSION_FILE.read_text())
        if sd.get("status") != "running" or sd.get("finished") is not None:
            return False
        started_raw = sd.get("started", "")
        if not started_raw:
            return False
        elapsed = (_dt.now(_tz.utc) - _dt.fromisoformat(started_raw)).total_seconds()
        return elapsed < 7200
    except (OSError, ValueError, KeyError) as e:
        _log.debug("smith_running: session.json fallback check failed: %s", e)
        return False


def _signal_process_scan_finds_client() -> bool:
    """Signal #3: a live process matches an MCP-client cmdline pattern.

    Catches the situation where smith.pid points at a stale dead dashboard-
    spawn but the operator manually relaunched opencode/claude in a
    terminal and is actively driving the scan. Run last — iterating every
    process is the most expensive signal, but still well under 10 ms.
    """
    try:
        import psutil
    except ImportError:
        _log.debug("smith_running: process-scan fallback unavailable (psutil missing)")
        return False
    try:
        for proc in psutil.process_iter(["cmdline"]):
            if _process_matches_smith(proc):
                return True
    except (OSError, psutil.AccessDenied):
        _log.debug("smith_running: process-scan fallback unavailable")
    return False


def _process_matches_smith(proc) -> bool:
    """True iff the process's cmdline contains a known Smith-client needle."""
    try:
        import psutil
        cmd = " ".join(proc.info.get("cmdline") or []).lower()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False
    if not cmd:
        return False
    return any(needle in cmd for needle in _SMITH_PROC_NEEDLES)


def _smith_running() -> bool:
    """Return True if any Smith (claude OR opencode, dashboard- or manually-launched) is active.

    Any one signal is sufficient — checked in cheapest-first order:
      1. ``_signal_pid_file_alive``           — tracked PID from a dashboard spawn
      2. ``_signal_quick_log_fresh``          — recent MCP tool-call heartbeat
      3. ``_signal_session_recently_started`` — scan started < 2 h ago with
                                                quick_log wiped (post-clear case)
      4. ``_signal_process_scan_finds_client``— live opencode/claude/codex process

    Each helper handles its own exceptions and returns False on any
    fault, so the top-level function stays low-complexity.
    """
    return (
        _signal_pid_file_alive()
        or _signal_quick_log_fresh()
        or _signal_session_recently_started()
        or _signal_process_scan_finds_client()
    )


def _live_pid_from_pid_file() -> int | None:
    """Read smith.pid, return the PID iff it's still alive. None otherwise."""
    try:
        import psutil
        pid = int(_SMITH_PID_FILE.read_text().strip())
    except (FileNotFoundError, ValueError, PermissionError, ImportError):
        return None
    if not (0 < pid < (1 << 22)):
        return None
    try:
        return pid if psutil.pid_exists(pid) else None
    except OSError:
        return None


def _live_pid_from_process_scan() -> int | None:
    """Return the PID of the first live process whose cmdline matches a
    Smith-client needle. None if psutil is missing or no match.
    """
    try:
        import psutil
        for proc in psutil.process_iter(["cmdline", "pid"]):
            if _process_matches_smith(proc):
                try:
                    return int(proc.info.get("pid") or proc.pid)
                except (ValueError, TypeError, AttributeError):
                    continue
    except (ImportError, OSError):
        return None
    except Exception as e:  # psutil.AccessDenied at iter-time
        _log.debug("process scan for hung pid failed: %s", e)
    return None


def _smith_hung_pid() -> int | None:
    """Return the PID of a hung Smith process, or None.

    A process is *hung* when it satisfies BOTH:

      • a Smith-like process exists (pid file points at a live PID OR a
        live process matches a Smith cmdline needle), AND
      • no MCP heartbeat in the last ``_SMITH_IDLE_SECONDS`` seconds AND
        the session is past its startup grace window.

    The fresh-quick-log / startup-grace short-circuits prevent us from
    declaring a healthy long-thinking pause or a just-spawned scan as
    hung. Without them, normal slow tool calls would trigger respawn.

    The hang-vs-stopped distinction matters because they need different
    remediation: a stopped Smith just needs respawn; a hung Smith needs
    its process killed BEFORE respawn or else the OS sees two competing
    MCP clients and dual writes start corrupting state.

    Existence-only signals (pid file, process scan) are exactly what
    mask hangs in ``_smith_running()`` — here we *want* that blindness
    because we're explicitly looking for "alive but stuck".
    """
    if _signal_quick_log_fresh() or _signal_session_recently_started():
        return None
    return _live_pid_from_pid_file() or _live_pid_from_process_scan()


def _kill_hung_smith(pid: int) -> bool:
    """SIGTERM then SIGKILL a hung Smith pid, wipe its pid-file pointers.

    Returns True iff the process is no longer alive after the kill
    attempt. Failure modes (already-gone, permission-denied) are logged
    and treated as "no longer our problem" — the next watchdog tick
    re-evaluates from scratch.

    Pid file + client file are unlinked on success so the next call to
    ``_smith_running()`` doesn't immediately re-resurrect the false
    "alive" signal off a stale pointer to the freshly-killed PID.
    """
    try:
        import psutil
        proc = psutil.Process(pid)
    except ImportError:
        _log.error("kill_hung_smith: psutil missing — cannot terminate pid=%d", pid)
        return False
    except psutil.NoSuchProcess:
        _safe_unlink(_SMITH_PID_FILE)
        _safe_unlink(_SMITH_CLIENT_FILE)
        return True
    try:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except psutil.TimeoutExpired:
            _log.warning("kill_hung_smith: pid=%d ignored SIGTERM, escalating to SIGKILL", pid)
            proc.kill()
            try:
                proc.wait(timeout=2)
            except psutil.TimeoutExpired:
                _log.error("kill_hung_smith: pid=%d survived SIGKILL", pid)
                return False
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        _log.warning("kill_hung_smith: pid=%d not killable: %s", pid, e)
        # Best-effort cleanup of pointers even on AccessDenied — if the
        # process is alive but we can't touch it, the pid file is still
        # misleading and worth clearing so detection stops false-positiving.
        _safe_unlink(_SMITH_PID_FILE)
        _safe_unlink(_SMITH_CLIENT_FILE)
        return False
    _safe_unlink(_SMITH_PID_FILE)
    _safe_unlink(_SMITH_CLIENT_FILE)
    return True


@app.get("/api/smith-status")
async def api_smith_status() -> JSONResponse:
    return JSONResponse({"running": _smith_running()})


_KNOWN_CLIENTS = ("claude", "opencode", "codex")


def _client_installed(name: str) -> bool:
    """Check whether the named client CLI is on $PATH (cross-platform).

    The older form fell back to hardcoded macOS paths (/opt/homebrew/bin and a
    literal user home), which broke on Windows and made the function lie on
    fresh systems where the user installed the CLI via npm/cargo to a
    different prefix. shutil.which() handles ``$PATHEXT`` on Windows so an
    ``opencode.cmd`` shim is detected correctly."""
    import shutil
    if name in ("claude", "opencode", "codex"):
        return bool(shutil.which(name))
    return False


def _client_process_running(name: str) -> bool:
    """Check whether any process for the given client is currently running.

    Cross-platform via psutil — replaces the older ``pgrep -f <name>`` shell
    call which only ran on Unix. Matches against the full command line so an
    opencode wrapper running as ``node /path/to/.opencode/...`` still hits."""
    try:
        import psutil
    except ImportError:
        return False
    needle = name.lower()
    try:
        for proc in psutil.process_iter(["name", "cmdline"]):
            try:
                pname = (proc.info.get("name") or "").lower()
                if needle in pname:
                    return True
                cmd = " ".join(proc.info.get("cmdline") or []).lower()
                if needle in cmd:
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except (psutil.AccessDenied, OSError):
        return False
    return False


def _resolve_client_from_session() -> str | None:
    """Resolver step 1+2: read session.json and return whichever client
    field is populated and points at an installed CLI.

    Step 1 (authoritative): ``smith_proc.client`` set at session.start() by
    caller-detection. This is THE answer when present — once a scan
    started in opencode, watchdog respawns must use opencode.

    Step 2 (legacy / back-compat): top-level ``client`` field, for older
    sessions or out-of-band operator overrides.
    """
    try:
        sd = json.loads(_SESSION_FILE.read_text())
    except (OSError, ValueError):
        return None
    smith_proc = sd.get("smith_proc") if isinstance(sd, dict) else None
    if isinstance(smith_proc, dict):
        locked = (smith_proc.get("client") or "").strip().lower()
        if locked in _KNOWN_CLIENTS and _client_installed(locked):
            return locked
    client = (sd.get("client") or "").strip().lower() if isinstance(sd, dict) else ""
    if client in _KNOWN_CLIENTS and _client_installed(client):
        return client
    return None


def _resolve_client_from_smith_client_file() -> str | None:
    """Resolver step 3: read logs/smith.client (last dashboard-managed
    spawn). Global file, can drift across scans — only useful when no
    scan-locked client is present."""
    try:
        saved = _SMITH_CLIENT_FILE.read_text().strip().lower()
    except (OSError, ValueError):
        return None
    return saved if (saved in _KNOWN_CLIENTS and _client_installed(saved)) else None


def _resolve_client_from_running_process() -> str | None:
    """Resolver step 4: scan for a live process matching a known client.

    Iterates _KNOWN_CLIENTS in priority order (claude > opencode > codex)
    so the answer is deterministic when multiple clients are open.
    """
    for name in _KNOWN_CLIENTS:
        if _client_process_running(name) and _client_installed(name):
            return name
    return None


def _detect_active_client() -> str:
    """Detect which client should be used for restart.

    Resolution chain (most authoritative first); first match wins:
      1. ``_resolve_client_from_session`` — scan-locked client or legacy
         top-level field in session.json
      2. ``_resolve_client_from_smith_client_file`` — logs/smith.client
         (global, drift-prone, used only when session.json is silent)
      3. ``_resolve_client_from_running_process`` — live process scan
      4. ``"claude"`` as final default

    Operator override: the /api/restart-smith endpoint accepts
    ``{"client": "<name>"}`` in the request body, which short-circuits
    this entire chain. Use that path when intentionally switching mid-scan.
    """
    for resolver in (
        _resolve_client_from_session,
        _resolve_client_from_smith_client_file,
        _resolve_client_from_running_process,
    ):
        client = resolver()
        if client:
            return client
    return "claude"


@app.get("/api/smith-clients")
async def api_smith_clients() -> JSONResponse:
    """Return available clients and the auto-detected active one."""
    return JSONResponse({
        "claude":   _client_installed("claude"),
        "opencode": _client_installed("opencode"),
        "codex":    _client_installed("codex"),
        "active":   _detect_active_client(),
    })


# Small lookup table for the audit-log tag that goes into session.json's
# smith_proc.source field. Replaces the chained ternary that SonarQube
# flagged as a confusing nested conditional (python:S3358). Adding a new
# spawn source = one entry here.
_SPAWN_SOURCE_TAGS = {
    "watchdog": "watchdog_spawn",
    "api":      "dashboard_spawn",
}


def _spawn_source_tag(source: str) -> str:
    """Map a _spawn_smith() source argument to its audit-log tag."""
    return _SPAWN_SOURCE_TAGS.get(source, f"spawn_{source}")


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
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, lambda: log_path.parent.mkdir(parents=True, exist_ok=True))
        audit_line = f"\n=== [{source}] spawning {client} at {loop.time()} ===\n"
        await loop.run_in_executor(None, lambda: log_path.open("a").write(audit_line))

        import shutil
        binary = shutil.which(client)
        if not binary:
            return False, f"{client} binary not found on PATH"
        if client == "claude":
            args = [binary, "--dangerously-skip-permissions", "-p", prompt]
        else:
            # opencode: detached background spawn has no controlling TTY, so any
            # permission prompt either hangs forever (waiting on closed stdin)
            # or exits because no TTY is available. --dangerously-skip-permissions
            # auto-approves prompts that aren't explicitly denied in opencode.json's
            # `permission.deny` block. Mirrors how the claude branch above handles
            # the same constraint. To keep the safety net, users should add
            # destructive-command denials to ~/.config/opencode/opencode.json —
            # the installer recommends a starter set.
            args = [binary, "run", "--dangerously-skip-permissions", prompt]

        log_fh = await loop.run_in_executor(None, lambda: log_path.open("a"))

        # Detach the child so signals to the dashboard process don't reach it.
        # POSIX uses os.setsid() via start_new_session; Windows uses the
        # CREATE_NEW_PROCESS_GROUP creationflag. Same intent, different API.
        spawn_kwargs: dict = {
            "stdout": log_fh,
            "stderr": log_fh,
            "cwd": str(_REPO_ROOT),
        }
        import sys as _sys
        if _sys.platform == "win32":
            # subprocess.CREATE_NEW_PROCESS_GROUP is only defined on Windows
            # builds of CPython. The literal value is the documented Win32
            # CREATE_NEW_PROCESS_GROUP creation flag (0x00000200), used as a
            # fallback so cross-platform tests that force sys.platform="win32"
            # still resolve to the expected integer.
            import subprocess as _subprocess
            spawn_kwargs["creationflags"] = getattr(
                _subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200
            )
        else:
            spawn_kwargs["start_new_session"] = True

        proc = await asyncio.create_subprocess_exec(*args, **spawn_kwargs)
        _SMITH_PID_FILE.write_text(str(proc.pid))
        _SMITH_CLIENT_FILE.write_text(client)

        # Scan-lock the chosen client into session.json so subsequent
        # watchdog restarts can't drift to a different CLI. This is the
        # other half of the fix: _detect_active_client() reads
        # smith_proc.client first, and _spawn_smith() guarantees it's
        # always populated after a successful spawn. Source distinguishes
        # dashboard restarts from auto-restarts so a later audit is clear.
        try:
            from core import session as scan_session
            scan_session.set_smith_proc(
                pid=proc.pid,
                client=client,
                source=_spawn_source_tag(source),
            )
        except Exception as e:
            # Never break the spawn path on a session-update failure —
            # the file-based smith.client write above is the operational
            # backup. Just note it for diagnostics.
            _log.debug("spawn_smith: scan-lock write failed: %s", e)

        return True, proc.pid
    except Exception:
        _log.exception("spawn_smith failed")
        return False, "spawn failed"


def _mcp_sse_alive() -> bool:
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
    except OSError as e:
        _log.debug("mcp_sse_alive check failed: %s", e)
        return False


async def _watchdog_tick(now: float) -> None:
    """Single watchdog tick: restart Smith if all guard conditions pass.

    Fires out-of-band notifications (Telegram/Slack/Discord) at three
    decision points so the operator sees stuck-scan states even when
    they're not watching the dashboard. Each notification has its own
    dedup code so the 30-min BaseNotifier cooldown prevents spam — one
    alert per condition per window, not one per watchdog tick.
    """
    global _watchdog_last_restart_ts
    session_data = _read_json(_SESSION_FILE)
    if session_data.get("status") != "running":
        return
    if (session_data.get("intervention") or {}).get("code"):
        return

    # Hung-process detection runs BEFORE the _smith_running() early-return.
    # A hung opencode/claude keeps _signal_pid_file_alive() and
    # _signal_process_scan_finds_client() returning True (process exists)
    # while quick_log goes stale (no MCP activity). _smith_running() OR's
    # all four signals, so it stays True for a hung process and the old
    # `if _smith_running(): return` masked the hang indefinitely. By
    # checking hang FIRST, we kill the zombie + let the rest of the tick
    # respawn via the normal _spawn_smith() path.
    hung_pid = _smith_hung_pid()
    if hung_pid is not None:
        _log.warning(
            "watchdog: detected hung Smith pid=%d (no MCP heartbeat in %ds) — killing",
            hung_pid, _SMITH_IDLE_SECONDS,
        )
        try:
            from core import notifiers as _nfr
            _nfr.notify(
                title="Smith hung — process alive but no progress",
                body=(
                    f"Watchdog detected pid {hung_pid} is still alive but "
                    f"hasn't made an MCP tool call in "
                    f"{_SMITH_IDLE_SECONDS // 60} min. Killing it and "
                    "attempting respawn. Check the dashboard if the scan "
                    "stays stuck after respawn."
                ),
                urgency="high",
                code="WATCHDOG_SMITH_HUNG",
            )
        except Exception:
            pass
        _kill_hung_smith(hung_pid)
        # Fall through into the spawn flow — do NOT return early.
    elif _smith_running():
        return
    # Smith is stopped (or just killed) while the scan is still running — that's
    # the condition the operator wants to know about. Fire BEFORE the MCP /
    # cap / gap guards so we don't go silent on the most actionable case.
    # Note: for hung→killed, the dedup key WATCHDOG_SMITH_STOPPED is
    # distinct from WATCHDOG_SMITH_HUNG (fired above), so both alerts land
    # for a hang event — operator sees "hung, killing" then "stopped,
    # restarting" within the same tick.
    try:
        from core import notifiers as _nfr
        _nfr.notify(
            title="Smith stopped while scan running",
            body=(
                "Watchdog detected Smith exited with the scan still "
                "marked running. Auto-restart will fire if MCP is alive "
                "and the per-hour cap allows. Check the dashboard if "
                "the scan stays stuck."
            ),
            urgency="high",
            code="WATCHDOG_SMITH_STOPPED",
        )
    except Exception:
        # Notifier failures must never break the watchdog loop.
        pass
    if not _mcp_sse_alive():
        _log.warning("watchdog suppressed: MCP SSE server unreachable on 127.0.0.1:7778")
        try:
            from core import notifiers as _nfr
            _nfr.notify(
                title="MCP SSE server unreachable",
                body=(
                    "Watchdog can't restart Smith because the MCP server "
                    "on 127.0.0.1:7778 isn't responding. Restart it with "
                    "`./installers/start-mcp-server.sh start`."
                ),
                urgency="high",
                code="WATCHDOG_MCP_DOWN",
            )
        except Exception:
            pass
        return
    if now - _watchdog_last_restart_ts < _WATCHDOG_MIN_GAP_SECONDS:
        return
    _watchdog_restart_count_window[:] = [
        t for t in _watchdog_restart_count_window if now - t < 3600
    ]
    if len(_watchdog_restart_count_window) >= _WATCHDOG_MAX_PER_HOUR:
        _log.warning(
            "watchdog suppressed: %d restarts in last hour exceeds cap %d",
            len(_watchdog_restart_count_window), _WATCHDOG_MAX_PER_HOUR,
        )
        try:
            from core import notifiers as _nfr
            _nfr.notify(
                title="Smith respawn cap reached",
                body=(
                    f"Watchdog gave up after {len(_watchdog_restart_count_window)} "
                    f"restarts in the last hour (cap {_WATCHDOG_MAX_PER_HOUR}). "
                    "Scan is stuck — please intervene from the dashboard."
                ),
                urgency="high",
                code="WATCHDOG_RESPAWN_CAP",
            )
        except Exception:
            pass
        return
    client = _detect_active_client()
    _log.info("watchdog: smith stopped while scan running — auto-restart")
    ok, result = await _spawn_smith(client, source="watchdog")
    if ok:
        _watchdog_last_restart_ts = now
        _watchdog_restart_count_window.append(now)
        # S5145 defense: result on success is a kernel-assigned PID (int).
        # Force %d formatting so a malformed string return path can't reach
        # the log line — int() would raise, and the resulting LogRecord
        # carries only a sanitized integer, never user-controlled bytes.
        _log.info("watchdog: spawned pid=%d", int(result) if isinstance(result, int) else 0)


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
    import time as _time
    while True:
        try:
            await asyncio.sleep(_WATCHDOG_POLL_SECONDS)
            await _watchdog_tick(_time.time())
        except asyncio.CancelledError:
            raise
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
    if client not in _KNOWN_CLIENTS:
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


def _read_pid() -> tuple[int | None, float | None]:
    """Return (pid, api_server_mtime_at_launch) from the PID file."""
    try:
        parts = _PID_FILE.read_text().strip().split(":", 1)
        pid = int(parts[0])
        mtime = float(parts[1]) if len(parts) > 1 else None
        return pid, mtime
    except Exception:
        return None, None


def _write_pid(pid: int) -> None:
    mtime = Path(__file__).stat().st_mtime
    _PID_FILE.write_text(f"{pid}:{mtime:.6f}")


def _pid_alive(pid: int) -> bool:
    """Cross-platform PID liveness check via psutil.pid_exists.

    The older ``os.kill(pid, 0)`` form was POSIX-only — on Windows it raises
    ``OSError: WinError 87`` (invalid parameter) for valid PIDs because the
    NT kernel doesn't model signal 0 the way POSIX does."""
    try:
        import psutil
        return bool(psutil.pid_exists(pid))
    except (ImportError, OSError):
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
    Restarts automatically if api_server.py has been modified since launch.
    """
    import signal

    current_mtime = Path(__file__).stat().st_mtime

    # Check PID file first — survives MCP server restarts
    saved_pid, saved_mtime = _read_pid()
    code_unchanged = saved_mtime is not None and abs(current_mtime - saved_mtime) < 1.0
    if saved_pid and _pid_alive(saved_pid) and _port_healthy(port) and code_unchanged:
        return f"http://localhost:{port}"

    # Old process died, code changed, or never existed — kill stale process if running
    if saved_pid and _pid_alive(saved_pid):
        # psutil.Process.terminate() abstracts SIGTERM (POSIX) vs
        # TerminateProcess (Windows). Older form was os.kill(SIGTERM)
        # which Windows doesn't support for foreign processes.
        try:
            import psutil
            psutil.Process(saved_pid).terminate()
            await asyncio.sleep(0.3)
        except (psutil.NoSuchProcess, psutil.AccessDenied, ImportError, OSError):
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
