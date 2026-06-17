"""
Smith process supervision.

Detects whether a Smith (claude / opencode / codex) is alive, distinguishes a
hung process from a stopped one, resolves which client to (re)spawn, performs
the spawn, and runs the auto-restart watchdog.

These functions call each other — and read the watchdog state/config globals
— through ``core.api_server`` (the ``_api`` alias) rather than as locals, so
the dashboard's tests can patch any one of them (e.g. ``_smith_running``,
``_spawn_smith``) and have the patch observed by every caller.
"""
from __future__ import annotations

import asyncio
import json
import logging

import core.api_server as _api

_log = logging.getLogger(__name__)

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
        pid = int(_api._SMITH_PID_FILE.read_text().strip())
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
        if not _api._QUICK_LOG_FILE.exists():
            return False
        age = time.time() - _api._QUICK_LOG_FILE.stat().st_mtime
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
    if _api._QUICK_LOG_FILE.exists():
        return False
    try:
        import json as _json
        from datetime import datetime as _dt, timezone as _tz
        sd = _json.loads(_api._SESSION_FILE.read_text())
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
        pid = int(_api._SMITH_PID_FILE.read_text().strip())
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
    return _api._live_pid_from_pid_file() or _api._live_pid_from_process_scan()


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
        _api._safe_unlink(_api._SMITH_PID_FILE)
        _api._safe_unlink(_api._SMITH_CLIENT_FILE)
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
        _api._safe_unlink(_api._SMITH_PID_FILE)
        _api._safe_unlink(_api._SMITH_CLIENT_FILE)
        return False
    _api._safe_unlink(_api._SMITH_PID_FILE)
    _api._safe_unlink(_api._SMITH_CLIENT_FILE)
    return True


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
        sd = json.loads(_api._SESSION_FILE.read_text())
    except (OSError, ValueError):
        return None
    smith_proc = sd.get("smith_proc") if isinstance(sd, dict) else None
    if isinstance(smith_proc, dict):
        locked = (smith_proc.get("client") or "").strip().lower()
        if locked in _KNOWN_CLIENTS and _api._client_installed(locked):
            return locked
    client = (sd.get("client") or "").strip().lower() if isinstance(sd, dict) else ""
    if client in _KNOWN_CLIENTS and _api._client_installed(client):
        return client
    return None


def _resolve_client_from_smith_client_file() -> str | None:
    """Resolver step 3: read logs/smith.client (last dashboard-managed
    spawn). Global file, can drift across scans — only useful when no
    scan-locked client is present."""
    try:
        saved = _api._SMITH_CLIENT_FILE.read_text().strip().lower()
    except (OSError, ValueError):
        return None
    return saved if (saved in _KNOWN_CLIENTS and _api._client_installed(saved)) else None


def _resolve_client_from_running_process() -> str | None:
    """Resolver step 4: scan for a live process matching a known client.

    Iterates _KNOWN_CLIENTS in priority order (claude > opencode > codex)
    so the answer is deterministic when multiple clients are open.
    """
    for name in _KNOWN_CLIENTS:
        if _api._client_process_running(name) and _api._client_installed(name):
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
        _terminal = {"complete", "incomplete_with_unresolved_blockers", "limit_reached"}
        if current.get("status") in _terminal:
            return (
                False,
                f"Cannot restart: scan is already in terminal state '{current.get('status')}'. Start a new scan instead.",
            )
        if current.get("status") == "intervention_required":
            scan_session.resolve_intervention(
                "CONTINUE",
                f"Smith restarted (source={source})",
            )
        # Clear QA alerts so Smith's first tool call doesn't immediately re-trigger
        # the same HIR that caused the intervention. The QA daemon re-evaluates every
        # 120 s and will re-fire any persistent issues on the next cycle.
        try:
            from core import paths as _paths, store as _store
            import json as _json
            _qa_file = _paths.QA_STATE_FILE
            if _qa_file.exists():
                _qa = _json.loads(_qa_file.read_text())
                _qa["alerts"] = []
                _store.save(_qa_file, _qa, indent=None)
        except Exception as _e:
            _log.debug("spawn_smith: qa_state clear failed: %s", _e)

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

        log_path = _api._REPO_ROOT / "logs" / "smith_restart.log"
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
            "cwd": str(_api._REPO_ROOT),
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
        _api._SMITH_PID_FILE.write_text(str(proc.pid))
        _api._SMITH_CLIENT_FILE.write_text(client)

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


# Throttle so a daemon that refuses to come up doesn't get hammered every tick.
_mcp_sse_last_restart_ts: float = 0.0
_MCP_SSE_RESTART_MIN_GAP_SECONDS = 30


async def _ensure_mcp_sse_alive(now: float) -> None:
    """Cross-platform self-heal for the MCP SSE daemon (port 7778).

    The MCP server is a bare uvicorn process with no reliable OS supervisor on
    most setups: a launchd KeepAlive agent silently fails when the repo lives in
    a TCC-protected folder (~/Desktop, ~/Documents, ...), and there's nothing at
    all on a fresh Linux/Windows box. When that process dies, every
    session()/scan()/report() call fails with "Unable to connect" until someone
    restarts it by hand — the recurring breakage.

    The always-on dashboard process is the natural supervisor: it inherits the
    operator's permissions (so it can actually restart the daemon) and is the
    same process the operator is already watching. This runs on every watchdog
    tick, independent of scan status, so MCP is back before the next scan starts.
    OS-agnostic: bash launcher on POSIX, PowerShell launcher on Windows.
    """
    global _mcp_sse_last_restart_ts
    if _mcp_sse_alive():
        return
    if now - _mcp_sse_last_restart_ts < _MCP_SSE_RESTART_MIN_GAP_SECONDS:
        return
    _mcp_sse_last_restart_ts = now

    import os
    if os.name == "nt":
        launcher = _api._REPO_ROOT / "installers" / "start-mcp-server.ps1"
        cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(launcher), "start"]
    else:
        launcher = _api._REPO_ROOT / "installers" / "start-mcp-server.sh"
        cmd = ["/bin/bash", str(launcher), "start"]
    if not launcher.exists():
        _log.warning("MCP SSE down but launcher missing: %s", launcher)
        return

    _log.warning("MCP SSE server down on 127.0.0.1:7778 — auto-restarting via %s", launcher.name)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.wait(), timeout=30)
    except asyncio.TimeoutError:
        _log.warning("MCP SSE auto-restart still coming up after 30s")
    except Exception:
        _log.exception("MCP SSE auto-restart failed")
        return
    if _mcp_sse_alive():
        _log.info("MCP SSE server auto-restarted OK")
        try:
            from core import notifiers as _nfr
            _nfr.notify(
                title="MCP SSE server auto-restarted",
                body=(
                    "The MCP server on 127.0.0.1:7778 had died and the dashboard "
                    "watchdog brought it back automatically — no manual restart needed."
                ),
                urgency="normal",
                code="WATCHDOG_MCP_REVIVED",
            )
        except Exception:
            pass


async def _watchdog_tick(now: float) -> None:
    """Single watchdog tick: restart Smith if all guard conditions pass.

    Fires out-of-band notifications (Telegram/Slack/Discord) at three
    decision points so the operator sees stuck-scan states even when
    they're not watching the dashboard. Each notification has its own
    dedup code so the 30-min BaseNotifier cooldown prevents spam — one
    alert per condition per window, not one per watchdog tick.
    """
    session_data = _api._read_json(_api._SESSION_FILE)
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
    hung_pid = _api._smith_hung_pid()
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
        _api._kill_hung_smith(hung_pid)
        # Fall through into the spawn flow — do NOT return early.
    elif _api._smith_running():
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
    if not _api._mcp_sse_alive():
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
    if now - _api._watchdog_last_restart_ts < _api._WATCHDOG_MIN_GAP_SECONDS:
        return
    _api._watchdog_restart_count_window[:] = [
        t for t in _api._watchdog_restart_count_window if now - t < 3600
    ]
    if len(_api._watchdog_restart_count_window) >= _api._WATCHDOG_MAX_PER_HOUR:
        _log.warning(
            "watchdog suppressed: %d restarts in last hour exceeds cap %d",
            len(_api._watchdog_restart_count_window), _api._WATCHDOG_MAX_PER_HOUR,
        )
        try:
            from core import notifiers as _nfr
            _nfr.notify(
                title="Smith respawn cap reached",
                body=(
                    f"Watchdog gave up after {len(_api._watchdog_restart_count_window)} "
                    f"restarts in the last hour (cap {_api._WATCHDOG_MAX_PER_HOUR}). "
                    "Scan is stuck — please intervene from the dashboard."
                ),
                urgency="high",
                code="WATCHDOG_RESPAWN_CAP",
            )
        except Exception:
            pass
        return
    client = _api._detect_active_client()
    _log.info("watchdog: smith stopped while scan running — auto-restart")
    ok, result = await _api._spawn_smith(client, source="watchdog")
    if ok:
        _api._watchdog_last_restart_ts = now
        _api._watchdog_restart_count_window.append(now)
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
            await asyncio.sleep(_api._WATCHDOG_POLL_SECONDS)
            # Keep the MCP SSE daemon alive FIRST, every tick, regardless of
            # scan status — _watchdog_tick early-returns when no scan is running,
            # but the operator still needs MCP up to start the next one.
            await _api._ensure_mcp_sse_alive(_time.time())
            await _api._watchdog_tick(_time.time())
        except asyncio.CancelledError:
            raise
        except Exception:
            _log.exception("watchdog loop error (continuing)")
