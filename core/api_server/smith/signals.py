"""
Smith liveness signals: the cheap "is a Smith alive?" probes.

Each ``_signal_*`` helper is one independent piece of evidence combined by
``_smith_running``; the ``_live_pid_*`` helpers locate a concrete pid. Sibling
smith functions are reached through the package object (``_smith.<name>``) so a
patch on ``core.api_server.smith.<name>`` is observed exactly as in the old
single module; parent-owned paths/config stay on ``_api.<name>``.
"""
from __future__ import annotations

import core.api_server as _api
import core.api_server.smith as _smith
from core.client_patterns import looks_like_smith

from ._common import _log, _SMITH_IDLE_SECONDS


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
            if _smith._process_matches_smith(proc):
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
    return looks_like_smith(cmd)


def _smith_running() -> bool:
    """Return True if a Smith (claude/opencode/codex) is actively driving the scan.

    Live-process / startup signals — any one means running:
      1. ``_signal_pid_file_alive``            — the tracked dashboard-spawn PID is alive
      2. ``_signal_process_scan_finds_client`` — a live opencode/claude/codex process matches
      3. ``_signal_session_recently_started``  — startup grace (scan started < 2 h ago, no heartbeat)

    Then the heartbeat, but GATED so it doesn't cause the laggy Phase-C pickup:
      - If we were tracking a spawn PID and it is now DEAD, the tracked Smith cleanly EXITED →
        return False so the watchdog respawns promptly (don't wait out the 5-min idle window). This
        is the dashboard-spawned / cloud-Claude path.
      - Otherwise (no tracked PID — e.g. a local model whose process the needle can't match) fall
        back to ``_signal_quick_log_fresh`` so **thinking-mode pauses (2-3 min between tool calls in
        Phase A/B) are still tolerated** and we don't spuriously respawn a working Smith.
    """
    if (_smith._signal_pid_file_alive()
            or _smith._signal_process_scan_finds_client()
            or _smith._signal_session_recently_started()):
        return True
    if _tracked_pid_is_dead():          # tracked spawn confirmed exited → snappy respawn
        return False
    return _smith._signal_quick_log_fresh()   # untracked → heartbeat tolerates thinking pauses


def _tracked_pid_is_dead() -> bool:
    """True iff smith.pid EXISTS and points to a valid-but-DEAD pid — i.e. a spawn we were
    tracking has cleanly exited. False when there's no pid file / an unparseable one (untracked:
    e.g. a manually-launched or local-model Smith whose process the needle can't match) so the
    caller falls back to the softer heartbeat signal instead of respawning over a thinking pause.
    """
    try:
        import psutil
        pid = int(_api._SMITH_PID_FILE.read_text().strip())
    except (FileNotFoundError, ValueError, PermissionError, ImportError):
        return False
    if not (0 < pid < (1 << 22)):
        return False
    try:
        return not psutil.pid_exists(pid)
    except OSError:
        return False


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
            if _smith._process_matches_smith(proc):
                try:
                    return int(proc.info.get("pid") or proc.pid)
                except (ValueError, TypeError, AttributeError):
                    continue
    except (ImportError, OSError):
        return None
    except Exception as e:  # psutil.AccessDenied at iter-time
        _log.debug("process scan for hung pid failed: %s", e)
    return None


def _quick_log_age_seconds() -> float | None:
    """Seconds since the last MCP heartbeat (quick_log mtime), or None if absent."""
    import time
    try:
        if not _api._QUICK_LOG_FILE.exists():
            return None
        return time.time() - _api._QUICK_LOG_FILE.stat().st_mtime
    except OSError as e:
        _log.debug("quick_log age check failed: %s", e)
        return None


def _is_loopback(ip: str) -> bool:
    return ip.startswith("127.") or ip in ("::1", "localhost", "0.0.0.0")
