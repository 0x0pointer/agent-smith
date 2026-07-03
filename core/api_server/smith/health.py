"""
Hung / stalled / exited Smith detection and the kill primitive.

Distinguishes the three failure shapes the watchdog must treat differently:
alive-but-stuck (hung), alive-but-loop-exited (stalled), and cleanly-gone
(exited). Sibling signal helpers are reached through the package object
(``_smith.<name>``) so patches on ``core.api_server.smith.<name>`` are observed;
pid lookups and paths stay on the parent (``_api.<name>``).
"""
from __future__ import annotations

import core.api_server as _api
import core.api_server.smith as _smith

from ._common import _log, _SMITH_STALL_SECONDS


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
    if _smith._signal_quick_log_fresh() or _smith._signal_session_recently_started():
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


def _smith_generating(pid: int) -> bool:
    """True if the Smith process holds a live connection to a REMOTE endpoint —
    i.e. it's actively talking to the model (mid-generation), not stalled.

    Smith's only non-loopback connection is to the LLM endpoint (the MCP server
    it talks to is loopback; the scan target is reached by the MCP server, not
    by Smith). So a live remote connection means "generating, leave it alone".
    A loop that has exited has closed that connection. On any error we cannot
    rule out generation, so we return True (fail-safe: never stall-kill what
    might be a slow generation).
    """
    try:
        import psutil
        proc = psutil.Process(pid)
        for c in proc.net_connections(kind="inet"):
            if c.status == "ESTABLISHED" and c.raddr and not _smith._is_loopback(c.raddr.ip):
                return True
        return False
    except Exception as e:  # psutil missing / AccessDenied / NoSuchProcess / OSError
        _log.debug("smith_generating check for pid=%d inconclusive (%s) — assuming generating", pid, e)
        return True


def _scan_has_pending_cells() -> bool:
    """True if the coverage matrix still has untested (pending/in_progress) cells.

    Gates the fast stall-respawn to scans with real testing work left — a scan
    whose cells are all addressed but isn't formally completed is left for the
    operator / the 30-min fallback, not auto-respawned in a loop.
    """
    import json as _json
    try:
        cov = _json.loads(_api._COVERAGE_FILE.read_text())
    except (OSError, ValueError):
        return False
    return any(c.get("status") in ("pending", "in_progress") for c in cov.get("matrix", []))


def _smith_stalled_pid() -> int | None:
    """Return the live Smith pid if its agent loop has clearly EXITED mid-scan.

    Distinct from _smith_hung_pid (the blunt 30-min timer): a clean loop-exit
    leaves the process alive but idle and NOT generating, so we catch it in
    minutes without false-killing a slow generation. Fires only when ALL hold:
      • not within the startup grace window,
      • no MCP heartbeat for > _SMITH_STALL_SECONDS,
      • a live Smith pid exists,
      • that process is NOT generating (no live model connection), and
      • the coverage matrix still has pending cells (scan isn't done).
    """
    if _smith._signal_session_recently_started():
        return None
    age = _smith._quick_log_age_seconds()
    if age is None or age < _SMITH_STALL_SECONDS:
        return None
    pid = _api._live_pid_from_pid_file() or _api._live_pid_from_process_scan()
    if pid is None:
        return None
    if _smith._smith_generating(pid):
        return None
    if not _smith._scan_has_pending_cells():
        return None
    return pid


def _smith_exited() -> bool:
    """True if the Smith agent process has cleanly EXITED mid-scan — gone, no pid.

    The counterpart to _smith_stalled_pid (alive-but-idle). ``opencode run`` is
    one-shot, so its most common death is a clean exit that leaves NO process —
    and both _smith_hung_pid and _smith_stalled_pid require a *live* pid, so they
    are blind to it. Without this path a gone process is masked by
    _signal_quick_log_fresh() for the full _SMITH_IDLE_SECONDS (30 min) before the
    watchdog respawns, leaving the scan dead for half an hour (observed: opencode
    exited 23:07, watchdog only respawned ~23:41).

    Fires only when ALL hold (mirrors the stall detector, inverted on pid):
      • not within the startup grace window,
      • no MCP heartbeat for > _SMITH_STALL_SECONDS (not a brief between-turn gap),
      • NO live Smith pid exists — pid file dead AND no matching process (truly gone),
      • the coverage matrix still has pending cells (scan isn't done).
    Returns a bool, not a pid: there is nothing to kill, so the watchdog falls
    straight through to the respawn flow.
    """
    if _smith._signal_session_recently_started():
        return False
    age = _smith._quick_log_age_seconds()
    if age is None or age < _SMITH_STALL_SECONDS:
        return False
    if _api._live_pid_from_pid_file() is not None or _api._live_pid_from_process_scan() is not None:
        return False  # a live process exists — the hung/stalled paths own that case
    return _smith._scan_has_pending_cells()
