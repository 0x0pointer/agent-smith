"""
Session persistence + cross-process reconciliation
===================================================
The on-disk ``session.json`` writer (`_flush`), the cross-process state
reconciler (`_reconcile_if_external_write`), the lazy stale-PID refresher
(`_refresh_smith_pid_if_stale`), and the `smith_proc` scan-lock helpers
(`set_smith_proc`, `get_scan_client`).

The mutable state these mutate/rebind — ``_current``, ``_SESSION_FILE``,
``_REPO_ROOT``, ``_last_local_write_mtime``, ``_last_pid_refresh_attempt`` —
lives in the ``core.session`` package namespace so the suite can patch it as
``core.session.NAME``. This module reaches it via ``import core.session as
_sess`` and reads/rebinds ``_sess.<name>`` at call time (never at import
time), which keeps the package importable without a cycle and keeps every
name patchable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import core.session as _sess
from core import store as _store


def set_smith_proc(pid: int, client: str, source: str) -> None:
    """Scan-lock the driving Smith client into session.json's `smith_proc` field.

    This is the authoritative answer to "which CLI is driving THIS scan?". The
    watchdog reads it before falling back to logs/smith.client (which is a
    global file shared across scans and prone to drift between sessions).

    Called from:
      • core.session.start() — via _detect_smith_caller() at scan start.
      • core.api_server._spawn_smith() — every time the dashboard or the
        watchdog spawns a Smith, locks the client choice into the scan.

    `client` should be one of "claude" | "opencode" | "codex". `source`
    documents what wrote it ("interactive_mcp", "dashboard_spawn",
    "watchdog_spawn", "api_restart") so a later audit can see why the
    current pin exists. Idempotent and safe to call repeatedly.
    """
    _sess._reconcile_if_external_write()
    if not _sess._current:
        return
    _sess._current["smith_proc"] = {
        "pid":          int(pid),
        "client":       str(client),
        "source":       str(source),
        "captured_at":  datetime.now(timezone.utc).isoformat(),
    }
    _sess._flush()


def get_scan_client() -> str | None:
    """Return the scan-locked Smith client, or None if not yet set.

    Read-only inspection helper for the watchdog. Does not reconcile —
    callers wanting freshest state should reload first."""
    if not _sess._current:
        return None
    sp = _sess._current.get("smith_proc")
    if isinstance(sp, dict):
        c = sp.get("client")
        if isinstance(c, str) and c in ("claude", "opencode", "codex"):
            return c
    return None


def _flush() -> None:
    if _sess._current:
        _store.save(_sess._SESSION_FILE, _sess._current)
        try:
            _sess._last_local_write_mtime = _sess._SESSION_FILE.stat().st_mtime
        except OSError:
            # Hold the previous mtime; reconcile will conservatively reload
            # the next time it's called.
            pass


def _reconcile_if_external_write() -> None:
    """Reload `_current` from disk if another process wrote to session.json
    since our last local flush, and lazily refresh logs/smith.pid when the
    tracked PID has died.

    Called by every mutation in this module before checking state. Two
    correctness benefits:

      1. Cross-process state desync — dashboard process and MCP server each
         keep their own ``_current``; a stale flush in one can silently undo
         the other's write. Reconciling against disk first eliminates the
         hot case (operator clicks Complete Scan, next MCP mutation is about
         to overwrite it).
      2. Stale smith.pid tracking — the dashboard's _smith_running() check
         consults logs/smith.pid first; if that file points at a dead PID
         (e.g., the original Smith died and a new one took over outside the
         dashboard restart path), the check fails and the watchdog fires a
         false "Smith stopped" alert. Re-detecting the caller on the fly
         keeps the pointer fresh without operator intervention.
    """
    # Disk-state reconcile (cross-process write protection).
    #
    # Three on-disk cases we need to handle distinctly:
    #   (a) file exists and mtime is newer → another process wrote it,
    #       reload _current.
    #   (b) file exists and mtime matches our last flush → no-op.
    #   (c) file does NOT exist → another process *deleted* it
    #       (dashboard's Clear All path). The previous version's bare
    #       `except OSError: return` left _current stale, so an MCP
    #       process's next session.get() returned the pre-Clear state
    #       and blocked the new scan with a phantom "intervention_required"
    #       from the prior HIR. Treat deletion as "session reset" and
    #       drop the in-memory cache to None to match disk reality.
    try:
        disk_mtime = _sess._SESSION_FILE.stat().st_mtime
    except FileNotFoundError:
        # Case (c) — disk was wiped. Only treat this as a deletion (and
        # drop the in-memory cache) when we have evidence the file
        # actually existed at some point: a non-zero
        # _last_local_write_mtime means THIS process flushed something
        # at least once, so an absent file = external deletion (Clear
        # All from the dashboard). When _last_local_write_mtime is 0,
        # the file may simply have never existed (fresh process startup,
        # or tests that stub _current via monkeypatch without flushing)
        # — leaving _current alone is the safer default.
        if _sess._last_local_write_mtime > 0 and _sess._current is not None:
            _sess._current = None
        _sess._refresh_smith_pid_if_stale()
        return
    except OSError:
        # Permission / IO error — leave cache alone (better stale than
        # a noisy False positive from a transient stat failure).
        return
    # Small fudge: filesystem mtime granularity varies (APFS is sub-µs but
    # some Linux mounts are 1s). A tolerance of 1ms catches genuine external
    # writes without false-positiving on same-process re-flushes within the
    # same syscall window.
    if disk_mtime > _sess._last_local_write_mtime + 0.001:
        try:
            fresh = json.loads(_sess._SESSION_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pass
        else:
            _sess._current = fresh

    # Stale-PID refresh (rate-limited)
    _sess._refresh_smith_pid_if_stale()


def _refresh_smith_pid_if_stale() -> None:
    """If logs/smith.pid points at a dead process, try to detect a live caller
    and rewrite the file. Rate-limited so high-frequency mutations don't pay
    for psutil scanning on every call.

    Returns silently on any error — this is a best-effort liveness refresh,
    not a correctness invariant. Worst case: stale PID stays stale and the
    watchdog's process-scan fallback signal does the job instead.
    """
    try:
        now = datetime.now(timezone.utc).timestamp()
    except OSError:
        return
    if now - _sess._last_pid_refresh_attempt < _sess._PID_REFRESH_MIN_INTERVAL_SECONDS:
        return
    _sess._last_pid_refresh_attempt = now

    pid_file = _sess._REPO_ROOT / "logs" / "smith.pid"
    try:
        raw = pid_file.read_text().strip()
        pid = int(raw)
    except (ValueError, OSError):
        # FileNotFoundError is a subclass of OSError — listing both is
        # redundant (sonar S5713). OSError alone covers the missing-file,
        # permission-denied, and other read-failure cases.
        # No tracked PID at all → detection probably never fired. Try now.
        caller = _sess._detect_smith_caller()
        if caller:
            _sess._persist_smith_caller(caller)
        return

    try:
        import psutil
        if 0 < pid < (1 << 22) and psutil.pid_exists(pid):
            return  # tracked PID is still alive; nothing to do
    except ImportError:
        return

    # Tracked PID is dead. Find a live caller and replace the file.
    caller = _sess._detect_smith_caller()
    if caller and caller["pid"] != pid:
        _sess._persist_smith_caller(caller)
