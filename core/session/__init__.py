"""
Scan session
============
Defines the target, scope, depth, and hard limits for a pentest run.
A scan ends when Claude calls complete_scan() OR when any hard limit is hit —
whichever comes first.

Depth presets
-------------
  recon    — port scan + subdomains + HTTP probe only
             fast, low-noise, safe to run on most targets
             default limits: $0.10  |  15 min  |  10 tool calls

  standard — recon + nuclei vuln scan + directory fuzzing
             catches the most common issues without being too loud
             default limits: $0.50  |  45 min  |  25 tool calls

  thorough — standard + full Kali toolchain (nikto, sqlmap, testssl, …)
             comprehensive but noisy — confirm authorisation first
             default limits: $100.00  |  8 hours  |  unlimited tool calls

Hard limit enforcement
----------------------
Call check_limits(cost_summary) before running any tool.
Returns a stop-message string when a limit is exceeded; None otherwise.
The stop message is returned directly to Claude as the tool result, which
causes it to stop invoking further tools and write the final report.

Output file
-----------
  session.json  (served by core/api_server at GET /api/session)

Layout
------
The implementation is split across focused submodules; import from
``core.session`` exactly as before — every name is re-exported here.

  __init__        this file — state (_current), presets, lifecycle, hard-limit
                  enforcement, intervention (HIR), context pressure, persistence
                  + cross-process reconciliation, and the facade
  process_detect  Smith caller detection (_detect_smith_caller + helpers)
  gates           gate tracking + skill/step/tools-called bookkeeping
  assets          known-assets vault, tool-invocation log, spider-failure gate

The mutable ``_current`` cache, paths, and _TRIGGER_MAP live here in the package
namespace so they stay patchable as ``core.session.NAME`` (the suite patches
_SESSION_FILE, _current, _REPO_ROOT, _last_local_write_mtime, _detect_smith_caller).
The submodules read them back via ``import core.session as _sess`` — they only
read + mutate ``_current`` in place; rebinding it (start/complete/load/reconcile)
happens here, so those keep the native ``global _current``.
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from core import cost as cost_tracker

# ── Depth presets ─────────────────────────────────────────────────────────────

PRESETS: dict[str, dict] = {
    "recon": {
        "label":       "Recon only",
        "description": "Port scan · subdomain enum · HTTP probe — no active exploitation",
        "max_cost_usd":     0.10,
        "max_time_minutes": 15,
        "max_tool_calls":   10,
    },
    "standard": {
        "label":       "Standard",
        "description": "Recon + nuclei vulnerability scan + directory fuzzing",
        "max_cost_usd":     0.50,
        "max_time_minutes": 45,
        "max_tool_calls":   25,
    },
    "thorough": {
        "label":       "Thorough",
        "description": "Standard + full Kali toolchain — runs until complete (no cost/time cap)",
        "max_cost_usd":     None,
        "max_time_minutes": None,
        "max_tool_calls":   0,
    },
}

# __file__ is core/session/__init__.py → three parents up is the repo root.
_REPO_ROOT = Path(__file__).parent.parent.parent
_SESSION_FILE = _REPO_ROOT / "session.json"


# ── In-memory state ───────────────────────────────────────────────────────────

_current: dict | None = None


# ── Endpoint-type trigger gates ───────────────────────────────────────────────
# When an endpoint is registered with a recognised type tag, a mandatory gate
# is opened so the model must invoke the appropriate skill before completing.
# (Consumed by gates.open_trigger_gate and qa_agent's missing-skill check.)

_TRIGGER_MAP: dict[str, dict] = {
    "graphql":    {"gate_id": "graphql_coverage",   "required_skills": ["api-security"]},
    "auth":       {"gate_id": "auth_coverage",       "required_skills": ["credential-audit"]},
    "admin":      {"gate_id": "admin_coverage",      "required_skills": ["web-exploit"]},
    "upload":     {"gate_id": "upload_coverage",     "required_skills": ["web-exploit"]},
    "api":        {"gate_id": "api_coverage",        "required_skills": ["api-security"]},
    "financial":  {"gate_id": "financial_coverage",  "required_skills": ["business-logic"]},
    "websocket":  {"gate_id": "websocket_coverage",  "required_skills": ["web-exploit"]},
}


# ── Public API ────────────────────────────────────────────────────────────────

def start(
    target:           str,
    depth:            str        = "standard",
    scope:            list[str]  | None = None,
    out_of_scope:     list[str]  | None = None,
    max_cost_usd:     float | None = None,
    max_time_minutes: int   | None = None,
    max_tool_calls:   int   | None = None,
    skill:            str   | None = None,
    model_profile:    str        = "full",
    scan_mode:        str        = "pentest",
) -> dict:
    """scan_mode: "pentest" (default) — HIR pauses for human decisions on ambiguous situations.
                  "benchmark" — fully autonomous, no HIR triggers, aggressive exploitation."""
    """Initialise a new scan session and write session.json."""
    global _current

    # Reset cost/call counters from any previous session
    cost_tracker.reset()

    preset = PRESETS.get(depth, PRESETS["standard"])
    limits = {
        "max_cost_usd":     max_cost_usd     if max_cost_usd     is not None else preset["max_cost_usd"],
        "max_time_minutes": max_time_minutes  if max_time_minutes is not None else preset["max_time_minutes"],
        "max_tool_calls":   max_tool_calls    if max_tool_calls   is not None else preset["max_tool_calls"],
    }

    _current = {
        "id":           str(uuid.uuid4()),
        "target":       target,
        "depth":        depth,
        "depth_label":  preset["label"],
        "description":  preset["description"],
        "scope":        scope        or [target],
        "out_of_scope": out_of_scope or [],
        "started":      datetime.now(timezone.utc).isoformat(),
        "finished":     None,
        "status":       "running",   # running | limit_reached | complete
        "stop_reason":  None,
        "limits":       limits,
        "skill":         skill,
        "skill_history": [
            {
                "skill":        skill,
                "reason":       "session start",
                "chained_from": None,
                "timestamp":    datetime.now(timezone.utc).isoformat(),
            }
        ] if skill else [],
        "tools_called":  [],
        "current_step":  None,
        "gates":         [],          # triggered gates that block completion
        "deferred_gates": [],         # gate IDs suppressed while a skill is active
        "spider_failures": {},        # targets where spider failed; cleared on success
        "model_profile": model_profile,
        "scan_mode":     scan_mode,
        "tool_invocations": [],
        "known_assets": {
            "domains": [], "ips": [], "ports": [],
            "technologies": [], "endpoints": [],
            # Authentication context — discovered creds, JWTs, and login endpoints.
            # Smith reads these (surfaced in recovery brief) when an endpoint
            # returns 401/403 instead of marking the cell "tested_clean".
            "credentials":    [],   # [{username, password, source}]
            "auth_tokens":    [],   # [{type, value, user_id?, role?, obtained_at}]
            "auth_endpoints": [],   # [{path, method, body_template}]
        },
        "context_chars_sent": 0,
        "complete_attempts":  0,        # incremented each time session(complete) is called
    }
    # Capture which Smith process drove this start() call so the dashboard
    # watchdog can ask "is THIS PID still alive?" instead of falling back to
    # the quick_log mtime heuristic (which gives false positives during long
    # thinking-mode reasoning).
    caller = _detect_smith_caller()
    if caller:
        _current["smith_proc"] = {
            **caller,
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "source":      "interactive_mcp",
        }
        _persist_smith_caller(caller)
    _flush()
    return _current


def check_limits(cost_summary: dict) -> str | None:
    """
    Check all hard limits against current cost/time/call data.
    Returns a stop-message if any limit is exceeded (return this directly
    to Claude as the tool result); returns None if the scan can continue.
    """
    if _current is None or _current["status"] != "running":
        return None

    lim = _current["limits"]

    # ── Cost ──────────────────────────────────────────────────────────────────
    spent = cost_summary.get("est_cost_usd", 0)
    if lim["max_cost_usd"] is not None and spent >= lim["max_cost_usd"]:
        return _stop(
            "limit_reached",
            f"COST LIMIT: ${spent:.4f} spent (limit ${lim['max_cost_usd']:.2f}). "
            "Do not run any more tools. Call complete_scan() and write the final report.",
        )

    # ── Time ──────────────────────────────────────────────────────────────────
    elapsed_min = (
        datetime.now(timezone.utc) - datetime.fromisoformat(_current["started"])
    ).total_seconds() / 60
    if lim["max_time_minutes"] is not None and elapsed_min >= lim["max_time_minutes"]:
        return _stop(
            "limit_reached",
            f"TIME LIMIT: {elapsed_min:.0f} min elapsed (limit {lim['max_time_minutes']} min). "
            "Do not run any more tools. Call complete_scan() and write the final report.",
        )

    # ── Tool calls (0 = unlimited) ────────────────────────────────────────────
    calls = cost_summary.get("tool_calls_total", 0)
    if lim["max_tool_calls"] > 0 and calls >= lim["max_tool_calls"]:
        return _stop(
            "limit_reached",
            f"CALL LIMIT: {calls} tool calls made (limit {lim['max_tool_calls']}). "
            "Do not run any more tools. Call complete_scan() and write the final report.",
        )

    return None


def complete(
    notes: str = "",
    stop_reason: str | None = None,
    quality_gate: str | None = None,
) -> dict:
    """Mark the scan as done (called by Claude when finished).

    quality_gate="failed" sets status to "incomplete_with_unresolved_blockers"
    so dashboards and exports can distinguish a force-completed scan from a clean one.
    """
    global _current
    _reconcile_if_external_write()
    if _current and _current["status"] == "running":
        _current["status"]   = "incomplete_with_unresolved_blockers" if quality_gate == "failed" else "complete"
        _current["finished"] = datetime.now(timezone.utc).isoformat()
        _current["notes"]    = notes
        if quality_gate:
            _current["quality_gate"] = quality_gate
        if stop_reason is not None:
            _current["stop_reason"] = stop_reason
        _flush()
    return _current or {}


def get() -> dict | None:
    return _current


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
    global _current
    _reconcile_if_external_write()
    if not _current:
        return
    _current["smith_proc"] = {
        "pid":          int(pid),
        "client":       str(client),
        "source":       str(source),
        "captured_at":  datetime.now(timezone.utc).isoformat(),
    }
    _flush()


def get_scan_client() -> str | None:
    """Return the scan-locked Smith client, or None if not yet set.

    Read-only inspection helper for the watchdog. Does not reconcile —
    callers wanting freshest state should reload first."""
    if not _current:
        return None
    sp = _current.get("smith_proc")
    if isinstance(sp, dict):
        c = sp.get("client")
        if isinstance(c, str) and c in ("claude", "opencode", "codex"):
            return c
    return None


def load_from_disk(force: bool = False) -> dict | None:
    """Populate _current from session.json.

    Used by processes (e.g. the dashboard API server) that never called
    start() but need to read/mutate session state.

    Default behavior loads only when _current is None (one-shot bootstrap).
    Pass force=True to ALWAYS reload from disk — required for the dashboard
    process whose in-memory _current goes stale as the MCP process keeps
    writing to session.json from another process.
    """
    global _current
    if force:
        # force=True means "make _current match disk reality, whatever
        # that is". If the file was deleted (dashboard Clear All), drop
        # the cache so callers don't keep operating on stale state.
        # Gated on _last_local_write_mtime > 0 so test fixtures that
        # monkeypatch _current without ever flushing don't get
        # clobbered: in those tests we never saw disk, so its absence
        # isn't a deletion to mirror.
        if _SESSION_FILE.exists():
            try:
                _current = json.loads(_SESSION_FILE.read_text(encoding="utf-8"))
            except Exception:
                pass
        elif _last_local_write_mtime > 0:
            _current = None
        return _current
    if _current is None and _SESSION_FILE.exists():
        try:
            _current = json.loads(_SESSION_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return _current


# ── Context pressure ─────────────────────────────────────────────────────────

def charge_context(chars: int) -> None:
    """Track cumulative response chars sent to the model."""
    if _current and _current.get("status") == "running":
        _current["context_chars_sent"] = _current.get("context_chars_sent", 0) + chars
        _flush()


def get_context_pressure(profile: dict) -> float:
    """Return context pressure as 0.0-1.0 ratio. Returns 0.0 if no budget set."""
    if _current is None:
        return 0.0
    budget = profile.get("context_budget_chars")
    if not budget:
        return 0.0
    sent = _current.get("context_chars_sent", 0)
    return min(1.0, sent / budget)


def remaining(cost_summary: dict) -> dict:
    """Return how much budget/time/calls are left (for dashboard display)."""
    if _current is None:
        return {}
    lim     = _current["limits"]
    elapsed = (
        datetime.now(timezone.utc) - datetime.fromisoformat(_current["started"])
    ).total_seconds() / 60
    spent   = cost_summary.get("est_cost_usd", 0)
    calls   = cost_summary.get("tool_calls_total", 0)
    max_calls = lim["max_tool_calls"]
    max_cost  = lim["max_cost_usd"]
    max_time  = lim["max_time_minutes"]
    return {
        "cost_remaining_usd":     None if max_cost is None else round(max(0, max_cost - spent), 4),
        "time_remaining_minutes": None if max_time is None else round(max(0, max_time - elapsed), 1),
        "calls_remaining":        max(0, max_calls - calls) if max_calls > 0 else -1,
        "cost_pct":               0 if max_cost is None else min(100, round(spent / max_cost * 100, 1)),
        "time_pct":               0 if max_time is None else min(100, round(elapsed / max_time * 100, 1)),
        "calls_pct":              min(100, round(calls / max_calls * 100, 1)) if max_calls > 0 else 0,
    }


# ── Human Intervention Required ──────────────────────────────────────────────

def trigger_intervention(
    code: str,
    situation: str,
    tried: list[str],
    options: list[str],
) -> dict:
    """Transition session to intervention_required state.

    Pauses the scan — envelope.py blocks all non-session tool calls while in this state.
    The human responds via the dashboard or session(action='resume').
    """
    global _current
    _reconcile_if_external_write()
    if not _current:
        return {}
    _current["status"] = "intervention_required"
    _current["intervention"] = {
        "code":         code,
        "situation":    situation,
        "tried":        tried,
        "options":      options,
        "triggered_at": datetime.now(timezone.utc).isoformat(),
        "resolved_at":  None,
        "resolution":   None,
    }
    _flush()
    # Out-of-band notification (Telegram etc.) — optional, fire-and-forget.
    # No-op when nothing is configured in .env. Wrapped so a notifier import
    # error never breaks the HIR fire path itself.
    try:
        from core.notifiers import notify as _notify
        _notify(
            title=code,
            body=situation,
            urgency="high",
            code=code,
            options=options,
        )
    except Exception:
        pass
    return _current


def resolve_intervention(choice: str, message: str = "") -> dict:
    """Human responded — transition back to running and record their decision.

    Idempotent: if there is no active intervention (already resolved), only
    the running-status flip is applied. Previously this path was appending
    a None entry to intervention_history every time it was called twice in
    a row (e.g. operator clicks REAUTH then watchdog also calls us), which
    broke the dashboard renderer that iterated history without null checks.
    """
    global _current
    _reconcile_if_external_write()
    if not _current:
        return {}
    intervention = _current.get("intervention")
    history = _current.setdefault("intervention_history", [])
    # Sanitize legacy entries: drop any None left from earlier bug.
    if any(h is None for h in history):
        history[:] = [h for h in history if h is not None]
    resolved_code = ""
    if intervention:
        resolved_code = intervention.get("code", "")
        intervention["resolved_at"] = datetime.now(timezone.utc).isoformat()
        intervention["resolution"]  = {"choice": choice, "message": message}
        history.append(intervention)
        _current["intervention"] = None
    # Only return to 'running' if we weren't already in a terminal state.
    # complete / incomplete_with_unresolved_blockers / limit_reached are
    # definitive end-states; resolving a stale intervention should not undo
    # the human's Complete Scan click or a budget/time stop.
    if _current.get("status") not in (
        "complete", "incomplete_with_unresolved_blockers", "limit_reached",
    ):
        _current["status"] = "running"
    _flush()
    # Reset Smith's complete()-attempts counter when an HIR_FORCE_COMPLETE
    # was just resolved. The counter lives in mcp_server.session_tools as a
    # module global; it only zeroed on session.start or a no-blocker
    # success, which meant once it crossed _MAX_COMPLETE_ATTEMPTS (8) the
    # very next complete() call would re-fire the HIR — turning a single
    # blocked scan into the 11→15→17→19→21→24→29 cascade the user saw.
    # Each human resolution should grant Smith a fresh 8-attempt budget to
    # try again with the new instructions. Imported lazily to avoid an
    # import cycle (mcp_server imports core.session).
    if resolved_code == "HIR_FORCE_COMPLETE":
        try:
            from mcp_server import session_tools as _st
            _st._complete_attempts = 0
        except Exception:
            # Test contexts may not have mcp_server importable; resetting
            # is a quality-of-life win, not a correctness invariant.
            pass
    return _current


def get_intervention() -> dict | None:
    """Return current intervention dict if scan is paused, else None.

    Reconciles against disk first because this is the dedup-check used by
    every HIR-triggering path. If a previous HIR fired and flushed to disk
    but our cached _current hasn't observed that flush yet (the dashboard
    process and MCP server keep separate _current caches; same family of
    cross-process desync we fixed for Clear All in PR #111), the dedup
    check returns None and a duplicate HIR fires. _reconcile_if_external_write
    only pays for a disk read when session.json's mtime is newer than our
    last local write, so the steady-state cost is near zero.
    """
    _reconcile_if_external_write()
    if not _current or _current.get("status") != "intervention_required":
        return None
    return _current.get("intervention")


# ── Internal ──────────────────────────────────────────────────────────────────

def _stop(status: str, message: str) -> str:
    global _current
    _reconcile_if_external_write()
    if _current:
        _current["status"]      = status
        _current["stop_reason"] = message
        _current["finished"]    = datetime.now(timezone.utc).isoformat()
        _flush()
    return message


def _flush() -> None:
    global _last_local_write_mtime
    if _current:
        _SESSION_FILE.write_text(json.dumps(_current, indent=2))
        try:
            _last_local_write_mtime = _SESSION_FILE.stat().st_mtime
        except OSError:
            # Hold the previous mtime; reconcile will conservatively reload
            # the next time it's called.
            pass


# ── Cross-process state reconciliation ───────────────────────────────────────
#
# The dashboard and the MCP server are separate Python processes that both
# read/write session.json. Each keeps its own in-memory `_current`. Without
# reconciliation, a write in process A can be silently undone by a stale
# `_flush()` in process B — e.g., the operator clicks Complete Scan on the
# dashboard (status → "complete"), then the MCP's next tool call flushes its
# stale `_current` (status → "running") on top of the dashboard's write.
#
# Strategy: track the mtime of our own last `_flush()` write. Before every
# mutation, compare against the on-disk mtime. If disk is newer than what we
# wrote, another process changed the file — reload it into `_current` before
# touching anything. Read-only callers don't reconcile (cost outweighs the
# benefit; they tolerate stale data fine).
#
# This isn't a real lock — TOCTTOU races between reconcile-read and the next
# write still exist — but it eliminates the common case of "every mutation
# silently undoes the operator's Complete click".

# mtime (seconds since epoch) of the last `_flush()` write performed by THIS
# process. 0.0 means we haven't written yet; any disk mtime > this value is
# treated as "external write, reconcile before continuing".
_last_local_write_mtime: float = 0.0

# Epoch-second timestamp of the last lazy smith.pid refresh attempt. Rate-
# limits the psutil scan in _refresh_smith_pid_if_stale() so very high-frequency
# mutations (e.g., add_tool_called on every MCP tool result) don't pay for an
# expensive process_iter on every single call when the PID went stale.
_last_pid_refresh_attempt: float = 0.0
_PID_REFRESH_MIN_INTERVAL_SECONDS = 30.0


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
    global _current
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
        disk_mtime = _SESSION_FILE.stat().st_mtime
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
        if _last_local_write_mtime > 0 and _current is not None:
            _current = None
        _refresh_smith_pid_if_stale()
        return
    except OSError:
        # Permission / IO error — leave cache alone (better stale than
        # a noisy False positive from a transient stat failure).
        return
    # Small fudge: filesystem mtime granularity varies (APFS is sub-µs but
    # some Linux mounts are 1s). A tolerance of 1ms catches genuine external
    # writes without false-positiving on same-process re-flushes within the
    # same syscall window.
    if disk_mtime > _last_local_write_mtime + 0.001:
        try:
            fresh = json.loads(_SESSION_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pass
        else:
            _current = fresh

    # Stale-PID refresh (rate-limited)
    _refresh_smith_pid_if_stale()


def _refresh_smith_pid_if_stale() -> None:
    """If logs/smith.pid points at a dead process, try to detect a live caller
    and rewrite the file. Rate-limited so high-frequency mutations don't pay
    for psutil scanning on every call.

    Returns silently on any error — this is a best-effort liveness refresh,
    not a correctness invariant. Worst case: stale PID stays stale and the
    watchdog's process-scan fallback signal does the job instead.
    """
    global _last_pid_refresh_attempt
    try:
        now = datetime.now(timezone.utc).timestamp()
    except OSError:
        return
    if now - _last_pid_refresh_attempt < _PID_REFRESH_MIN_INTERVAL_SECONDS:
        return
    _last_pid_refresh_attempt = now

    pid_file = _REPO_ROOT / "logs" / "smith.pid"
    try:
        raw = pid_file.read_text().strip()
        pid = int(raw)
    except (ValueError, OSError):
        # FileNotFoundError is a subclass of OSError — listing both is
        # redundant (sonar S5713). OSError alone covers the missing-file,
        # permission-denied, and other read-failure cases.
        # No tracked PID at all → detection probably never fired. Try now.
        caller = _detect_smith_caller()
        if caller:
            _persist_smith_caller(caller)
        return

    try:
        import psutil
        if 0 < pid < (1 << 22) and psutil.pid_exists(pid):
            return  # tracked PID is still alive; nothing to do
    except ImportError:
        return

    # Tracked PID is dead. Find a live caller and replace the file.
    caller = _detect_smith_caller()
    if caller and caller["pid"] != pid:
        _persist_smith_caller(caller)


# ── Facade re-exports ────────────────────────────────────────────────────────
# Imported after the state + lifecycle above so each submodule's module-level
# ``import core.session as _sess`` binds a package that already exposes
# _current, paths, _TRIGGER_MAP, _flush, and _reconcile_if_external_write.
# (Those modules read package attributes at call time, so this is also
# belt-and-suspenders.) start()/_refresh_smith_pid_if_stale() above call
# _detect_smith_caller/_persist_smith_caller by bare name, which resolves to
# these re-exported globals — and stays patchable as core.session.NAME.

from .process_detect import (  # noqa: E402
    _MCP_SSE_PORT,
    _connected_pids,
    _detect_smith_caller,
    _persist_smith_caller,
    _resolve_client_for_pid,
)
from .gates import (  # noqa: E402
    add_tool_called,
    defer_gates,
    open_trigger_gate,
    pending_gates,
    restore_gates,
    satisfy_gate,
    set_skill,
    set_step,
    trigger_gate,
)
from .assets import (  # noqa: E402
    _SPIDER_MAX_RETRIES,
    _update_dict_assets,
    _update_ports_assets,
    _update_scalar_assets,
    add_tool_invocation,
    clear_spider_failure,
    get_spider_failures,
    has_spider_failure,
    record_spider_failure,
    spider_max_retries,
    update_known_assets,
)
