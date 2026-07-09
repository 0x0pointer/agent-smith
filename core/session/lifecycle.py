"""
Session lifecycle
=================
Scan start/complete, the live-state accessor (`get`), disk bootstrap
(`load_from_disk`), and the post-scan triage-flag helpers
(`set_triage_requested`, `note_triage_progress`).

Mutable state (``_current``, paths, ``PRESETS``) lives in the ``core.session``
package namespace so the suite can patch it as ``core.session.NAME``. This
module reaches it via ``import core.session as _sess`` and reads/rebinds
``_sess.<name>`` at call time — start()/load_from_disk() rebind
``_sess._current`` (the package attribute) exactly as the in-package versions
did, keeping every name patchable without introducing an import cycle.
"""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone

import core.session as _sess
from core import cost as cost_tracker


def start(
    target:           str,
    depth:            str        = "standard",
    scope:            list[str]  | None = None,
    out_of_scope:     list[str]  | None = None,
    max_cost_usd:     float | None = None,
    max_time_minutes: int   | None = None,
    max_tool_calls:   int   | None = None,
    skill:            str   | None = None,
    model_profile:    str   | None = None,
    scan_mode:        str        = "pentest",
) -> dict:
    """scan_mode: "pentest" (default) — HIR pauses for human decisions on ambiguous situations.
                  "benchmark" — fully autonomous, no HIR triggers, aggressive exploitation.

    model_profile: full|medium|small, or None to AUTO-DETECT from the environment
                   (model name in OPENCODE_MODEL/OLLAMA_MODEL/MODEL/…, or a
                   SMITH_MODEL_PROFILE override). Auto-detection scopes the
                   context window so a forgotten flag on a small local model
                   (e.g. Qwen3-27B) doesn't silently overflow — it resolves to
                   'full' when no local signal is present (cloud Claude/GPT)."""
    """Initialise a new scan session and write session.json."""

    # Resolve the model profile: an explicit value wins; otherwise auto-detect
    # from the environment. Stored alongside the human-readable reason so the
    # operator can see (and override) what was picked.
    from core.model_detect import detect_profile
    resolved_profile, profile_reason = detect_profile(model_profile)

    # Reset cost/call counters from any previous session
    cost_tracker.reset()

    preset = _sess.PRESETS.get(depth, _sess.PRESETS["standard"])
    limits = {
        "max_cost_usd":     max_cost_usd     if max_cost_usd     is not None else preset["max_cost_usd"],
        "max_time_minutes": max_time_minutes  if max_time_minutes is not None else preset["max_time_minutes"],
        "max_tool_calls":   max_tool_calls    if max_tool_calls   is not None else preset["max_tool_calls"],
    }

    _sess._current = {
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
        # Three-phase scan model: exploit (deep, matrix-free) → coverage (matrix breadth)
        # → synthesis (compose everything). Saturation-driven; see core/session/phases.py.
        "scan_phase":    "exploit",
        "gates":         [],          # triggered gates that block completion
        "deferred_gates": [],         # gate IDs suppressed while a skill is active
        "setup_gates":   [],          # manual-setup prerequisites (capabilities.yaml) — NON-blocking, distinct from gates
        "spider_failures": {},        # targets where spider failed; cleared on success
        "model_profile": resolved_profile,
        "model_profile_reason": profile_reason,
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
            # Out-of-band callbacks minted for blind-vuln confirmation. Survives
            # compaction (recovery brief) so a callback fired now can be polled later.
            "oob_interactions": [], # [{subdomain, correlation_id, linked_cell_id, minted_at, polled, hits}]
            # Connected test devices/emulators a readiness probe confirmed live.
            # Lets a setup_gate auto-satisfy its re-prompt across skills (never the probe).
            "devices": [],          # [{kind, serial, transport, source, obtained_at}]
        },
        # SM-1: seed with the always-resident overhead (system prompt + tool
        # schemas + CLAUDE.md/AGENTS.md) instead of counting tool output from 0 —
        # otherwise the meter reads ~10% while the window is near full and the
        # recovery directive never fires in time on a small model.
        "context_chars_sent": _sess._fixed_context_overhead_chars(),
        "complete_attempts":  0,        # incremented each time session(complete) is called
    }
    # Capture which Smith process drove this start() call so the dashboard
    # watchdog can ask "is THIS PID still alive?" instead of falling back to
    # the quick_log mtime heuristic (which gives false positives during long
    # thinking-mode reasoning).
    caller = _sess._detect_smith_caller()
    if caller:
        _sess._current["smith_proc"] = {
            **caller,
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "source":      "interactive_mcp",
        }
        _sess._persist_smith_caller(caller)
    _sess._flush()
    return _sess._current


def complete(
    notes: str = "",
    stop_reason: str | None = None,
    quality_gate: str | None = None,
) -> dict:
    """Mark the scan as done (called by Claude when finished).

    quality_gate="failed" sets status to "incomplete_with_unresolved_blockers"
    so dashboards and exports can distinguish a force-completed scan from a clean one.
    """
    _sess._reconcile_if_external_write()
    if _sess._current and _sess._current["status"] == "running":
        _sess._current["status"]   = "incomplete_with_unresolved_blockers" if quality_gate == "failed" else "complete"
        _sess._current["finished"] = datetime.now(timezone.utc).isoformat()
        _sess._current["notes"]    = notes
        if quality_gate:
            _sess._current["quality_gate"] = quality_gate
        if stop_reason is not None:
            _sess._current["stop_reason"] = stop_reason
        _sess._flush()
    return _sess._current or {}


def set_triage_requested(value: bool = True) -> None:
    """Mark/clear that a standalone triage (adjudication) pass is in flight.

    Drives the dashboard's adjudication banner. Set when the operator triggers
    POST /api/triage; cleared (by api_session self-heal) once every in-scope
    finding carries a verdict. Triage never completes the scan, so there is no
    force_complete coupling — completion stays an independent operator action.
    """
    _sess._reconcile_if_external_write()
    if not _sess._current:
        return
    if value:
        # Triage is a post-scan step now: the flag must be settable on a STOPPED
        # scan (status complete/limit_reached/...), not only while running. Any
        # live session can carry it; completion never clears it.
        if _sess._current.get("status"):
            _sess._current["triage_requested"] = True
            # Stall clock: stamped now and re-stamped whenever a verdict lands
            # (see note_triage_progress). The dashboard flips the banner to a
            # "stalled" warning when this stops advancing — a progress signal
            # that, unlike the MCP heartbeat, isn't fooled by Smith staying
            # busy on unrelated testing while the triage pass is abandoned.
            now = time.time()
            _sess._current["triage_requested_at"] = now
            _sess._current["triage_progress_at"] = now
            _sess._current.pop("triage_pending_last", None)
            _sess._flush()
    else:
        _sess._current.pop("triage_requested", None)
        _sess._current.pop("triage_requested_at", None)
        _sess._current.pop("triage_progress_at", None)
        _sess._current.pop("triage_pending_last", None)
        _sess._flush()


def note_triage_progress(pending_count: int) -> None:
    """Advance the triage stall clock when the pending-verdict count drops.

    Called from the /api/session self-heal with the live pending count. The
    clock resets only on real progress (count decreased, or first observation),
    so a slow-but-advancing pass never looks stalled, while a pass that stops
    making verdicts — whether Smith went idle or wandered off to other work —
    trips the dashboard's stalled warning after the threshold.
    """
    if not _sess._current or not _sess._current.get("triage_requested"):
        return
    last = _sess._current.get("triage_pending_last")
    if last is None or pending_count < last:
        _sess._current["triage_pending_last"] = pending_count
        _sess._current["triage_progress_at"] = time.time()
        _sess._flush()


def get() -> dict | None:
    return _sess._current


def load_from_disk(force: bool = False) -> dict | None:
    """Populate _current from session.json.

    Used by processes (e.g. the dashboard API server) that never called
    start() but need to read/mutate session state.

    Default behavior loads only when _current is None (one-shot bootstrap).
    Pass force=True to ALWAYS reload from disk — required for the dashboard
    process whose in-memory _current goes stale as the MCP process keeps
    writing to session.json from another process.
    """
    if force:
        # force=True means "make _current match disk reality, whatever
        # that is". If the file was deleted (dashboard Clear All), drop
        # the cache so callers don't keep operating on stale state.
        # Gated on _last_local_write_mtime > 0 so test fixtures that
        # monkeypatch _current without ever flushing don't get
        # clobbered: in those tests we never saw disk, so its absence
        # isn't a deletion to mirror.
        if _sess._SESSION_FILE.exists():
            try:
                _sess._current = json.loads(_sess._SESSION_FILE.read_text(encoding="utf-8"))
            except Exception:
                pass
        elif _sess._last_local_write_mtime > 0:
            _sess._current = None
        return _sess._current
    if _sess._current is None and _sess._SESSION_FILE.exists():
        try:
            _sess._current = json.loads(_sess._SESSION_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return _sess._current
