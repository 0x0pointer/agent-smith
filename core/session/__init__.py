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

  __init__        this file — mutable state (_current), presets, _TRIGGER_MAP,
                  cross-process reconciliation bookkeeping vars, and the facade
  lifecycle       scan start/complete, get, load_from_disk, triage flags
  limits          hard-limit enforcement (check_limits/_stop), remaining,
                  context-pressure tracking (charge_context/get_context_pressure)
  intervention    Human-Intervention-Required (HIR) trigger/resolve/get
  persistence     session.json flush, cross-process reconcile, stale-PID
                  refresh, and the smith_proc scan-lock helpers
  process_detect  Smith caller detection (_detect_smith_caller + helpers)
  gates           gate tracking + skill/step/tools-called bookkeeping
  assets          known-assets vault, tool-invocation log, spider-failure gate
  setup_gates     manual-setup capability gates (capabilities.yaml)

The mutable ``_current`` cache, paths, and _TRIGGER_MAP live here in the package
namespace so they stay patchable as ``core.session.NAME`` (the suite patches
_SESSION_FILE, _current, _REPO_ROOT, _last_local_write_mtime, _detect_smith_caller).
The submodules read them back via ``import core.session as _sess`` and access
``_sess.<name>`` at call time — reading + mutating ``_current`` in place, and
(for start/complete/load/reconcile) rebinding ``_sess._current`` on the package
itself, so every name stays patchable and no import cycle forms.
"""
from __future__ import annotations

from core import paths as _paths

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

_REPO_ROOT = _paths.REPO_ROOT
_SESSION_FILE = _paths.SESSION_FILE


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
    "ai-redteam": {"gate_id": "ai_redteam_coverage", "required_skills": ["ai-redteam"]},
}


# ── Cross-process state reconciliation bookkeeping ────────────────────────────
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
# silently undoes the operator's Complete click". The reconcile/flush/refresh
# logic itself lives in ``persistence`` and rebinds these package attributes
# via ``import core.session as _sess``.

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


# ── Facade re-exports ────────────────────────────────────────────────────────
# Imported after the state + globals above so each submodule's module-level
# ``import core.session as _sess`` binds a package that already exposes
# _current, paths, _TRIGGER_MAP, and the reconcile bookkeeping vars. (Those
# modules only touch package attributes at call time, so this ordering is also
# belt-and-suspenders.) Every name below stays patchable as core.session.NAME.

from .process_detect import (  # noqa: E402
    _MCP_SSE_PORT,
    _connected_pids,
    _detect_smith_caller,
    _persist_smith_caller,
    _resolve_client_for_pid,
)
from .persistence import (  # noqa: E402
    _flush,
    _reconcile_if_external_write,
    _refresh_smith_pid_if_stale,
    get_scan_client,
    get_smith_session_id,
    set_smith_proc,
    set_smith_session_id,
)
from .lifecycle import (  # noqa: E402
    complete,
    get,
    load_from_disk,
    note_triage_progress,
    set_triage_requested,
    start,
)
from .limits import (  # noqa: E402
    _fixed_context_overhead_chars,
    _stop,
    charge_context,
    charge_skill_context,
    check_limits,
    get_context_pressure,
    remaining,
    reset_context_meter,
)
from .intervention import (  # noqa: E402
    get_intervention,
    resolve_intervention,
    trigger_intervention,
)
from .gates import (  # noqa: E402
    add_tool_called,
    defer_gates,
    maybe_advance_phase,
    open_trigger_gate,
    pending_gates,
    reconcile_worked_gates,
    restore_gates,
    satisfy_gate,
    set_skill,
    set_step,
    skill_worked,
    trigger_gate,
)
from . import phases  # noqa: E402  (three-phase scan model)
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
    set_last_artifact,
    spider_max_retries,
    update_known_assets,
)
from .setup_gates import (  # noqa: E402
    list_setup_gates,
    open_setup_gate,
    probe_is_fresh,
    record_election,
    record_probe_result,
    setup_gate_by_id,
)
