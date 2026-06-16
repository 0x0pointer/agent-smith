"""
QA Agent — depth enforcer
=========================
Depth-enforcement daemon. Runs every 2 minutes during an active scan.

Focus: push Smith to go deeper, not cut corners, and complete full scan cycles.
Not concerned with PoC files, coverage bookkeeping, scope housekeeping, or gate timers.

Two responsibilities:
1. Alert generation — coded alerts written to qa_state.json and surfaced in envelopes.
2. Steering directives — written to steering_queue.json, injected into Smith's next
   tool response automatically. One directive at a time — never pile on.

Alert schema
  {
    "code":     str,   — machine-readable code
    "urgency":  str,   — "high" | "medium" | "low"
    "blocking": bool,  — true = blocks scan completion
    "message":  str,   — human-readable description
  }

Checks kept:
  BULK_MARKING         — >10 N/A cells with no tested_by tool (blocking anti-shortcut)
  COVERAGE_INTEGRITY   — tested/vulnerable cells missing tested_by tool (blocking anti-shortcut)
  SUSPICIOUS_SPEED     — >20 cells closed in <10 min (shortcut detection)
  NA_ABUSE             — N/A rate >35% of addressed cells (shortcut detection)
  DEPTH_AFTER_FINDING  — high/critical finding >20 min old with no follow-up tools
  WHITEBOX_PASSES      — thorough scan with <3 semgrep passes (3-pass enforcement)
  PREMATURE_COMPLETE   — complete called before 3-pass requirement met
  TOOL_INACTIVITY      — no tool activity for >15 min (stall detection)
  NO_SPIDER            — httpx ran but spider never did (mandatory tool chain)
  MISSING_SKILL        — endpoint type discovered but required skill never invoked

Layout
------
The implementation is split across focused submodules; import from
``core.qa_agent`` exactly as before — every name is re-exported here.

  __init__         this file — paths, HIR dedup state, _has_pending_directives, facade
  _util            pure helpers (_ts_age_secs)
  hir              the _hir() Human-Intervention trigger
  checks_shortcuts anti-shortcut checks (bulk N/A, integrity, speed, N/A abuse)
  checks_depth     depth/stall checks + stuck-on-target HIR escalation
  checks_skills    mandatory skill-chain + missing-skill checks
  checks_health    auth/budget/reachability/tool-failure HIR checks
  daemon           _deterministic_qa_checks orchestrator + QADaemon

Paths and _last_hir_trigger_ts live here in the package namespace so they stay
patchable as ``core.qa_agent.NAME`` (the test suite patches _STEERING_FILE,
_SESSION_FILE, _last_hir_trigger_ts, etc.). Submodules read them back via
``import core.qa_agent as _qa``.
"""
from __future__ import annotations

import json
import logging
from core import paths as _paths

_log = logging.getLogger(__name__)

_QA_STATE_FILE  = _paths.QA_STATE_FILE
_SESSION_FILE   = _paths.SESSION_FILE
_FINDINGS_FILE  = _paths.FINDINGS_FILE
_COVERAGE_FILE  = _paths.COVERAGE_FILE
_STEERING_FILE  = _paths.STEERING_FILE

# Minimum seconds between two HIR triggers of the same code. Even if the
# get_intervention() dedup fails (cross-process state desync, racy flush,
# etc.), this caps the burst at one HIR per minute per code. The user
# observed 5 HIR_STUCK_ON_TARGET events fire within 137ms — that's the
# blast radius this floor closes.
_HIR_MIN_GAP_SECONDS = 60
_last_hir_trigger_ts: dict[str, float] = {}


def _has_pending_directives() -> bool:
    """Return True if Smith already has an unacknowledged directive in the queue."""
    try:
        data = json.loads(_STEERING_FILE.read_text()) if _STEERING_FILE.exists() else {}
        return any(
            d.get("status") in ("pending", "injected")
            for d in data.get("directives", [])
        )
    except Exception:
        return False


# ── Facade re-exports ────────────────────────────────────────────────────────
# Imported after the state above so each submodule's module-level
# ``import core.qa_agent as _qa`` binds a package that already exposes paths +
# HIR state. (Attribute access in those modules is deferred to call time, so
# this ordering is belt-and-suspenders.)

from ._util import _ts_age_secs  # noqa: E402
from .hir import _hir  # noqa: E402
from .checks_shortcuts import (  # noqa: E402
    _check_bulk_marking,
    _check_coverage_integrity,
    _check_na_abuse,
    _check_suspicious_speed,
)
from .checks_depth import (  # noqa: E402
    _check_depth_after_finding,
    _check_premature_complete,
    _check_stuck_on_target,
    _check_tool_inactivity,
    _check_whitebox_passes,
)
from .checks_skills import (  # noqa: E402
    _check_core_skill_chain,
    _check_missing_skill,
    _check_no_spider_after_httpx,
    _maybe_inject_business_logic_directive,
    _maybe_inject_param_fuzz_directive,
    _maybe_inject_web_exploit_directive,
)
from .checks_health import (  # noqa: E402
    _ABORT_OPTION,
    _PYTHON_NATIVE_TOOLS,
    _check_auth_failure,
    _check_budget_limit,
    _check_exploit_escalation,
    _check_repeated_tool_failure,
    _check_target_unreachable,
    _check_zero_endpoints,
)
from .daemon import (  # noqa: E402
    QADaemon,
    _deduplicate,
    _deterministic_qa_checks,
    _load_json,
    _merge_alerts,
    _read_qa_state,
    _sanitize_history,
    _session_is_running,
    qa_daemon,
)
