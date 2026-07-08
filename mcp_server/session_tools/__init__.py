"""
Consolidated session tool — replaces scan.py and infra.py

Split into a package for the <300-lines-per-file convention. This facade keeps
the public import surface identical: `import mcp_server.session_tools` still
registers the `@mcp.tool()` `session` dispatcher, and every name previously
importable from the module is re-exported here. Mutable completion counters live
here as module globals so external writers (core/session/__init__.py resets
`_complete_attempts`) and unittest patches on `mcp_server.session_tools.<name>`
target the same object the submodule functions read/write via `_st.`.
"""
import asyncio
import json
import os
import re
from typing import Any

from core import cost as cost_tracker
from core import findings as findings_store
from core import logger as log
from core import session as scan_session
from core.taxonomy import BYPASS_REQUIRED_TYPES as _BYPASS_REQUIRED_TYPES
from mcp_server._app import mcp, _ensure_dict, _session_tools_called
from mcp.server.fastmcp import Context

_background_tasks: set[asyncio.Task] = set()  # keeps fire-and-forget tasks alive

# Track completion attempts — after _MAX_COMPLETE_ATTEMPTS the scan escalates to the
# HIR_FORCE_COMPLETE human-override valve. Kept low (4) so a genuinely-stuck scan
# reaches a human quickly with the accept-gaps / skip-cells options, instead of the
# agent silently giving up long before the valve (the observed failure: a findings-rich
# run stopped at complete_attempts=2 and never escalated). The progress-aware refund
# below means legitimate one-blocker-at-a-time fixing does NOT accumulate attempts, so
# a low ceiling only bites truly non-progressing retries.
_complete_attempts = 0
_MAX_COMPLETE_ATTEMPTS = 4

# Blocker count from the previous complete() attempt. Under condensed (small/
# medium) profiles, blockers are surfaced ONE AT A TIME, so a model legitimately
# fixing them across several complete() calls would otherwise trip the 8-attempt
# HIR. When the count DROPS (progress), we refund the attempt budget. None = no
# prior attempt this scan.
_last_blocker_count: int | None = None

# Counts complete() calls that passed ALL quality checks (no PoC gaps, no missing
# reproductions, no coverage blockers). Separate from _complete_attempts so that
# quality-fix attempts do NOT count as genuine analysis passes. The iteration gate
# uses _analysis_passes, not _complete_attempts.
_analysis_passes = 0

_QA_STATE_FILENAME = "qa_state.json"

# ── Re-exports (public import surface preserved) ────────────────────────────────
from ._common import (
    _THOROUGH_MIN_ITERATIONS,
    _FLAG_RE,
    _min_iterations,
    _condensed_directives,
    _has_ctf_flag,
    _effective_tools,
)
from .handshake import _client_from_ctx, _record_handshake_client
from .start_helpers import (
    _reset_coverage_matrix,
    _norm_target,
    _SEV_ORDER,
    _prior_findings_brief,
    _start_first_move,
)
from .start import _start_response, _do_start
from .integrity_gates import (
    _skipped_no_evidence_blocker,
    _integrity_blockers,
    _na_untooled_blocker,
    _injection_breadth_blocker,
    _suspect_na_cells,
)
from .coverage_gates import (
    _COVERAGE_FLOOR_PCT,
    _low_coverage_blocker,
    _rich_exploitation,
    _CROSSCUTTING_CELL_TYPES,
    _INJECTION_FINDING_KEYWORDS,
    _findings_mapped_blocker,
    _completeness_blockers,
    _coverage_blockers,
)
from .completion_gates import (
    _qa_blockers,
    _gate_blockers,
    _escalation_lead_blockers,
    _finding_quality_blockers,
    _collect_completion_blockers,
)
from .whitebox import _is_whitebox_scan, _deepen_brief_condensed, _deepen_brief_whitebox
from .deepen import _deepen_steps_pass1, _deepen_steps_pass2, _deepen_brief
from .blocker_response import (
    _pending_steer_block,
    _BLOCKER_PRIORITY,
    _blocker_priority,
    _build_blocker_response,
)
from .complete import (
    _persist_completion_counters,
    _thorough_gate,
    _autoclose_crosscutting_best_effort,
    _do_complete,
    _record_metrics,
)
from .hir import _do_qa_reply, _do_resume, _do_intervene
from .oob_actions import _oob_config, _oob_module, _do_oob_start, _do_oob_mint, _do_oob_poll
from .status import _do_status, _build_status_base, _add_status_work_queue, _add_status_qa_alerts
from .recovery import (
    _INJECTION_TOOL_MAP,
    _determine_resume_step,
    _check_coverage_integrity,
    _TERMINAL_SCAN_STATUSES,
    _terminal_recovery_brief,
    _do_recovery,
)
from .recovery_build import (
    _recovery_iter_status,
    _recovery_auth_context,
    _build_recovery_result,
    _concrete_next_call,
    _next_pending_probe,
    _build_action_list,
)
from .skills import (
    _do_artifact,
    _do_pre_chain,
    _manage_skill_gates,
    _do_set_skill,
    _enqueue_setup_gates,
    _do_set_step,
    _do_set_codebase,
)
from .containers import (
    _do_start_kali,
    _do_stop_kali,
    _do_start_metasploit,
    _do_stop_metasploit,
    _do_start_mobsf,
    _do_stop_mobsf,
    _do_pull_images,
)
from .wishlist import (
    _AUTH_NEED_TERMS,
    _wishlist_already_satisfiable,
    _do_wishlist_add,
    _do_wishlist_list,
)
from .setup_gates import (
    _setup_gate_describe,
    _setup_gate_list_response,
    _setup_gate_check,
    _setup_gate_open,
    _SETUP_ELECT_MSG,
    _setup_gate_elect,
    _do_setup_gate,
)


@mcp.tool()
async def session(action: str, options: dict | str | None = None, ctx: Context | None = None) -> str:
    """Scan lifecycle and infrastructure management.

    action  : start | complete | status | recovery | artifact | qa_reply | set_skill | set_step | wishlist_add | wishlist_list | start_kali | stop_kali | start_metasploit | stop_metasploit | pull_images | set_codebase

    wishlist_add options (NON-BLOCKING agent→operator backlog — use instead of
      marking a cell not_applicable when you're blocked by a missing resource):
      need= (required — what you need to go deeper, e.g. "analyst-role creds for /admin"),
      category= (credentials|scope|rate_limit|tooling|access|environment|other),
      rationale=, blocking_cell_ids=[...]. Does NOT pause the scan; keep testing
      other coverage. Auth needs already satisfiable from known_assets are rejected.

    wishlist_list: returns the open wishlist (what you've asked the operator for)

    start options:
      target, depth=standard (recon|standard|thorough), scope=[],
      out_of_scope=[], max_cost_usd=, max_time_minutes=, max_tool_calls=,
      model_profile=full (full|medium|small) — controls output verbosity

    complete options: notes=

    qa_reply options:
      message= (your response to the QA agent's alerts — what you acknowledge and what
                you plan to do. Call this immediately after session(action="status")
                returns qa_alerts so the QA ↔ Smith conversation log is complete.)

    status: returns current scan state (target, tools run, findings, cost)

    recovery: returns compact recovery brief after context compaction — tells you
              exactly what to do next. Call this if you lost context.

    artifact options:
      id= (artifact ID from tool response), mode=summary (summary|head|tail|grep|full),
      max_chars=4000, pattern= (regex for grep mode)

    set_skill options:
      skill= (name of the active skill, e.g. "pentester", "ai-redteam")
      reason= (why this skill was chosen — shown in logs)
      chained_from= (parent skill name when chaining, omit for first skill)

    set_step options:
      step= (current workflow step, e.g. "5_nuclei_scan")

    set_codebase options:
      path= (absolute path to local codebase)

    start_kali, stop_kali, start_metasploit, stop_metasploit, pull_images: no options needed
    """
    opts = _ensure_dict(options) or {}
    # Force-reload from disk on EVERY action.
    #
    # The MCP server runs in its own process with its own _current cache.
    # Three cross-process events can rewrite session.json behind us:
    #   • Dashboard's "Clear All"     → deletes session.json
    #   • Dashboard's "Complete Scan" → flips status to "complete"
    #   • Dashboard HIR resolution    → flips status back to "running"
    #
    # Without force=True, our cache stays at whatever it last wrote (often
    # intervention_required from a prior HIR), and `_do_start` then blocks
    # a fresh scan with "SCAN PAUSED" even though disk is clean. The
    # earlier `if action != "start"` carve-out made start the worst case
    # — it had to be force=True precisely to catch the post-Clear state,
    # but was getting nothing at all.
    #
    # Cost is one stat()+read() per session() call. session() fires ~5-10
    # times per scan (start, status, recovery, complete, qa_reply, …), so
    # the overhead is negligible compared to the cross-process desync it
    # closes.
    scan_session.load_from_disk(force=True)
    result = await _dispatch_async_action(action, opts)
    if result is None:
        result = _dispatch_sync_action(action, opts)
    if action == "start":
        # Lock the session to the client named in the MCP initialize handshake
        # (authoritative, per-connection) — overrides the ambiguous PID scan.
        _record_handshake_client(ctx)
    return result


async def _dispatch_async_action(action: str, opts: dict) -> str | None:
    """Handle async session actions. Returns None if action is not async."""
    if action == "start_kali":
        return await _do_start_kali()
    if action == "stop_kali":
        return await _do_stop_kali()
    if action == "start_metasploit":
        return await _do_start_metasploit()
    if action == "stop_metasploit":
        return await _do_stop_metasploit()
    if action == "start_mobsf":
        return await _do_start_mobsf()
    if action == "stop_mobsf":
        return await _do_stop_mobsf()
    if action == "pull_images":
        return await _do_pull_images()
    if action == "qa_reply":
        return await _do_qa_reply(opts)
    if action == "oob_start":
        return await _do_oob_start()
    if action == "oob_poll":
        return await _do_oob_poll(opts)
    if action == "setup_gate":
        return await _do_setup_gate(opts)
    if action == "complete":
        # Async so we can propagate app-wide cross-cutting verdicts to their cells
        # (best-effort) before the completion gate evaluates coverage.
        await _autoclose_crosscutting_best_effort()
        return _do_complete()
    return None


def _dispatch_sync_action(action: str, opts: dict) -> str:
    """Handle sync session actions."""
    if action == "start":
        return _do_start(opts)
    if action == "status":
        return _do_status()
    if action == "set_skill":
        return _do_set_skill(opts)
    if action == "set_step":
        return _do_set_step(opts)
    if action == "set_codebase":
        return _do_set_codebase(opts)
    if action == "recovery":
        return _do_recovery()
    if action == "artifact":
        return _do_artifact(opts)
    if action == "pre_chain":
        return _do_pre_chain(opts)
    if action == "resume":
        return _do_resume(opts)
    if action == "intervene":
        return _do_intervene(opts)
    if action == "wishlist_add":
        return _do_wishlist_add(opts)
    if action == "wishlist_list":
        return _do_wishlist_list()
    if action == "oob_mint":
        return _do_oob_mint(opts)
    return f"Unknown action '{action}'. Use: start, complete, status, qa_reply, recovery, artifact, pre_chain, set_skill, set_step, resume, wishlist_add, wishlist_list, setup_gate, start_kali, stop_kali, start_metasploit, stop_metasploit, start_mobsf, stop_mobsf, pull_images, set_codebase, oob_start, oob_mint, oob_poll"
