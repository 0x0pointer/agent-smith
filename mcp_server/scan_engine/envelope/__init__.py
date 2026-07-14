"""
Canonical response envelope — every tool returns this exact shape.

The envelope is the only thing that enters the LLM context window.
Raw output lives in artifacts, referenced by artifact_id.

This package is a facade: `wrap()` (the central entry point) lives here and
every externally-imported name is re-exported so `import mcp_server.scan_engine.envelope`
continues to expose the same surface as the pre-split module, including for
tests that patch attributes on this module.
"""
from __future__ import annotations

from mcp_server.scan_engine.artifacts import store_artifact
from mcp_server.scan_engine.budget import enforce_budget, get_tool_budget, get_profile
from mcp_server.scan_engine.planner import compute_next
from mcp_server.scan_engine.state import get_state
from mcp_server.scan_engine.summarizers import summarize

# --- Shared state, constants, and the Envelope dataclass --------------------
from mcp_server.scan_engine.envelope._common import (
    Envelope,
    _compact_state,
    _log,
    _REPO_ROOT,
    _QA_STATE_FILE,
    _STEERING_FILE,
    _RECOVERY_SNAP_FILE,
    _last_qa_shown_ts,
    _qa_alert_last_shown,
    _QA_ALERT_DEDUP_SECONDS,
)

# --- Scan gate (HIR / SCAN_COMPLETED short-circuit) -------------------------
from mcp_server.scan_engine.envelope.gates import _check_scan_gate

# --- Tool-invocation recording + known-asset extraction ---------------------
from mcp_server.scan_engine.envelope.assets import (
    _record_invocation,
    _persist_httpx_assets,
    _persist_port_scan_assets,
    _JWT_RE,
    _AUTH_PATH_HINTS,
    _update_jwt_tokens,
    _update_credentials,
    _update_session_cookies,
    _persist_http_auth_assets,
    _extract_and_persist_assets,
)

# --- Context-pressure tracking + recovery snapshots -------------------------
from mcp_server.scan_engine.envelope.pressure import (
    _check_context_pressure,
    _maybe_write_recovery_snapshot,
)

# --- Steering / duplicate / QA-alert injection ------------------------------
from mcp_server.scan_engine.envelope.qa_injection import (
    _inject_steering_directives,
    _inject_duplicate_warning,
    _inject_qa_alerts_into_envelope,
    _filter_qa_alerts_by_dedup,
)

# --- HTTP-request auth-signal detectors -------------------------------------
from mcp_server.scan_engine.envelope.auth_detect import (
    _is_zero_status,
    _is_auth_attempt,
    _AUTH_PAYLOAD_FIELDS,
    _AUTH_FIELD_RE,
)

# --- Missing-Authorization warning ------------------------------------------
from mcp_server.scan_engine.envelope.auth_warning import (
    _request_carries_auth,
    _inject_missing_auth_warning,
    _AUTH_HEADER_NAMES_LOWER,
    _AUTH_HEADER_PATTERNS,
    _AUTH_QUERY_PATTERNS,
)

# --- Quick log --------------------------------------------------------------
from mcp_server.scan_engine.envelope.quick_log import (
    _build_quick_log_entry,
    _enrich_http_request_entry,
    _mark_tool_error,
    _quick_log_tool,
)


def wrap(tool: str, raw_output: str, context: dict | None = None,
         artifact_raw: str | None = None) -> str:
    """Central entry point: raw tool output in, canonical envelope JSON out.

    Args:
        tool: tool name (e.g. "httpx", "http_request", "kali_sqlmap")
        raw_output: the raw string output from the tool — drives the inline
            summary AND the cost meter, so it must stay bounded.
        context: tool-specific context (url, method, params, etc.)
        artifact_raw: when given, the content STORED as the on-disk artifact
            instead of raw_output. Lets a tool keep a large full body (e.g. a
            50 KB OpenAPI spec) retrievable via session(action='artifact')
            without that body inflating context or the cost estimate — the
            inline envelope and cost still come from the bounded raw_output.

    Returns:
        JSON string of the canonical envelope
    """
    blocked = _check_scan_gate(tool)
    if blocked:
        return blocked

    ctx = context or {}

    # 1. Store raw output as artifact + remember it as the session's most-recent
    #    proof, so a finding filed right after auto-links it (adjudication can
    #    then reuse it instead of forcing a re-run). artifact_raw (when set) is
    #    the full, un-clipped body — stored but never sent inline / costed.
    artifact_id = store_artifact(tool, artifact_raw if artifact_raw is not None else raw_output)
    try:
        from core import session as _sess
        _sess.set_last_artifact(tool, artifact_id)
    except Exception:
        pass

    # 2. Run tool-specific summarizer
    result = summarize(tool, raw_output, ctx)

    # 2a. Record tool invocation with summary (P1 — dedup + recovery)
    is_duplicate = _record_invocation(tool, ctx, result.summary)

    # 2b. Extract and persist known assets (P2 — auto-accumulation)
    _extract_and_persist_assets(tool, result, ctx)

    # 3. Compute server-determined state and planner next-actions
    state = get_state()
    plan = compute_next(tool, state)

    # Merge: planner required/recommended take priority, summarizer adds tool-specific ones
    merged_required = plan["required"] + result.required
    # Cap recommended to 3 — Smith acts on item 1, rarely on 2-3, never on 4+
    merged_recommended = (plan["recommended"] + result.recommended)[:3]
    warnings = plan["warnings"]

    # Cap facts to 5 — full detail lives in the artifact; facts are orientation only
    capped_facts = result.facts[:5]

    # 4. Build envelope — prepend first required action to summary so models see it
    summary = result.summary
    if merged_required:
        # Skip planner "Start scan" directives if session is already running
        actionable = [r for r in merged_required if not r.startswith("Start scan:")]
        if actionable:
            summary += f"\n\nEXECUTE NEXT: {actionable[0]}"
            if len(actionable) > 1:
                summary += f"\n(then {len(actionable) - 1} more required action(s) in next.required)"

    env = Envelope(
        summary=summary,
        facts=capped_facts,
        anomalies=result.anomalies,
        evidence=result.evidence,
        next={"required": merged_required, "recommended": merged_recommended},
        artifact=artifact_id,
        session_state=_compact_state(state),
        warnings=warnings,
    )

    # 5. Enforce budget (profile-aware) — may truncate facts/evidence
    budget = get_tool_budget(tool)
    enforced = enforce_budget(env, budget, artifact_id)

    # 5.5. Steering directives — inject first; return value suppresses QA summary prepend
    directive_injected = _inject_steering_directives(enforced)

    # 5.6. QA alerts — high urgency only; skip summary prepend when directive already owns it
    _inject_qa_alerts_into_envelope(enforced, suppress_summary_prepend=directive_injected)

    # 5.7. Duplicate tool call warning
    if is_duplicate:
        _inject_duplicate_warning(enforced, tool)

    # 5.7b. Missing-Authorization warning. When an http_request returns 401/403
    # and the caller did NOT send an Authorization header, but known_assets has
    # at least one valid JWT, inject a high-pri warning telling Smith to retry
    # with the token. This catches the loop where Smith fires injection payloads
    # at /api/* without auth and accumulates 401s until HIR_AUTH_FAILURE fires.
    if tool == "http_request":
        _inject_missing_auth_warning(enforced, ctx)

    # 5.8. Quick log — fire-and-forget, does not block
    _quick_log_tool(tool, ctx, result.summary, result)

    # 5.9. smith-event capture (training-data Plane A) — fire-and-forget, fail-soft, does not block
    try:
        from mcp_server.scan_engine.smith_events import emit_tool_call
        emit_tool_call(tool, ctx, result, artifact_id)
    except Exception:
        pass

    # 6. Context tracking (P4) — charge, check pressure tiers, periodic snapshot
    json_str = enforced.to_json()
    json_str = _check_context_pressure(enforced, json_str)

    return json_str


__all__ = [
    "wrap",
    "Envelope",
    "store_artifact",
    "enforce_budget",
    "get_tool_budget",
    "get_profile",
    "compute_next",
    "get_state",
    "summarize",
    "_compact_state",
    "_log",
    "_REPO_ROOT",
    "_QA_STATE_FILE",
    "_STEERING_FILE",
    "_RECOVERY_SNAP_FILE",
    "_last_qa_shown_ts",
    "_qa_alert_last_shown",
    "_QA_ALERT_DEDUP_SECONDS",
    "_check_scan_gate",
    "_record_invocation",
    "_persist_httpx_assets",
    "_persist_port_scan_assets",
    "_JWT_RE",
    "_AUTH_PATH_HINTS",
    "_update_jwt_tokens",
    "_update_credentials",
    "_update_session_cookies",
    "_persist_http_auth_assets",
    "_extract_and_persist_assets",
    "_check_context_pressure",
    "_maybe_write_recovery_snapshot",
    "_inject_steering_directives",
    "_inject_duplicate_warning",
    "_inject_qa_alerts_into_envelope",
    "_filter_qa_alerts_by_dedup",
    "_is_zero_status",
    "_is_auth_attempt",
    "_AUTH_PAYLOAD_FIELDS",
    "_AUTH_FIELD_RE",
    "_request_carries_auth",
    "_inject_missing_auth_warning",
    "_AUTH_HEADER_NAMES_LOWER",
    "_AUTH_HEADER_PATTERNS",
    "_AUTH_QUERY_PATTERNS",
    "_build_quick_log_entry",
    "_enrich_http_request_entry",
    "_mark_tool_error",
    "_quick_log_tool",
]
