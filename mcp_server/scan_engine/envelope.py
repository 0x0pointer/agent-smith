"""
Canonical response envelope — every tool returns this exact shape.

The envelope is the only thing that enters the LLM context window.
Raw output lives in artifacts, referenced by artifact_id.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from typing import Any, TYPE_CHECKING

from mcp_server.scan_engine.artifacts import store_artifact
from mcp_server.scan_engine.budget import enforce_budget, get_tool_budget, get_profile
from mcp_server.scan_engine.planner import compute_next
from mcp_server.scan_engine.state import get_state
from mcp_server.scan_engine.summarizers import summarize

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
_QA_STATE_FILE      = os.path.join(_REPO_ROOT, "qa_state.json")
_STEERING_FILE      = os.path.join(_REPO_ROOT, "steering_queue.json")
_RECOVERY_SNAP_FILE = os.path.join(_REPO_ROOT, "recovery_latest.json")
_last_qa_shown_ts: str = ""  # ISO timestamp of last alert batch shown to the model


@dataclass
class Envelope:
    summary: str = ""
    facts: list[str] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    next: dict[str, list[str]] = field(default_factory=lambda: {"required": [], "recommended": []})
    artifact: str | None = None
    session_state: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


def wrap(tool: str, raw_output: str, context: dict | None = None) -> str:
    """Central entry point: raw tool output in, canonical envelope JSON out.

    Args:
        tool: tool name (e.g. "httpx", "http_request", "kali_sqlmap")
        raw_output: the raw string output from the tool
        context: tool-specific context (url, method, params, etc.)

    Returns:
        JSON string of the canonical envelope
    """
    ctx = context or {}

    # 1. Store raw output as artifact
    artifact_id = store_artifact(tool, raw_output)

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
    merged_recommended = plan["recommended"] + result.recommended
    warnings = plan["warnings"]

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
        facts=result.facts,
        anomalies=result.anomalies,
        evidence=result.evidence,
        next={"required": merged_required, "recommended": merged_recommended},
        artifact=artifact_id,
        session_state=state,
        warnings=warnings,
    )

    # 5. Enforce budget (profile-aware) — may truncate facts/evidence
    budget = get_tool_budget(tool)
    enforced = enforce_budget(env, budget, artifact_id)

    # 5.5. QA alerts — inject into warnings (high urgency also prepended to summary)
    _inject_qa_alerts_into_envelope(enforced)

    # 5.6. Steering directives — inject pending QA steering directives
    _inject_steering_directives(enforced)

    # 5.7. Duplicate tool call warning
    if is_duplicate:
        _inject_duplicate_warning(enforced, tool)

    # 5.8. Quick log — fire-and-forget, does not block
    _quick_log_tool(tool, ctx, result.summary)

    # 6. Context tracking (P4) — charge, check pressure tiers, periodic snapshot
    json_str = enforced.to_json()
    json_str = _check_context_pressure(enforced, json_str)

    return json_str


# ---------------------------------------------------------------------------
# P1 — Tool invocation recording
# ---------------------------------------------------------------------------

def _record_invocation(tool: str, ctx: dict, summary: str) -> bool:
    """Record tool invocation with summary for dedup and recovery.

    Returns True if this invocation was a duplicate (same tool+target+options already seen).
    """
    import hashlib
    from core import session as scan_session
    target = ctx.get("url", ctx.get("host", ctx.get("domain", ctx.get("path", ""))))
    hash_input = f"{tool}:{target}:{sorted(ctx.items())}"
    options_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:8]
    current = scan_session.get() or {}
    invocations = current.get("tool_invocations", [])
    is_duplicate = bool(options_hash and any(i.get("options_hash") == options_hash for i in invocations))
    scan_session.add_tool_invocation(tool, target, summary, options_hash)
    return is_duplicate


# ---------------------------------------------------------------------------
# P2 — Known assets extraction
# ---------------------------------------------------------------------------

def _persist_httpx_assets(scan_session: Any, evidence: dict) -> None:
    """Persist tech stack and server assets from httpx evidence."""
    tech = evidence.get("tech", [])
    if tech:
        scan_session.update_known_assets(
            "technologies", tech if isinstance(tech, list) else [tech])
    server = evidence.get("server")
    if server:
        scan_session.update_known_assets("technologies", [server])


def _persist_port_scan_assets(scan_session: Any, evidence: dict, ctx: dict) -> None:
    """Persist ports and hosts from naabu/nmap evidence."""
    ports = evidence.get("ports", [])
    hosts = evidence.get("hosts", [])
    host = hosts[0] if hosts else ctx.get("host", "")
    if ports:
        scan_session.update_known_assets(
            "ports", [{"host": host, "port": p} for p in ports])
    if hosts:
        scan_session.update_known_assets("domains", hosts)


def _extract_and_persist_assets(tool: str, result: Any, ctx: dict) -> None:
    """Extract discovered assets from summarizer result and persist to session."""
    from core import session as scan_session
    evidence = result.evidence

    if tool == "httpx":
        _persist_httpx_assets(scan_session, evidence)
    elif tool in ("naabu", "nmap"):
        _persist_port_scan_assets(scan_session, evidence, ctx)
    elif tool == "subfinder":
        subs = evidence.get("subdomains", [])
        if subs:
            scan_session.update_known_assets("domains", subs[:50])
    elif tool == "spider":
        endpoints = evidence.get("endpoints", [])
        if endpoints:
            scan_session.update_known_assets(
                "endpoints",
                [ep.get("path", "") for ep in endpoints if ep.get("path")])


# ---------------------------------------------------------------------------
# P4 — Context pressure tracking (tiered)
# ---------------------------------------------------------------------------

def _check_context_pressure(env: Envelope, json_str: str) -> str:
    """Track context usage and inject tiered warnings as pressure grows.

    Tier 1 (>70%): advisory — good time to call recovery.
    Tier 2 (>80%): urgent — EXECUTE NOW directive with exact call.
    Tier 3 (>90%): auto-inject full recovery brief into session_state; no model action needed.
    Also writes a periodic snapshot to recovery_latest.json every 10 tool calls.
    """
    from core import session as scan_session
    scan_session.charge_context(len(json_str))
    profile = get_profile()
    pressure = scan_session.get_context_pressure(profile)

    _maybe_write_recovery_snapshot(scan_session)

    if pressure > 0.9:
        pct = int(pressure * 100)
        env.warnings.append(
            f"CONTEXT_WARNING: ~{pct}% of context budget used — compaction imminent. "
            f"Recovery brief auto-injected into session_state.recovery_brief. "
            f"EXECUTE NOW: session(action='recovery') for a fresh copy."
        )
        try:
            from mcp_server.session_tools import _do_recovery
            import json as _json
            env.session_state["recovery_brief"] = _json.loads(_do_recovery())
        except Exception:
            pass
        return env.to_json()

    if pressure > 0.8:
        pct = int(pressure * 100)
        env.warnings.append(
            f"CONTEXT_WARNING: ~{pct}% of context budget used. "
            f"EXECUTE NOW: session(action='recovery') — all state is safe on disk. "
            f"After reading the brief, continue from its EXECUTE_NOW field."
        )
        return env.to_json()

    if pressure > 0.7:
        pct = int(pressure * 100)
        env.warnings.append(
            f"CONTEXT_WARNING: ~{pct}% of context budget used. "
            f"Good time to call session(action='recovery') to get a compact state snapshot."
        )
        return env.to_json()

    return json_str


def _maybe_write_recovery_snapshot(scan_session: Any) -> None:
    """Write recovery_latest.json every 10 tool invocations as a passive fallback."""
    try:
        current = scan_session.get() or {}
        if current.get("status") != "running":
            return
        seq = len(current.get("tool_invocations", []))
        if seq > 0 and seq % 10 == 0:
            from mcp_server.session_tools import _do_recovery
            import pathlib
            pathlib.Path(_RECOVERY_SNAP_FILE).write_text(_do_recovery(), encoding="utf-8")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# P5.6 — Steering directive injection
# ---------------------------------------------------------------------------

def _inject_steering_directives(env: Envelope) -> None:
    """Inject pending QA steering directives into the envelope.

    Pending directives are injected into warnings. High-priority directives are
    also prepended to the summary so the model sees them immediately.
    Each directive is marked injected after surfacing so the audit trail is accurate.
    """
    try:
        from core.steering import steering_queue
        pending = steering_queue.get_pending()
        if not pending:
            return
        for directive in pending:
            env.warnings.append(f"[QA STEER {directive.priority.upper()}] {directive.message}")
            if directive.priority == "high":
                env.summary = (
                    f"⚠ QA STEERING: {directive.message}\n"
                    f"(Act on this before continuing.)\n\n"
                    + env.summary
                )
            steering_queue.mark_injected(directive.id)
    except Exception:
        pass  # steering failures must never break tool dispatch


def _inject_duplicate_warning(env: Envelope, tool: str) -> None:
    """Inject a recovery reminder when the same tool+params were already run."""
    from core import session as scan_session
    try:
        invocations = (scan_session.get() or {}).get("tool_invocations", [])
        seq = next(
            (i.get("seq") for i in reversed(invocations) if i.get("tool") == tool),
            "?",
        )
        env.warnings.append(
            f"DUPLICATE_TOOL_CALL: {tool} was already run with these exact parameters "
            f"(invocation #{seq}). You may be post-compaction. "
            "Call session(action='recovery') to verify where you left off."
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# P5 — QA alert injection
# ---------------------------------------------------------------------------

def _inject_qa_alerts_into_envelope(env: Envelope) -> None:
    """Read qa_state.json and inject new alerts into the envelope.

    High urgency  → appended to env.warnings AND prepended to env.summary.
                    The model sees it whether it reads summary or warnings.
    Medium urgency → env.warnings only (dashboard-visible, not summary-loud).
    Low urgency   → skipped entirely (dashboard-only, not model-facing).

    Uses a module-level timestamp so each alert is shown exactly once across
    consecutive tool calls, not repeated on every response.
    """
    global _last_qa_shown_ts
    try:
        if not os.path.isfile(_QA_STATE_FILE):
            return
        state = json.loads(open(_QA_STATE_FILE).read())
        ts = state.get("ts", "")
        if not ts or ts <= _last_qa_shown_ts:
            return
        alerts = [a for a in state.get("alerts", []) if a.get("urgency") in ("high", "medium")]
        if not alerts:
            _last_qa_shown_ts = ts
            return
        _last_qa_shown_ts = ts

        # Structured entries into warnings[]
        for a in alerts:
            env.warnings.append(f"[QA {a['urgency'].upper()}] {a['message']}")

        # High urgency: also surface in summary so no model misses it
        high = [a for a in alerts if a.get("urgency") == "high"]
        if high:
            alert_text = " | ".join(a["message"] for a in high)
            env.summary = (
                f"⚠ QA ALERT: {alert_text}\n"
                f"(Address before continuing or call session(action='status') to review.)\n\n"
                + env.summary
            )
    except Exception:
        pass  # never break tool dispatch


# ---------------------------------------------------------------------------
# P6 — Quick log
# ---------------------------------------------------------------------------

def _quick_log_tool(tool: str, ctx: dict, summarizer_summary: str) -> None:
    """Fire-and-forget quick_log entry. Called from within an async tool handler
    so asyncio.get_running_loop() is always available.

    Uses the summarizer's summary (before QA injection) so the log reflects
    what the tool actually found, not the alert state.
    """
    import asyncio
    import re as _re
    try:
        from core.quick_log import quick_log as _qlog
        target = ctx.get("url", ctx.get("host", ctx.get("domain", ctx.get("path", ""))))
        if tool == "spider":
            m = _re.search(r'(\d+)\s+unique\s+endpoint', summarizer_summary, _re.IGNORECASE)
            entry: dict = {
                "type": "SPIDER",
                "target": target,
                "endpoints_found": int(m.group(1)) if m else 0,
            }
        else:
            entry = {"type": "TOOL", "name": tool, "target": target}
        loop = asyncio.get_running_loop()
        loop.create_task(_qlog.append(entry))
    except Exception:
        pass  # quick_log failures must never affect tool dispatch
