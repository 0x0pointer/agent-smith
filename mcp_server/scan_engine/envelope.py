"""
Canonical response envelope — every tool returns this exact shape.

The envelope is the only thing that enters the LLM context window.
Raw output lives in artifacts, referenced by artifact_id.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from typing import Any

from mcp_server.scan_engine.artifacts import store_artifact
from mcp_server.scan_engine.budget import enforce_budget, get_tool_budget, get_profile
from mcp_server.scan_engine.planner import compute_next
from mcp_server.scan_engine.state import get_state
from mcp_server.scan_engine.summarizers import summarize

_QA_STATE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "qa_state.json"
)
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
    _record_invocation(tool, ctx, result.summary)

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

    # 5.6. Quick log — fire-and-forget, does not block
    _quick_log_tool(tool, ctx, result.summary)

    # 6. Context tracking (P4) — charge and check pressure
    json_str = enforced.to_json()
    json_str = _check_context_pressure(enforced, json_str)

    return json_str


# ---------------------------------------------------------------------------
# P1 — Tool invocation recording
# ---------------------------------------------------------------------------

def _record_invocation(tool: str, ctx: dict, summary: str) -> None:
    """Record tool invocation with summary for dedup and recovery."""
    import hashlib
    from core import session as scan_session
    target = ctx.get("url", ctx.get("host", ctx.get("domain", ctx.get("path", ""))))
    hash_input = f"{tool}:{target}:{sorted(ctx.items())}"
    options_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:8]
    scan_session.add_tool_invocation(tool, target, summary, options_hash)


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
# P4 — Context pressure tracking
# ---------------------------------------------------------------------------

def _check_context_pressure(env: Envelope, json_str: str) -> str:
    """Track context usage and inject warning if pressure exceeds 80%."""
    from core import session as scan_session
    scan_session.charge_context(len(json_str))
    profile = get_profile()
    pressure = scan_session.get_context_pressure(profile)
    if pressure > 0.8:
        pct = int(pressure * 100)
        env.warnings.append(
            f"CONTEXT_WARNING: ~{pct}% of context budget used. "
            f"Consider calling session(action='recovery') to compact."
        )
        return env.to_json()
    return json_str


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
