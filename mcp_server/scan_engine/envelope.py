"""
Canonical response envelope — every tool returns this exact shape.

The envelope is the only thing that enters the LLM context window.
Raw output lives in artifacts, referenced by artifact_id.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any

from mcp_server.scan_engine.artifacts import store_artifact
from mcp_server.scan_engine.budget import enforce_budget, get_tool_budget, get_profile
from mcp_server.scan_engine.planner import compute_next
from mcp_server.scan_engine.state import get_state
from mcp_server.scan_engine.summarizers import summarize


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

def _extract_and_persist_assets(tool: str, result: Any, ctx: dict) -> None:
    """Extract discovered assets from summarizer result and persist to session."""
    from core import session as scan_session
    evidence = result.evidence

    if tool == "httpx":
        tech = evidence.get("tech", [])
        if tech:
            scan_session.update_known_assets(
                "technologies", tech if isinstance(tech, list) else [tech])
        server = evidence.get("server")
        if server:
            scan_session.update_known_assets("technologies", [server])
    elif tool in ("naabu", "nmap"):
        ports = evidence.get("ports", [])
        hosts = evidence.get("hosts", [])
        host = hosts[0] if hosts else ctx.get("host", "")
        if ports:
            scan_session.update_known_assets(
                "ports", [{"host": host, "port": p} for p in ports])
        if hosts:
            scan_session.update_known_assets("domains", hosts)
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
