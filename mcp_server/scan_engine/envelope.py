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
from mcp_server.scan_engine.budget import enforce_budget, TOOL_BUDGETS
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

    # 3. Compute server-determined state and planner next-actions
    state = get_state()
    plan = compute_next(tool, state)

    # Merge: planner required/recommended take priority, summarizer adds tool-specific ones
    merged_required = plan["required"] + result.required
    merged_recommended = plan["recommended"] + result.recommended
    warnings = plan["warnings"]

    # 4. Build envelope
    env = Envelope(
        summary=result.summary,
        facts=result.facts,
        anomalies=result.anomalies,
        evidence=result.evidence,
        next={"required": merged_required, "recommended": merged_recommended},
        artifact=artifact_id,
        session_state=state,
        warnings=warnings,
    )

    # 5. Enforce budget — may truncate facts/evidence
    budget = TOOL_BUDGETS.get(tool, TOOL_BUDGETS["_default"])
    enforced = enforce_budget(env, budget, artifact_id)

    return enforced.to_json()
