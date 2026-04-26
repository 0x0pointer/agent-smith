"""
Budget enforcement — hard character caps per tool, enforced centrally.

Each tool has a max_chars budget for the total serialized envelope.
If the envelope exceeds the budget, facts and evidence are truncated
(summary is always preserved) and a warning is added.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp_server.scan_engine.envelope import Envelope


@dataclass
class ToolBudget:
    max_chars: int
    max_facts: int = 15
    max_evidence_chars: int = 2000


# Per-tool budgets. Tuned so that even the largest response
# fits comfortably in a 32K context alongside CLAUDE.md + tool schemas.
TOOL_BUDGETS: dict[str, ToolBudget] = {
    "httpx":         ToolBudget(max_chars=3000, max_facts=10, max_evidence_chars=1500),
    "http_request":  ToolBudget(max_chars=4000, max_facts=12, max_evidence_chars=2000),
    "kali_sqlmap":   ToolBudget(max_chars=4000, max_facts=15, max_evidence_chars=2000),
    "kali":          ToolBudget(max_chars=5000, max_facts=15, max_evidence_chars=2500),
    "naabu":         ToolBudget(max_chars=2500, max_facts=10, max_evidence_chars=1000),
    "nmap":          ToolBudget(max_chars=3000, max_facts=10, max_evidence_chars=1500),
    "subfinder":     ToolBudget(max_chars=2500, max_facts=20, max_evidence_chars=1000),
    "nuclei":        ToolBudget(max_chars=4000, max_facts=20, max_evidence_chars=2000),
    "spider":        ToolBudget(max_chars=4000, max_facts=30, max_evidence_chars=2000),
    "ffuf":          ToolBudget(max_chars=4000, max_facts=25, max_evidence_chars=2000),
    "_default":      ToolBudget(max_chars=5000, max_facts=15, max_evidence_chars=2500),
}


def enforce_budget(env: "Envelope", budget: ToolBudget, artifact_id: str) -> "Envelope":
    """Enforce character budget on an envelope. Mutates and returns env."""
    import json

    # Truncate facts list
    if len(env.facts) > budget.max_facts:
        dropped = len(env.facts) - budget.max_facts
        env.facts = env.facts[:budget.max_facts]
        env.warnings.append(f"Truncated {dropped} fact(s) — retrieve full output: artifact={artifact_id}")

    # Truncate evidence
    ev_str = json.dumps(env.evidence)
    if len(ev_str) > budget.max_evidence_chars:
        # Keep only the first N chars worth of evidence keys
        trimmed: dict = {}
        current = 2  # {}
        for k, v in env.evidence.items():
            entry = json.dumps({k: v})
            if current + len(entry) > budget.max_evidence_chars:
                break
            trimmed[k] = v
            current += len(entry)
        dropped_keys = set(env.evidence.keys()) - set(trimmed.keys())
        env.evidence = trimmed
        if dropped_keys:
            env.warnings.append(
                f"Evidence truncated ({len(dropped_keys)} key(s) dropped) — "
                f"artifact={artifact_id}"
            )

    # Final envelope size check
    serialized = env.to_json()
    if len(serialized) > budget.max_chars:
        # Emergency truncation: cut facts from the end until we fit
        while len(env.to_json()) > budget.max_chars and env.facts:
            env.facts.pop()
        if len(env.to_json()) > budget.max_chars:
            # Last resort: truncate summary
            overage = len(env.to_json()) - budget.max_chars
            env.summary = env.summary[:max(50, len(env.summary) - overage)] + "..."
        env.warnings.append(f"Envelope exceeded {budget.max_chars} char budget — content truncated")

    return env
