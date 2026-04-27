"""
Budget enforcement — model-profile-aware character caps per tool.

Each tool has a base budget. Model profiles scale these budgets:
- full: no enforcement (large-context models like Claude)
- medium: base budgets as-is (64K context models)
- small: half budgets (16-32K context models)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp_server.scan_engine.envelope import Envelope


# ---------------------------------------------------------------------------
# Model profiles
# ---------------------------------------------------------------------------

MODEL_PROFILES: dict[str, dict] = {
    "full": {
        "enforce_budget": False,     # No output limits — go full in
        "budget_multiplier": 1.0,    # unused when enforce_budget=False
        "context_budget_chars": None,  # no context tracking limit
        "recovery_cells_shown": None,  # show all cells in recovery
        "execute_next_in_summary": True,  # still useful, harmless for large models
    },
    "medium": {
        "enforce_budget": True,
        "budget_multiplier": 1.0,    # base budgets as-is
        "context_budget_chars": 160_000,  # ~40K tokens
        "recovery_cells_shown": 10,
        "execute_next_in_summary": True,
    },
    "small": {
        "enforce_budget": True,
        "budget_multiplier": 0.5,    # half budgets
        "context_budget_chars": 64_000,  # ~16K tokens
        "recovery_cells_shown": 3,
        "execute_next_in_summary": True,
    },
}


def get_profile(profile_name: str | None = None) -> dict:
    """Get model profile. Reads from session if not specified."""
    if profile_name is None:
        from core import session as scan_session
        current = scan_session.get()
        profile_name = (current or {}).get("model_profile", "full")
    return MODEL_PROFILES.get(profile_name, MODEL_PROFILES["full"])


# ---------------------------------------------------------------------------
# Per-tool budgets (base values — scaled by profile multiplier)
# ---------------------------------------------------------------------------

@dataclass
class ToolBudget:
    max_chars: int
    max_facts: int = 15
    max_evidence_chars: int = 2000


# Base budgets — tuned for medium profile (current values).
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


def get_tool_budget(tool: str) -> ToolBudget:
    """Get profile-scaled budget for a tool."""
    profile = get_profile()
    base = TOOL_BUDGETS.get(tool, TOOL_BUDGETS["_default"])
    if not profile.get("enforce_budget", True):
        # Full profile: very generous limits (effectively no enforcement)
        return ToolBudget(
            max_chars=base.max_chars * 10,
            max_facts=base.max_facts * 5,
            max_evidence_chars=base.max_evidence_chars * 5,
        )
    mult = profile.get("budget_multiplier", 1.0)
    return ToolBudget(
        max_chars=max(500, int(base.max_chars * mult)),
        max_facts=max(3, int(base.max_facts * mult)),
        max_evidence_chars=max(200, int(base.max_evidence_chars * mult)),
    )


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
