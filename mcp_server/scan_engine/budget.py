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
        "enforce_budget": True,
        # enforce_coverage: hard-gate completion on the coverage matrix (the matrix
        # is the deliverable). ON for full — a capable cloud model can actually work
        # a 700-cell matrix. OFF for medium/small: a local model has no in-loop
        # injection-sweep tooling to honestly close hundreds of cells, so a hard
        # floor just forces gaming (false tested_clean on 500s) and then stalls at
        # HIR_NO_PROGRESS — restoring the V1.0.2 "exploit → findings → complete"
        # behavior. Flip medium→True once the automated endpoint_sweep lands and
        # cells become honestly closeable on local. The closure-INTEGRITY guards
        # (artifact-backed, auth-block, suspect-N/A) stay on for every profile —
        # this knob only governs the completeness gates that demand MORE work.
        "enforce_coverage": True,
        "budget_multiplier": 2.0,      # generous but bounded — facts/evidence won't explode
        "context_budget_chars": 400_000,  # ~100K tokens; warn at 80% (320K) before compaction fires
        "recovery_cells_shown": None,  # show all cells in recovery
        "execute_next_in_summary": True,
        # condensed_directives: serialize completion blockers one-at-a-time and
        # emit digest (not full) versions of the big instruction blocks. OFF for
        # full — large-context models absorb the whole wall in one pass and a
        # batch is fewer round-trips for them.
        "condensed_directives": False,
        # thorough_min_passes: how many quality-clean analysis passes a thorough
        # scan must complete. Capable models do the full 3; small local models
        # cannot hold 3 deep passes in a 16-32K window, so they do fewer.
        "thorough_min_passes": 3,
        # next_batch_size: how many cells the focused step-by-step testing loop
        # hands the agent at once (report(action='coverage', type='next_batch')).
        "next_batch_size": 10,
    },
    "medium": {
        "enforce_budget": True,
        # SM-5: with the server-side sweep (report coverage type='sweep') a medium
        # model can now honestly close injection cells without hand-running every
        # probe, so coverage is a hard completion gate again. `small` stays
        # advisory until the sweep is proven on a real 27B run (a hard gate on the
        # smallest window risks the "spun on a 700-cell matrix and stalled" failure).
        "enforce_coverage": True,
        "budget_multiplier": 1.0,    # base budgets as-is
        "context_budget_chars": 160_000,  # ~40K tokens
        "recovery_cells_shown": 10,
        "execute_next_in_summary": True,
        "condensed_directives": True,
        "thorough_min_passes": 2,
        "next_batch_size": 5,
    },
    "small": {
        "enforce_budget": True,
        "enforce_coverage": False,   # local model — coverage advisory, not a completion gate (see "full")
        "budget_multiplier": 0.5,    # half budgets
        "context_budget_chars": 64_000,  # ~16K tokens
        "recovery_cells_shown": 3,
        "execute_next_in_summary": True,
        "condensed_directives": True,
        "thorough_min_passes": 1,
        "next_batch_size": 3,
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


def _retrieve_artifact_hint(artifact_id: str, *, dropped_facts: int = 0,
                            dropped_evidence_keys: int = 0,
                            envelope_oversize: bool = False) -> str:
    """Build a self-evidencing 'how to get the full output' instruction.

    Smaller models (e.g. Qwen3.6-35B-A3B) treat short "see artifact X"
    warnings as background noise and retry the same command instead of
    retrieving the artifact. The user observed Smith looping 8+ times
    trying variations of the same `python3 -c '...'` because each call
    hit the 5000-char budget and Smith never recognised the artifact
    mechanism. Embedding the exact next MCP tool call inline — with
    concrete option values — gives the model an explicit pattern to
    match on rather than relying on tool-system knowledge that isn't
    reinforced in-context.

    The mode= hint follows progressive disclosure: try grep with a
    relevant pattern first (cheapest), fall back to head/tail, last
    resort full. This matches how a human triages a truncated log.
    """
    reasons = []
    if dropped_facts:
        reasons.append(f"{dropped_facts} fact(s) dropped")
    if dropped_evidence_keys:
        reasons.append(f"{dropped_evidence_keys} evidence key(s) dropped")
    if envelope_oversize:
        reasons.append("envelope exceeded char budget")
    reason_str = ", ".join(reasons) if reasons else "output truncated"
    return (
        f"OUTPUT TRUNCATED ({reason_str}). "
        f"EXECUTE NOW to get the full output: "
        f"session(action='artifact', options={{id: '{artifact_id}', mode: 'full'}}). "
        f"Or grep just what you need: "
        f"session(action='artifact', options={{id: '{artifact_id}', mode: 'grep', pattern: '<regex>'}}). "
        f"DO NOT re-run the same command — the artifact already has the complete output."
    )


def enforce_budget(env: "Envelope", budget: ToolBudget, artifact_id: str) -> "Envelope":
    """Enforce character budget on an envelope. Mutates and returns env."""
    import json

    # Track what got dropped so the final warning can summarise all of
    # it at once, instead of Smith having to correlate three separate
    # warning lines to understand "there's an artifact, here's how to read it".
    dropped_facts = 0
    dropped_evidence_keys = 0
    envelope_oversize = False

    # Truncate facts list
    if len(env.facts) > budget.max_facts:
        dropped_facts = len(env.facts) - budget.max_facts
        env.facts = env.facts[:budget.max_facts]

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
        dropped_evidence_keys = len(set(env.evidence.keys()) - set(trimmed.keys()))
        env.evidence = trimmed

    # Final envelope size check
    serialized = env.to_json()
    if len(serialized) > budget.max_chars:
        envelope_oversize = True
        # Emergency truncation: cut facts from the end until we fit
        while len(env.to_json()) > budget.max_chars and env.facts:
            env.facts.pop()
        if len(env.to_json()) > budget.max_chars:
            # Last resort: truncate summary
            overage = len(env.to_json()) - budget.max_chars
            env.summary = env.summary[:max(50, len(env.summary) - overage)] + "..."

    # One consolidated, fully-actionable warning instead of 3 cryptic
    # ones. Smaller models match on the explicit "EXECUTE NOW: session(...)"
    # pattern far more reliably than on "artifact=<id>" hints alone.
    if dropped_facts or dropped_evidence_keys or envelope_oversize:
        env.warnings.append(_retrieve_artifact_hint(
            artifact_id,
            dropped_facts=dropped_facts,
            dropped_evidence_keys=dropped_evidence_keys,
            envelope_oversize=envelope_oversize,
        ))

    return env
