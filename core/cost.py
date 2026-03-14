"""
Cost tracker
============
Estimates USD cost from tool output sizes.

Why tool outputs drive cost
---------------------------
Every tool result sent back to Claude becomes part of the conversation history
and is re-read as INPUT tokens on every subsequent API call. A 5,000-token
tool output that stays in context for 10 more turns costs 50,000 input tokens —
so keeping outputs small is the single biggest lever for cost reduction.

Estimate method
---------------
  output_chars / 4  →  tokens   (1 token ≈ 4 ASCII chars; security output is dense)
  tokens * $3.00/M  →  USD cost (claude-sonnet-4-6 input pricing)

Two-phase recording
-------------------
  call_id = start(tool_name)   # written immediately → dashboard shows "running"
  finish(call_id, output)      # updated on completion → dashboard shows tokens + cost

Output file
-----------
  session_cost.json  (written on every start/finish, served by core/api_server.py at GET /api/cost)
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

# ── Pricing (claude-sonnet-4-6) ──────────────────────────────────────────────
MODEL             = "claude-sonnet-4-6"
INPUT_PRICE_PER_M = 3.00    # USD per million input tokens
CHARS_PER_TOKEN   = 4       # 1 token ≈ 4 ASCII chars for security tool output

_REPO_ROOT = Path(__file__).parent.parent
_COST_FILE = _REPO_ROOT / "session_cost.json"

# ── In-memory session state ───────────────────────────────────────────────────
_session_start = datetime.now(timezone.utc).isoformat()
_calls: list[dict] = []


# ── Public API ────────────────────────────────────────────────────────────────

def start(tool_name: str) -> str:
    """
    Record that a tool has started. Flushes immediately so the dashboard
    shows the call as 'running' before the tool returns.
    Returns a call_id to pass to finish().
    """
    call_id = str(uuid.uuid4())
    _calls.append({
        "id":        call_id,
        "tool":      tool_name,
        "status":    "running",
        "chars":     0,
        "tokens":    0,
        "started":   datetime.now(timezone.utc).isoformat(),
        "finished":  None,
    })
    _flush()
    return call_id


def finish(call_id: str, output: str) -> None:
    """
    Update a running call with its actual output size and mark it done.
    Flushes so the dashboard picks up the final token count immediately.
    """
    tokens = max(1, len(output) // CHARS_PER_TOKEN)
    for call in _calls:
        if call["id"] == call_id:
            call["status"]   = "done"
            call["chars"]    = len(output)
            call["tokens"]   = tokens
            call["finished"] = datetime.now(timezone.utc).isoformat()
            break
    _flush()


def get_summary() -> dict:
    done_calls   = [c for c in _calls if c["status"] == "done"]
    running      = [c for c in _calls if c["status"] == "running"]
    n            = len(done_calls)
    raw_tokens   = sum(c["tokens"] for c in done_calls)
    # Each call's output stays in context and is re-read as input on every
    # subsequent turn.  Call at index i (0-based) out of n total has been
    # included in (n - i) API requests, so it contributes tokens * (n - i).
    weighted_tokens = sum(c["tokens"] * (n - i) for i, c in enumerate(done_calls))
    est_usd      = round(weighted_tokens / 1_000_000 * INPUT_PRICE_PER_M, 6)
    return {
        "model":               MODEL,
        "input_price_per_M":   INPUT_PRICE_PER_M,
        "session_started":     _session_start,
        "tool_calls_total":    len(_calls),
        "tool_calls_running":  len(running),
        "tool_calls_done":     len(done_calls),
        "total_output_tokens": raw_tokens,
        "total_weighted_tokens": weighted_tokens,
        "est_cost_usd":        est_usd,
        "note": (
            "Cost accounts for compounding: each tool output is re-read as "
            "input tokens on every subsequent turn."
        ),
        "breakdown": _calls,
    }


# ── Internal ──────────────────────────────────────────────────────────────────

def _flush() -> None:
    _COST_FILE.write_text(json.dumps(get_summary(), indent=2))
