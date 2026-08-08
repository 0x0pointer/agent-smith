#!/usr/bin/env python3
"""
Passive decision harvester (training-data-plan.md §3 — the "why", captured WITHOUT influencing the scan).

Smith already narrates its reasoning (text + thinking) before each tool call, and that narration is
recorded in its transcript. This reads the transcript + the emitted `action` events, correlates the
reasoning to the actions it preceded, and writes schema-valid `decision` events to a SEPARATE stream
(`<engagement>.decisions.jsonl`). Fully offline — it never runs during a scan and never prompts the
model, so it cannot change the trajectories it captures.

Honesty rules:
  - The reasoning is Smith's ACTUAL words (verbatim in `explanation`), never invented.
  - A harvested decision does NOT claim to be a causal parent of the action (it was recorded LATE):
    it carries `explains: [action_id]` — a reference edge (like `supersedes`), NOT `caused_by` — so
    the execution-causality DAG stays clean and the §3.1 "late-arriving event keeps its occurred_at,
    gets a later sequence" rule holds. occurred_at = the reasoning's transcript time (genuinely
    pre-action); recorded_at = harvest time.
  - Structured fields (goal/hypothesis/confidence/…) are `not_captured` — we captured raw narration,
    not parsed structure. An offline extractor can derive structure later as a tagged, derived view.
  - An action whose transcript reasoning is empty, or whose tool doesn't match (correlation drift),
    is left UNATTRIBUTED — never back-filled.

Usage:
  python training-data/eventstore/harvest_decisions.py --transcript <t.jsonl> --events <e.jsonl> [--out <o.jsonl>]
  python training-data/eventstore/harvest_decisions.py --latest      # newest transcript + newest event stream
"""
import argparse
import hashlib
import json
import pathlib
import re
import secrets
import time
from datetime import datetime, timezone

_SCHEMA_VERSION = "smith-event/1.0"
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_WRAP_ROUTED = {"scan", "http", "kali"}  # MCP tools that flow through wrap() and emit `action` events
_MAX_EXPLANATION = 2000


def _ulid() -> str:
    n = (int(time.time() * 1000) << 80) | secrets.randbits(80)
    out = []
    for _ in range(26):
        out.append(_CROCKFORD[n & 31])
        n >>= 5
    return "".join(reversed(out))


def _inner_tool(mcp_name: str, tool_input: dict) -> str | None:
    """Map an MCP tool_use to the inner tool the emitter records in action.tool, or None if the call
    doesn't flow through wrap() (session/report/etc. emit no action event)."""
    seg = re.split(r"__|_", mcp_name or "")[-1].lower()
    if seg == "scan":
        return str((tool_input or {}).get("tool") or "").lower() or None
    if seg == "http":
        return "http_request"
    if seg == "kali":
        return "kali"
    return None


def _block_reasoning(b: dict) -> str | None:
    """Reasoning text of a `thinking`/`text` content block, else None."""
    if b.get("type") == "thinking":
        return (b.get("thinking") or b.get("text") or "").strip() or None
    if b.get("type") == "text":
        return (b.get("text") or "").strip() or None
    return None


def _content_blocks(entry: dict):
    """Yield the content blocks of an assistant message (normalizing string content to a text block)."""
    msg = entry.get("message") if isinstance(entry.get("message"), dict) else {}
    content = msg.get("content")
    if isinstance(content, str):
        if msg.get("role") == "assistant" and content.strip():
            yield {"type": "text", "text": content}
    elif isinstance(content, list):
        for b in content:
            if isinstance(b, dict):
                yield b


def parse_transcript(path: pathlib.Path) -> list[dict]:
    """Ordered wrap-routed tool calls with the reasoning (text+thinking) that preceded each."""
    calls: list[dict] = []
    buf: list[str] = []
    for line in path.read_text(errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        ts = entry.get("timestamp")
        for b in _content_blocks(entry):
            reasoning = _block_reasoning(b)
            if reasoning:
                buf.append(reasoning)
            elif b.get("type") == "tool_use":
                inner = _inner_tool(b.get("name", ""), b.get("input") or {})
                if inner:
                    calls.append({"reasoning": "\n".join(buf).strip(), "inner_tool": inner, "ts": ts})
                buf = []  # reasoning belongs to the immediately-following tool call
    return calls


def load_actions(path: pathlib.Path) -> tuple[list[dict], int]:
    """The `action` events in order + the max sequence seen (so harvested decisions sort after)."""
    actions, max_seq = [], 0
    for line in path.read_text(errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        max_seq = max(max_seq, ev.get("sequence", 0))
        if ev.get("event_type") == "action":
            actions.append(ev)
    return actions, max_seq


def correlate(calls: list[dict], actions: list[dict]) -> tuple[list[tuple], int]:
    """Ordinal match (wrap-routed transcript call i ↔ action i), validated by tool name. A mismatch
    or a run past the end leaves the action unattributed (reasoning=None)."""
    pairs, drift = [], 0
    for i, act in enumerate(actions):
        c = calls[i] if i < len(calls) else None
        if c is not None and c["inner_tool"] == act.get("action", {}).get("tool"):
            pairs.append((act, c))
        else:
            if c is not None:
                drift += 1
            pairs.append((act, None))
    return pairs, drift


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_decision(action: dict, reasoning: str, ts, engagement: str, seq: int) -> dict:
    """A schema-valid `decision` that `explains` the action (reference edge, NOT caused_by)."""
    not_captured = {"value": None, "capture_mode": "not_captured"}
    return {
        "event_id": _ulid(), "engagement_id": engagement, "event_type": "decision", "sequence": seq,
        "occurred_at": ts or _now_iso(), "recorded_at": _now_iso(), "schema_version": _SCHEMA_VERSION,
        "explains": [action["event_id"]],                       # reference edge, not causal
        "correlation_id": action.get("correlation_id") or action["event_id"],
        "decision": {
            "goal": "", "chosen_tool": action.get("action", {}).get("tool", ""),
            "operation": action.get("action", {}).get("operation", "call"),
            "alternatives_considered": not_captured, "expected_signals": not_captured,
            "confidence": not_captured, "stop_condition": not_captured,
            "explanation": reasoning[:_MAX_EXPLANATION],        # Smith's ACTUAL words, verbatim
            "provenance": {"proposal_source": "model", "teacher_origin": "open_weight"},
            "capture_method": "transcript_harvest",             # marker: passive, offline, genuine
        },
    }


def harvest(transcript: pathlib.Path, events: pathlib.Path, out: pathlib.Path) -> dict:
    calls = parse_transcript(transcript)
    actions, max_seq = load_actions(events)
    if not actions:
        return {"actions": 0, "harvested": 0, "note": "no action events"}
    engagement = actions[0].get("engagement_id", events.stem)
    pairs, drift = correlate(calls, actions)
    harvested, no_reasoning = [], 0
    seq = max_seq
    for act, c in pairs:
        if c is None or not c["reasoning"]:
            if c is not None and not c["reasoning"]:
                no_reasoning += 1
            continue
        seq += 1
        harvested.append(build_decision(act, c["reasoning"], c["ts"], engagement, seq))
    out.write_text("".join(json.dumps(d, ensure_ascii=False) + "\n" for d in harvested))
    return {"actions": len(actions), "transcript_wrap_calls": len(calls),
            "harvested": len(harvested), "unattributed_no_reasoning": no_reasoning,
            "unattributed_drift_or_unmatched": len(actions) - len(harvested) - no_reasoning,
            "drift": drift, "out": str(out)}


def _latest(pattern_dir: pathlib.Path, glob: str, exclude: str = "") -> pathlib.Path | None:
    files = [f for f in pattern_dir.glob(glob) if exclude not in f.name]
    return max(files, key=lambda f: f.stat().st_mtime) if files else None


def _epoch(iso) -> float | None:
    try:
        return datetime.fromisoformat(str(iso)).timestamp()
    except (TypeError, ValueError):
        return None


def auto_transcript(events_path: pathlib.Path, tdir: pathlib.Path) -> pathlib.Path | None:
    """Pick the transcript whose wrap-call timestamps best overlap this event stream's action window —
    robust engagement↔transcript mapping (no dependence on 'newest' or a stored session id)."""
    actions, _ = load_actions(events_path)
    times = [t for t in (_epoch(a.get("occurred_at")) for a in actions) if t]
    if not times:
        return None
    lo, hi = min(times), max(times)
    best, best_n = None, 0
    for f in tdir.glob("*.jsonl"):
        try:
            if f.stat().st_mtime < lo - 3600:  # cheap prefilter: inactive before the scan -> skip parse
                continue
        except OSError:
            continue
        n = sum(1 for c in parse_transcript(f)
                if (ts := _epoch(c.get("ts"))) is not None and lo - 30 <= ts <= hi + 30)
        if n > best_n:
            best, best_n = f, n
    return best


def main():
    ap = argparse.ArgumentParser(description="Passively harvest decisions from a Smith transcript.")
    ap.add_argument("--transcript")
    ap.add_argument("--events")
    ap.add_argument("--out")
    ap.add_argument("--latest", action="store_true", help="use the newest event stream")
    a = ap.parse_args()
    repo = pathlib.Path(__file__).resolve().parents[2]
    tdir = pathlib.Path.home() / ".claude" / "projects" / "-Users-gibson-agent-smith"
    if a.latest and not a.events:
        a.events = str(_latest(repo / "logs" / "smith-events", "*.jsonl", exclude="decisions") or "")
    if not a.events:
        ap.error("need --events (or --latest)")
    events = pathlib.Path(a.events)
    # Default: auto-select the transcript by timestamp overlap (robust engagement↔transcript mapping).
    transcript = pathlib.Path(a.transcript) if a.transcript else auto_transcript(events, tdir)
    if not transcript or not transcript.exists():
        ap.error("could not resolve a transcript; pass --transcript explicitly")
    out = pathlib.Path(a.out) if a.out else events.with_suffix(".decisions.jsonl")
    stats = harvest(transcript, events, out)
    stats["transcript"] = transcript.name
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
