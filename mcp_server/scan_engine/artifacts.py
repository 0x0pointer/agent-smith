"""
Artifact storage — raw tool output stored on disk, retrievable by ID.

Artifacts keep raw output out of the LLM context window while preserving
full audit trail. Retrieval is bounded: callers specify a mode and max_chars.
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

_ARTIFACTS_DIR = Path(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))) / "artifacts"


def _ensure_dir() -> Path:
    _ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    return _ARTIFACTS_DIR


def store_artifact(tool: str, raw_output: str) -> str:
    """Store raw output and return an artifact ID."""
    artifact_id = f"{tool}_{datetime.now(timezone.utc).strftime('%H%M%S')}_{uuid.uuid4().hex[:8]}"
    path = _ensure_dir() / f"{artifact_id}.txt"
    path.write_text(raw_output, encoding="utf-8")
    return artifact_id


def artifact_exists(artifact_id: str) -> bool:
    """True if a stored artifact file exists on disk for this ID.

    Shared disk-existence check (same convention as coverage validation): an
    artifact_id is only trustworthy if the tool actually produced
    ``artifacts/<artifact_id>.txt``. Used to enforce that adjudication
    reproducibility verdicts and exploit-chain transitions are backed by a real
    artifact, not a placeholder string.
    """
    if not artifact_id or not artifact_id.strip():
        return False
    return (_ARTIFACTS_DIR / f"{artifact_id.strip()}.txt").exists()


# Bounds for a SINGLE artifact retrieval, so one pull can't dominate/overflow the
# model window (a max_chars=1_000_000 'full' pull previously returned ~1MB inline).
_ARTIFACT_ABS_CEILING = 120_000   # never return more than ~30K tokens in one call
_ARTIFACT_ABS_FLOOR = 20_000      # always allow at least this much


def _artifact_ceiling() -> int:
    """Upper clamp for one retrieval — ~30% of the model's context budget, bounded by
    sane absolutes. Scales with the profile/window so a small-window model gets a
    smaller cap; falls back safely when the profile can't be resolved."""
    try:
        from mcp_server.scan_engine.budget import get_profile
        budget = int(get_profile().get("context_budget_chars") or 400_000)
    except Exception:
        budget = 400_000
    return max(_ARTIFACT_ABS_FLOOR, min(int(budget * 0.30), _ARTIFACT_ABS_CEILING))


def retrieve_artifact(
    artifact_id: str,
    mode: str = "summary",
    max_chars: int = 4000,
    pattern: str = "",
) -> str:
    """Retrieve artifact content with bounded output.

    Modes:
        summary — first max_chars characters
        head    — first max_chars characters (alias for summary)
        tail    — last max_chars characters
        grep    — lines matching pattern, up to max_chars
        full    — full content, hard-capped at max_chars

    Returns JSON with {artifact_id, mode, chars_returned, total_chars, content}.
    """
    path = _ARTIFACTS_DIR / f"{artifact_id}.txt"
    if not path.exists():
        return json.dumps({"error": f"Artifact not found: {artifact_id}"})

    raw = path.read_text(encoding="utf-8")
    total = len(raw)

    # Clamp the caller-supplied max_chars to the safe, profile-scaled ceiling.
    try:
        requested = max(1, int(max_chars))
    except (TypeError, ValueError):
        requested = 4000
    ceiling = _artifact_ceiling()
    eff_max = min(requested, ceiling)
    clamped = eff_max < requested

    if mode in ("summary", "head"):
        content = raw[:eff_max]
    elif mode == "tail":
        content = raw[-eff_max:] if total > eff_max else raw
    elif mode == "grep":
        if not pattern:
            return json.dumps({"error": "grep mode requires a pattern"})
        import re
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            return json.dumps({"error": f"Invalid regex: {e}"})
        matches = [line for line in raw.splitlines() if regex.search(line)]
        content = "\n".join(matches)[:eff_max]
    elif mode == "full":
        if total > eff_max:
            # Keep the START and END (where scan results usually sit) and tell the
            # model exactly how to fetch the rest — bounded, never a silent loss.
            head = (eff_max * 2) // 3
            tail = eff_max - head
            content = (
                raw[:head]
                + f"\n\n… [{total - eff_max} of {total} chars omitted — narrow with "
                  "mode='grep' pattern='<term>', or mode='tail'/'head' for the ends] …\n\n"
                + raw[-tail:]
            )
        else:
            content = raw[:eff_max]
    else:
        return json.dumps({"error": f"Unknown mode: {mode}. Use: summary, head, tail, grep, full"})

    return json.dumps({
        "artifact_id": artifact_id,
        "mode": mode,
        "chars_returned": len(content),
        "total_chars": total,
        "truncated": len(content) < total,
        "clamped": clamped,          # max_chars was capped to the safe ceiling
        "ceiling": ceiling,
        "content": content,
    })


def cleanup_artifacts(max_age_hours: int = 24) -> int:
    """Remove artifacts older than max_age_hours. Returns count deleted."""
    if not _ARTIFACTS_DIR.exists():
        return 0
    cutoff = datetime.now(timezone.utc).timestamp() - (max_age_hours * 3600)
    deleted = 0
    for f in _ARTIFACTS_DIR.iterdir():
        if f.is_file() and f.stat().st_mtime < cutoff:
            f.unlink()
            deleted += 1
    return deleted
