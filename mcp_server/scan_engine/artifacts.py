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

    if mode in ("summary", "head"):
        content = raw[:max_chars]
    elif mode == "tail":
        content = raw[-max_chars:] if total > max_chars else raw
    elif mode == "grep":
        if not pattern:
            return json.dumps({"error": "grep mode requires a pattern"})
        import re
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            return json.dumps({"error": f"Invalid regex: {e}"})
        matches = [line for line in raw.splitlines() if regex.search(line)]
        content = "\n".join(matches)[:max_chars]
    elif mode == "full":
        content = raw[:max_chars]
    else:
        return json.dumps({"error": f"Unknown mode: {mode}. Use: summary, head, tail, grep, full"})

    return json.dumps({
        "artifact_id": artifact_id,
        "mode": mode,
        "chars_returned": len(content),
        "total_chars": total,
        "truncated": len(content) < total,
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
