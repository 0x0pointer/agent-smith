"""
Shared state, constants, and the Envelope dataclass for the envelope package.
"""
from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass, field, asdict
from typing import Any

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent.parent
_QA_STATE_FILE      = _REPO_ROOT / "qa_state.json"
_STEERING_FILE      = _REPO_ROOT / "steering_queue.json"
_RECOVERY_SNAP_FILE = _REPO_ROOT / "recovery_latest.json"
_last_qa_shown_ts: str = ""  # ISO timestamp of last alert batch shown to the model

# Content-based dedup for QA alerts. Maps (code, message) → ISO timestamp last shown.
# Suppresses re-injection of an identical alert that Smith has already seen until
# either (a) the content changes, (b) the alert clears, or (c) the cooldown expires.
# Prevents Smith answering the same "553 cells lack tested_by" message every 120s.
_qa_alert_last_shown: dict[tuple, str] = {}
_QA_ALERT_DEDUP_SECONDS = 30 * 60  # 30 min cooldown per identical alert

import logging as _logging
_log = _logging.getLogger("mcp_server.scan_engine.envelope")


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


# ---------------------------------------------------------------------------
# State compaction — strip fields the model doesn't need on every response
# ---------------------------------------------------------------------------

def _compact_state(state: dict) -> dict:
    """Return a fingerprint of scan state for embedding in the envelope.

    Drops `tools_run` (grows unboundedly, not useful per-response) and
    `time_pct` (low-value scalar). Anything Smith needs beyond this is one
    session(action='status') call away.
    """
    keep = ("target", "phase", "active_skill", "coverage", "findings",
            "calls_used", "pending_escalations", "in_progress_cells")
    return {k: state[k] for k in keep if k in state}
