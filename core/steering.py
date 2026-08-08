"""
Steering queue — QA-driven directives injected into Smith's tool envelopes.

The steering queue is the active correction mechanism. When the QA daemon detects
that Smith has stalled, missed a skill chain, or left a gate open too long, it writes
a SteeringDirective here. The envelope pipeline (P5.7) reads pending directives and
injects them directly into Smith's next tool response — no model action required.

Directive lifecycle
  pending      → created by QA daemon
  injected     → envelope P5.7 pushed it into a tool response
  acknowledged → Smith called session(action='qa_reply')
  auto_satisfied → the required action actually happened (_do_set_skill chained the skill)

File: steering_queue.json
API:  GET /api/steering
"""
from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from core import paths as _paths
from core import store as _store

_STEERING_FILE = _paths.STEERING_FILE

# Codes that can appear in a directive
RESUME_REQUIRED  = "RESUME_REQUIRED"
CHAIN_REQUIRED   = "CHAIN_REQUIRED"
RESUME_TESTING   = "RESUME_TESTING"
POC_REQUIRED     = "POC_REQUIRED"
# Compositional-chaining bridge push. A DISTINCT code (not RESUME_TESTING) so its
# add_directive dedup slot (keyed on code+skill) is independent — otherwise the five
# existing RESUME_TESTING/skill=None checks would silently suppress the bridge nudge.
COMPOSE_REQUIRED = "COMPOSE_REQUIRED"


@dataclass
class SteeringDirective:
    id: str
    ts: str
    code: str
    priority: str           # "high" | "medium"
    message: str
    skill: str | None       # for CHAIN_REQUIRED: the skill to invoke
    trigger: str            # alert code that caused this directive
    status: str             # pending | injected | acknowledged | auto_satisfied
    injected_at: str | None = None
    acknowledged_at: str | None = None
    ack_message: str | None = None


class SteeringQueue:
    """Persistent steering directive queue backed by steering_queue.json."""

    def _load(self) -> list[dict]:
        try:
            if _STEERING_FILE.exists():
                return json.loads(_STEERING_FILE.read_text(encoding="utf-8")).get("directives", [])
        except Exception:
            pass
        return []

    def _save(self, directives: list[dict]) -> None:
        try:
            _store.save(_STEERING_FILE, {"directives": directives})
        except Exception:
            pass

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    # ── Write ──────────────────────────────────────────────────────────────────

    def add_directive(
        self,
        code: str,
        message: str,
        priority: str = "high",
        skill: str | None = None,
        trigger: str = "",
        force: bool = False,
    ) -> str | None:
        """Add a directive. Returns id if created, None if deduped.

        Dedup rule: skip if same code+skill already has status pending or injected.
        Pass force=True to bypass dedup (used for human steering instructions).
        """
        directives = self._load()
        if not force:
            for d in directives:
                if (
                    d.get("code") == code
                    and d.get("skill") == skill
                    and d.get("status") in ("pending", "injected")
                ):
                    return None  # already active — don't duplicate

        directive_id = f"steer-{uuid.uuid4().hex[:8]}"
        directive = {
            "id": directive_id,
            "ts": self._now(),
            "code": code,
            "priority": priority,
            "message": message,
            "skill": skill,
            "trigger": trigger,
            "status": "pending",
            "injected_at": None,
            "acknowledged_at": None,
            "ack_message": None,
        }
        directives.append(directive)
        self._save(directives)
        return directive_id

    # ── Transitions ────────────────────────────────────────────────────────────

    def mark_injected(self, directive_id: str) -> None:
        directives = self._load()
        for d in directives:
            if d["id"] == directive_id and d["status"] == "pending":
                d["status"] = "injected"
                d["injected_at"] = self._now()
                break
        self._save(directives)

    def acknowledge(self, directive_id: str, message: str | None = None) -> bool:
        """Mark a directive acknowledged. Returns True if found."""
        directives = self._load()
        for d in directives:
            if d["id"] == directive_id and d["status"] in ("pending", "injected"):
                d["status"] = "acknowledged"
                d["acknowledged_at"] = self._now()
                d["ack_message"] = message
                self._save(directives)
                return True
        return False

    def auto_satisfy(self, skill: str) -> list[str]:
        """Auto-satisfy all CHAIN_REQUIRED directives for a skill. Returns satisfied IDs."""
        directives = self._load()
        satisfied: list[str] = []
        for d in directives:
            if (
                d.get("code") == CHAIN_REQUIRED
                and d.get("skill") == skill
                and d.get("status") in ("pending", "injected")
            ):
                d["status"] = "auto_satisfied"
                d["acknowledged_at"] = self._now()
                satisfied.append(d["id"])
        if satisfied:
            self._save(directives)
        return satisfied

    def cancel_by_trigger(self, trigger: str, message: str | None = None) -> int:
        """Acknowledge all active directives with the given trigger. Returns count.

        Used by the dashboard to cancel an in-flight pass (e.g. triage) — marks
        the matching pending/injected directives acknowledged so they drop out of
        get_active()/get_pending() without losing the audit trail.
        """
        directives = self._load()
        n = 0
        for d in directives:
            if d.get("trigger") == trigger and d.get("status") in ("pending", "injected"):
                d["status"] = "acknowledged"
                d["acknowledged_at"] = self._now()
                d["ack_message"] = message or "cancelled by operator"
                n += 1
        if n:
            self._save(directives)
        return n

    def acknowledge_latest_injected(self, message: str | None = None) -> str | None:
        """Acknowledge the most recently injected directive. Returns its id or None."""
        directives = self._load()
        injected = [d for d in directives if d.get("status") == "injected"]
        if not injected:
            return None
        latest = max(injected, key=lambda d: d.get("injected_at") or d["ts"])
        self.acknowledge(latest["id"], message)
        return latest["id"]

    # ── Query ──────────────────────────────────────────────────────────────────

    def get_pending(self) -> list[SteeringDirective]:
        return [
            SteeringDirective(**d)
            for d in self._load()
            if d.get("status") == "pending"
        ]

    def get_injected(self) -> list[SteeringDirective]:
        return [
            SteeringDirective(**d)
            for d in self._load()
            if d.get("status") == "injected"
        ]

    def get_active(self) -> list[SteeringDirective]:
        """Pending + injected — the directives Smith should still act on."""
        return [
            SteeringDirective(**d)
            for d in self._load()
            if d.get("status") in ("pending", "injected")
        ]

    def get_history(self) -> list[dict]:
        """All directives, newest first — for the dashboard audit trail."""
        directives = self._load()
        return list(reversed(directives))


steering_queue = SteeringQueue()
