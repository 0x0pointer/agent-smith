"""
Wishlist queue — the non-blocking agent→operator backlog.

Smith's signal topology had two directions: operator→agent (steering directives,
core/steering.py) and a BLOCKING agent→human escalation (HIR). It had no way for
the agent to say, without stopping, "I could go deeper here if you gave me X"
(a credential, a wider scope, rate-limit relief, a tool/image). Those needs used
to vanish into a buried `not_applicable` note.

The wishlist makes under-testing-by-lack-of-access a first-class, operator-visible,
NON-BLOCKING signal. Smith appends a need (linked to the coverage cells it blocks);
the operator drains it from the dashboard at their leisure; a fulfilled need points
Smith back at the exact cells to reopen. Unlike HIR it never pauses the scan, and
unlike steering it flows the other way.

Lifecycle
  open       → created by Smith via session(action='wishlist_add')
  fulfilled  → operator supplied the resource (dashboard / API)
  dismissed  → operator declined it

File: wishlist_queue.json   API: GET /api/wishlist
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from core import paths as _paths
from core import store as _store

_WISHLIST_FILE = _paths.WISHLIST_FILE

# Suggested categories (free-form is accepted; these just normalise the common ones).
CATEGORIES = ("credentials", "scope", "rate_limit", "tooling", "access", "environment", "other")


@dataclass
class WishlistItem:
    id: str
    ts: str
    need: str
    category: str
    rationale: str
    blocking_cell_ids: list[str] = field(default_factory=list)
    status: str = "open"            # open | fulfilled | dismissed
    resolved_at: str | None = None
    resolution_note: str | None = None


class WishlistQueue:
    """Persistent agent→operator backlog backed by wishlist_queue.json."""

    def _load(self) -> list[dict]:
        try:
            if _WISHLIST_FILE.exists():
                return json.loads(_WISHLIST_FILE.read_text(encoding="utf-8")).get("items", [])
        except Exception:
            pass
        return []

    def _save(self, items: list[dict]) -> None:
        try:
            _store.save(_WISHLIST_FILE, {"items": items})
        except Exception:
            pass

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _norm(s) -> str:
        return " ".join(str(s or "").strip().lower().split())

    # ── Write ──────────────────────────────────────────────────────────────────

    def add(
        self,
        need: str,
        category: str = "other",
        rationale: str = "",
        blocking_cell_ids: list[str] | None = None,
    ) -> str | None:
        """Add a need. Returns id, or None if an OPEN item with the same need exists.

        Dedup is on the normalised need text so a re-asked need doesn't pile up
        a second open entry every turn.
        """
        need = str(need or "").strip()
        if not need:
            return None
        items = self._load()
        norm = self._norm(need)
        for it in items:
            if it.get("status") == "open" and self._norm(it.get("need")) == norm:
                return None  # already on the open backlog

        cat = self._norm(category) or "other"
        if cat not in CATEGORIES:
            cat = "other"
        item_id = f"wish-{uuid.uuid4().hex[:8]}"
        items.append({
            "id": item_id,
            "ts": self._now(),
            "need": need,
            "category": cat,
            "rationale": str(rationale or "").strip(),
            "blocking_cell_ids": [str(c) for c in (blocking_cell_ids or []) if str(c).strip()],
            "status": "open",
            "resolved_at": None,
            "resolution_note": None,
        })
        self._save(items)
        return item_id

    def _resolve(self, item_id: str, status: str, note: str | None) -> dict | None:
        items = self._load()
        for it in items:
            if it.get("id") == item_id and it.get("status") == "open":
                it["status"] = status
                it["resolved_at"] = self._now()
                it["resolution_note"] = note
                self._save(items)
                return it
        return None

    def fulfill(self, item_id: str, note: str | None = None) -> dict | None:
        """Operator supplied the resource. Returns the item (with its blocking
        cells, so the caller can tell Smith which cells to reopen)."""
        return self._resolve(item_id, "fulfilled", note)

    def dismiss(self, item_id: str, note: str | None = None) -> dict | None:
        return self._resolve(item_id, "dismissed", note)

    # ── Query ──────────────────────────────────────────────────────────────────

    def list_open(self) -> list[WishlistItem]:
        return [WishlistItem(**it) for it in self._load() if it.get("status") == "open"]

    def get_all(self) -> list[dict]:
        """All items, newest first — for the dashboard."""
        return list(reversed(self._load()))


wishlist_queue = WishlistQueue()
