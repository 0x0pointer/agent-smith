"""
Shared base for out-of-band notifiers (Telegram, Slack, Discord, …).

Every notifier reuses the same compose, dedup, audit-log, and never-raise
machinery. Subclasses override _send_message() and set two class-level
constants (AUDIT_FILENAME, DEFAULT_MAX_BODY_CHARS). Anything else common
across platforms belongs here, not in the per-platform module.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

_log = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_AUDIT_DIR = _REPO_ROOT / "logs"

# Conservative defaults — each subclass can raise its own cap. Telegram is
# the floor at 800; Discord and Slack lift it because their UIs handle
# multi-paragraph messages better.
_DEFAULT_MAX_BODY_CHARS = 800
_DEFAULT_DEDUP_SECONDS = 30 * 60


class BaseNotifier:
    """Shared dedup + audit + compose layer. Concrete classes only need
    to implement _send_message()."""

    # Subclasses override these.
    AUDIT_FILENAME: str = "notifier_audit.log"
    DEFAULT_MAX_BODY_CHARS: int = _DEFAULT_MAX_BODY_CHARS

    def __init__(
        self,
        *,
        audit_log_path: Path | None = None,
        max_body_chars: int | None = None,
        dedup_seconds: int = _DEFAULT_DEDUP_SECONDS,
    ):
        self._max_body = max_body_chars or self.DEFAULT_MAX_BODY_CHARS
        self._dedup_seconds = dedup_seconds
        # In-memory dedup: (code, body) -> last sent timestamp.
        self._last_sent: dict[tuple[str, str], datetime] = {}
        self._audit_path = audit_log_path or (_AUDIT_DIR / self.AUDIT_FILENAME)

    # ── public ────────────────────────────────────────────────────────────────

    async def notify(
        self,
        title: str,
        body: str,
        *,
        urgency: str = "normal",
        code: str = "",
        options: Iterable[str] | None = None,
    ) -> bool:
        """Send a notification. Returns True on successful delivery.

        Idempotent within _DEDUP_SECONDS for identical (code, body) pairs.
        Never raises — HTTP errors are caught and audit-logged so the scan
        path can stay simple.
        """
        urgency_prefix = self._urgency_prefix(urgency)
        message = self._compose(urgency_prefix + title, body, options)
        dedup_key = (code or title, message)
        if self._is_dup(dedup_key):
            self._audit("skip-dedup", dedup_key, message)
            return False
        try:
            sent = await self._send_message(message)
        except Exception as e:
            _log.warning("%s send failed: %s", type(self).__name__, e)
            self._audit("error", dedup_key, message, extra={"error": str(e)[:200]})
            return False
        if sent:
            self._last_sent[dedup_key] = datetime.now(timezone.utc)
            self._audit("sent", dedup_key, message)
        else:
            self._audit("rejected", dedup_key, message)
        return sent

    # ── must override ─────────────────────────────────────────────────────────

    async def _send_message(self, text: str) -> bool:
        raise NotImplementedError("subclass must implement _send_message")

    # ── shared internals ──────────────────────────────────────────────────────

    def _urgency_prefix(self, urgency: str) -> str:
        return {"high": "⚠ ", "low": "· ", "normal": ""}.get(urgency.lower(), "")

    def _compose(self, title: str, body: str, options: Iterable[str] | None) -> str:
        parts = [title.strip()]
        if body.strip():
            parts.append(body.strip())
        if options:
            opts = ", ".join(str(o).strip() for o in options if str(o).strip())
            if opts:
                parts.append(f"Options: {opts}")
                parts.append("Resolve from the dashboard.")
        message = "\n\n".join(parts)
        if len(message) > self._max_body:
            message = message[: self._max_body - 1] + "…"
        return message

    def _is_dup(self, dedup_key: tuple[str, str]) -> bool:
        last = self._last_sent.get(dedup_key)
        if not last:
            return False
        delta = (datetime.now(timezone.utc) - last).total_seconds()
        return delta < self._dedup_seconds

    def _audit(
        self,
        outcome: str,
        dedup_key: tuple[str, str],
        message: str,
        *,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Append a single JSON line to the audit log. Never raises —
        audit-log failures must not break scan logic."""
        try:
            entry: dict[str, Any] = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "outcome": outcome,
                "code": dedup_key[0],
                "message_len": len(message),
                "message_preview": message[:160],
            }
            if extra:
                entry.update(extra)
            self._audit_path.parent.mkdir(parents=True, exist_ok=True)
            with self._audit_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            _log.debug("audit log write failed: %s", e)
