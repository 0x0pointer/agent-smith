"""
Telegram notifier — one-way alerts to the operator's phone.

Sends HIR / watchdog / scan-complete / status alerts via the Telegram Bot
API. This is a notifier, not a control surface: it does not read inbound
messages, does not render interactive keyboards, and the bot does nothing
when the operator replies. All scan control happens through the dashboard.

Security guardrails (inherited from BaseNotifier where shared):
  • Outbound HTTPS only — no port opened, no public URL needed.
  • Bot token + chat ID loaded from .env (mode 600); never logged.
  • Body length capped so a verbose HIR can't leak payloads to Telegram.
  • Content-based dedup (same code+message in last _DEDUP_SECONDS skipped).
  • Audit log at logs/telegram_audit.log — every send + skip recorded.
  • Never raises into scan logic; HTTP errors caught and audit-logged.
  • Never sends finding bodies — only short situation strings and counts.
"""
from __future__ import annotations

import logging
from pathlib import Path

from core.notifiers._base import BaseNotifier

_log = logging.getLogger(__name__)

# Telegram's hard text limit is 4096 chars — we stay well below it. Short
# alerts only; finding bodies never go through this channel.
_MAX_BODY_CHARS = 800

# Telegram Bot API base URL pattern.
_TELEGRAM_API = "https://api.telegram.org/bot{token}/{method}"

# Re-export so existing tests / external code can monkeypatch the default
# audit-log path on this module. The real path lives on the base class.
from core.notifiers._base import _AUDIT_DIR as _BASE_AUDIT_DIR  # noqa: E402
_AUDIT_LOG_DEFAULT = _BASE_AUDIT_DIR / "telegram_audit.log"


class TelegramNotifier(BaseNotifier):
    """Telegram bridge — outbound HIR / lifecycle / status alerts only."""

    AUDIT_FILENAME = "telegram_audit.log"
    DEFAULT_MAX_BODY_CHARS = _MAX_BODY_CHARS

    def __init__(
        self,
        token: str,
        chat_id: str,
        *,
        audit_log_path: Path | None = None,
        api_base: str = _TELEGRAM_API,
        max_body_chars: int | None = None,
        dedup_seconds: int | None = None,
    ):
        if not token or not isinstance(token, str):
            raise ValueError("TELEGRAM_BOT_TOKEN is empty")
        # Telegram chat IDs are integers (positive for users, negative for
        # groups/channels). We accept the string form from .env but validate
        # it converts cleanly so a typo fails loudly at startup.
        try:
            self._chat_id_int = int(str(chat_id).strip())
        except (TypeError, ValueError) as e:
            raise ValueError(
                f"TELEGRAM_CHAT_ID is not a valid integer ({chat_id!r}) — "
                "get it from /api/getUpdates after sending /start to your bot"
            ) from e
        kw: dict = {"audit_log_path": audit_log_path}
        if max_body_chars is not None:
            kw["max_body_chars"] = max_body_chars
        if dedup_seconds is not None:
            kw["dedup_seconds"] = dedup_seconds
        super().__init__(**kw)
        self._token = token
        self._api_base = api_base

    async def _send_message(self, text: str) -> bool:
        """POST to Telegram sendMessage. Returns True on HTTP 200 + ok=True.

        aiohttp with a 10s timeout so a Telegram outage doesn't pile up
        tasks behind every HIR fire.
        """
        import aiohttp
        url = self._api_base.format(token=self._token, method="sendMessage")
        payload = {
            "chat_id": self._chat_id_int,
            "text": text,
            "disable_web_page_preview": True,
        }
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, json=payload) as resp:
                if resp.status != 200:
                    return False
                body = await resp.json()
                return bool(body.get("ok"))
