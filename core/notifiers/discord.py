"""
Discord notifier — webhook-based, outbound only.

Posts plain-text alerts to a single Discord channel via a Webhook URL
configured in .env. Same security guardrails as the Telegram notifier:
no inbound listening, no PII, dedup, audit log, never raises.

Setup (operator):
  1. In Discord: open the channel that should receive alerts.
  2. Channel settings → Integrations → Webhooks → "New Webhook".
  3. Name the webhook (e.g. "agent-smith"), pick the channel, save.
  4. Copy the webhook URL — looks like https://discord.com/api/webhooks/<id>/<token>
  5. Drop it into .env as DISCORD_WEBHOOK_URL=…
"""
from __future__ import annotations

import logging
from pathlib import Path

from core.notifiers._base import BaseNotifier

_log = logging.getLogger(__name__)

# Discord's hard limit for webhook `content` is 2000 chars. We cap at 1800
# to leave headroom for the urgency prefix and the Options/Resolve footer.
_MAX_BODY_CHARS = 1800

# A friendly username surfaced in the channel (overrides the webhook's
# default name without granting any extra permissions).
_DEFAULT_USERNAME = "agent-smith"


class DiscordNotifier(BaseNotifier):
    """Discord webhook bridge — outbound alerts only."""

    AUDIT_FILENAME = "discord_audit.log"
    DEFAULT_MAX_BODY_CHARS = _MAX_BODY_CHARS

    def __init__(
        self,
        webhook_url: str,
        *,
        username: str = _DEFAULT_USERNAME,
        audit_log_path: Path | None = None,
        max_body_chars: int | None = None,
        dedup_seconds: int | None = None,
    ):
        if not webhook_url or not isinstance(webhook_url, str):
            raise ValueError("DISCORD_WEBHOOK_URL is empty")
        # Discord webhook URLs are HTTPS to discord.com/api/webhooks/<id>/<token>
        # (the discordapp.com variant also exists for legacy clients).
        if not (
            webhook_url.startswith("https://discord.com/api/webhooks/")
            or webhook_url.startswith("https://discordapp.com/api/webhooks/")
        ):
            raise ValueError(
                "DISCORD_WEBHOOK_URL must start with "
                "https://discord.com/api/webhooks/ "
                f"(got {webhook_url[:50]!r}…)"
            )
        kw: dict = {"audit_log_path": audit_log_path}
        if max_body_chars is not None:
            kw["max_body_chars"] = max_body_chars
        if dedup_seconds is not None:
            kw["dedup_seconds"] = dedup_seconds
        super().__init__(**kw)
        self._webhook_url = webhook_url
        self._username = username

    async def _send_message(self, text: str) -> bool:
        """POST to the Discord webhook. Returns True on HTTP 204 (No Content)
        which is Discord's success response for a webhook send.

        We disable @everyone / @here / role mentions defensively in case an
        HIR situation string ever contains a literal '@everyone' substring.
        """
        import aiohttp
        payload = {
            "content": text,
            "username": self._username,
            "allowed_mentions": {"parse": []},
        }
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(self._webhook_url, json=payload) as resp:
                # Discord returns 204 on success for webhook sends.
                return resp.status in (200, 204)
