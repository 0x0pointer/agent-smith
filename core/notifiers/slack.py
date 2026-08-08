"""
Slack notifier — incoming-webhook based, outbound only.

Posts plain-text alerts to a single Slack channel via an Incoming Webhook
URL configured in .env. Same security guardrails as the Telegram notifier:
no inbound listening, no PII, dedup, audit log, never raises.

Setup (operator):
  1. In Slack: Apps → "Incoming Webhooks" → Add to your workspace.
  2. Pick the channel that should receive alerts (private DM is fine).
  3. Copy the webhook URL — looks like https://hooks.slack.com/services/T.../B.../...
  4. Drop it into .env as SLACK_WEBHOOK_URL=…
"""
from __future__ import annotations

import logging
from pathlib import Path

from core.notifiers._base import BaseNotifier

_log = logging.getLogger(__name__)

# Slack's hard text limit is 40k chars but blocks-rendered text starts to
# wrap awkwardly past ~3k. We cap at 2500 to match Telegram-style brevity
# while taking advantage of Slack's roomier UI.
_MAX_BODY_CHARS = 2500

# Slack incoming webhooks expect POST to the exact URL operator copied
# from the app config. The URL itself is the auth token — treat as secret.


class SlackNotifier(BaseNotifier):
    """Slack incoming-webhook bridge — outbound alerts only."""

    AUDIT_FILENAME = "slack_audit.log"
    DEFAULT_MAX_BODY_CHARS = _MAX_BODY_CHARS

    def __init__(
        self,
        webhook_url: str,
        *,
        audit_log_path: Path | None = None,
        max_body_chars: int | None = None,
        dedup_seconds: int | None = None,
    ):
        if not webhook_url or not isinstance(webhook_url, str):
            raise ValueError("SLACK_WEBHOOK_URL is empty")
        # Slack webhook URLs are HTTPS to hooks.slack.com/services/...
        # Validate the prefix loudly so a typo doesn't silently disable.
        if not webhook_url.startswith("https://hooks.slack.com/"):
            raise ValueError(
                f"SLACK_WEBHOOK_URL must start with https://hooks.slack.com/ "
                f"(got {webhook_url[:40]!r}…)"
            )
        kw: dict = {"audit_log_path": audit_log_path}
        if max_body_chars is not None:
            kw["max_body_chars"] = max_body_chars
        if dedup_seconds is not None:
            kw["dedup_seconds"] = dedup_seconds
        super().__init__(**kw)
        self._webhook_url = webhook_url

    async def _send_message(self, text: str) -> bool:
        """POST to the Slack incoming webhook. Returns True on HTTP 200.

        Webhooks accept either plain text in the `text` field or a structured
        `blocks` array. Plain text is enough for our short alerts and avoids
        accidentally rendering user-controlled HIR text as Slack markup.
        """
        import aiohttp
        payload = {"text": text}
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(self._webhook_url, json=payload) as resp:
                # Slack webhooks return 200 + body "ok" on success.
                if resp.status != 200:
                    return False
                body = await resp.text()
                return body.strip() == "ok"
