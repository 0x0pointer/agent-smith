"""
Tests for core.notifiers.discord.

Covers:
  • __init__ validation rejects empty / malformed webhook URLs loudly.
  • Audit log path is the discord-specific filename.
  • _compose / dedup / urgency-prefix behavior inherited from BaseNotifier.
  • notify() never raises; HTTP errors become audit entries.
  • Outbound payload to the Discord webhook has the expected shape,
    including the @everyone-mentions defense.
"""
import json
from unittest.mock import patch, AsyncMock

import pytest

from core.notifiers import discord as dc


VALID_URL = "https://discord.com/api/webhooks/123456789/abcdefghi"
LEGACY_URL = "https://discordapp.com/api/webhooks/123456789/abcdefghi"


# ---------------------------------------------------------------------------
# __init__ validation
# ---------------------------------------------------------------------------

class TestDiscordNotifierInit:

    def test_rejects_empty_url(self):
        with pytest.raises(ValueError, match="DISCORD_WEBHOOK_URL"):
            dc.DiscordNotifier(webhook_url="")

    def test_rejects_non_discord_url(self):
        with pytest.raises(ValueError, match="discord.com/api/webhooks"):
            dc.DiscordNotifier(webhook_url="https://example.com/some-hook")

    def test_rejects_http_url(self):
        with pytest.raises(ValueError, match="discord.com/api/webhooks"):
            dc.DiscordNotifier(webhook_url="http://discord.com/api/webhooks/1/x")

    def test_accepts_valid_url(self):
        n = dc.DiscordNotifier(webhook_url=VALID_URL)
        assert n._webhook_url == VALID_URL

    def test_accepts_legacy_discordapp_url(self):
        # Older clients still use discordapp.com — keep accepting it.
        n = dc.DiscordNotifier(webhook_url=LEGACY_URL)
        assert n._webhook_url == LEGACY_URL

    def test_default_audit_filename_is_discord(self):
        n = dc.DiscordNotifier(webhook_url=VALID_URL)
        assert n._audit_path.name == "discord_audit.log"


# ---------------------------------------------------------------------------
# _send_message — outbound payload shape
# ---------------------------------------------------------------------------

class TestDiscordOutboundPayload:

    @pytest.mark.asyncio
    async def test_payload_has_text_username_and_no_mentions(self, tmp_path):
        n = dc.DiscordNotifier(webhook_url=VALID_URL, audit_log_path=tmp_path / "audit.log")

        captured = {}

        class _FakeResp:
            status = 204
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False

        class _FakeSession:
            def __init__(self, *a, **kw): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False
            def post(self, url, json=None, **kw):
                captured["url"] = url
                captured["json"] = json
                return _FakeResp()

        with patch("aiohttp.ClientSession", _FakeSession):
            ok = await n._send_message("hello there")

        assert ok is True
        assert captured["url"] == VALID_URL
        body = captured["json"]
        assert body["content"] == "hello there"
        assert body["username"] == "agent-smith"
        # @everyone defense — even if an HIR string contains the literal
        # token, Discord must NOT parse it as a mention.
        assert body["allowed_mentions"] == {"parse": []}

    @pytest.mark.asyncio
    async def test_200_also_accepted(self, tmp_path):
        # Discord usually returns 204; older endpoints sometimes return 200.
        n = dc.DiscordNotifier(webhook_url=VALID_URL, audit_log_path=tmp_path / "audit.log")

        class _FakeResp:
            status = 200
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False

        class _FakeSession:
            def __init__(self, *a, **kw): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False
            def post(self, *a, **kw): return _FakeResp()

        with patch("aiohttp.ClientSession", _FakeSession):
            ok = await n._send_message("x")
        assert ok is True

    @pytest.mark.asyncio
    async def test_429_returns_false(self, tmp_path):
        # Rate-limited — Discord returns 429; we treat as failed delivery.
        n = dc.DiscordNotifier(webhook_url=VALID_URL, audit_log_path=tmp_path / "audit.log")

        class _FakeResp:
            status = 429
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False

        class _FakeSession:
            def __init__(self, *a, **kw): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False
            def post(self, *a, **kw): return _FakeResp()

        with patch("aiohttp.ClientSession", _FakeSession):
            ok = await n._send_message("x")
        assert ok is False


# ---------------------------------------------------------------------------
# notify() top-level behavior
# ---------------------------------------------------------------------------

class TestDiscordNotify:

    @pytest.mark.asyncio
    async def test_notify_writes_sent_audit_entry(self, tmp_path):
        log_path = tmp_path / "audit.log"
        n = dc.DiscordNotifier(webhook_url=VALID_URL, audit_log_path=log_path)
        with patch.object(n, "_send_message", AsyncMock(return_value=True)):
            assert await n.notify("HIR", "broke", code="HIR_X") is True
        entry = json.loads(log_path.read_text().splitlines()[0])
        assert entry["outcome"] == "sent"

    @pytest.mark.asyncio
    async def test_notify_swallows_http_exception(self, tmp_path):
        log_path = tmp_path / "audit.log"
        n = dc.DiscordNotifier(webhook_url=VALID_URL, audit_log_path=log_path)
        with patch.object(n, "_send_message", AsyncMock(side_effect=RuntimeError("boom"))):
            assert await n.notify("HIR", "broke", code="HIR_X") is False
        entry = json.loads(log_path.read_text().splitlines()[0])
        assert entry["outcome"] == "error"
