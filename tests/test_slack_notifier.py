"""
Tests for core.notifiers.slack.

Covers:
  • __init__ validation rejects empty / malformed webhook URLs loudly.
  • Audit log path is the slack-specific filename, not the telegram one.
  • _compose / dedup / urgency-prefix behavior inherited from BaseNotifier.
  • notify() never raises; HTTP errors become audit entries.
  • Outbound payload to the Slack webhook has the expected shape.
"""
import json
from unittest.mock import patch, AsyncMock, MagicMock

import pytest

from core.notifiers import slack as sl


VALID_URL = "https://hooks.slack.com/services/T000/B000/abcdef"


# ---------------------------------------------------------------------------
# __init__ validation
# ---------------------------------------------------------------------------

class TestSlackNotifierInit:

    def test_rejects_empty_url(self):
        with pytest.raises(ValueError, match="SLACK_WEBHOOK_URL"):
            sl.SlackNotifier(webhook_url="")

    def test_rejects_non_slack_url(self):
        with pytest.raises(ValueError, match="hooks.slack.com"):
            sl.SlackNotifier(webhook_url="https://example.com/some-hook")

    def test_rejects_http_url(self):
        # HTTP (not S) must fail — we never want to leak even an alert over plaintext.
        with pytest.raises(ValueError, match="hooks.slack.com"):
            sl.SlackNotifier(webhook_url="http://hooks.slack.com/services/T/B/X")

    def test_accepts_valid_url(self):
        n = sl.SlackNotifier(webhook_url=VALID_URL)
        assert n._webhook_url == VALID_URL

    def test_audit_filename_is_slack_specific(self, tmp_path):
        n = sl.SlackNotifier(webhook_url=VALID_URL, audit_log_path=tmp_path / "audit.log")
        # The override path is honored exactly.
        assert n._audit_path == tmp_path / "audit.log"

    def test_default_audit_filename_is_slack(self):
        n = sl.SlackNotifier(webhook_url=VALID_URL)
        assert n._audit_path.name == "slack_audit.log"


# ---------------------------------------------------------------------------
# _send_message — outbound payload shape
# ---------------------------------------------------------------------------

class TestSlackOutboundPayload:

    @pytest.mark.asyncio
    async def test_sends_text_field_to_webhook(self, tmp_path):
        n = sl.SlackNotifier(webhook_url=VALID_URL, audit_log_path=tmp_path / "audit.log")

        captured = {}

        class _FakeResp:
            status = 200
            async def text(self): return "ok"
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
            ok = await n._send_message("hello world")

        assert ok is True
        assert captured["url"] == VALID_URL
        assert captured["json"] == {"text": "hello world"}

    @pytest.mark.asyncio
    async def test_non_200_returns_false(self, tmp_path):
        n = sl.SlackNotifier(webhook_url=VALID_URL, audit_log_path=tmp_path / "audit.log")

        class _FakeResp:
            status = 500
            async def text(self): return "internal error"
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False

        class _FakeSession:
            def __init__(self, *a, **kw): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False
            def post(self, *a, **kw): return _FakeResp()

        with patch("aiohttp.ClientSession", _FakeSession):
            ok = await n._send_message("anything")
        assert ok is False

    @pytest.mark.asyncio
    async def test_non_ok_body_returns_false(self, tmp_path):
        # Slack signals app-level errors via the body being something other
        # than literal "ok" while still returning HTTP 200.
        n = sl.SlackNotifier(webhook_url=VALID_URL, audit_log_path=tmp_path / "audit.log")

        class _FakeResp:
            status = 200
            async def text(self): return "invalid_payload"
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False

        class _FakeSession:
            def __init__(self, *a, **kw): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False
            def post(self, *a, **kw): return _FakeResp()

        with patch("aiohttp.ClientSession", _FakeSession):
            ok = await n._send_message("anything")
        assert ok is False


# ---------------------------------------------------------------------------
# notify() top-level behavior — dedup, audit, never-raise
# ---------------------------------------------------------------------------

class TestSlackNotify:

    @pytest.mark.asyncio
    async def test_notify_writes_sent_audit_entry(self, tmp_path):
        log_path = tmp_path / "audit.log"
        n = sl.SlackNotifier(webhook_url=VALID_URL, audit_log_path=log_path)
        with patch.object(n, "_send_message", AsyncMock(return_value=True)):
            assert await n.notify("HIR", "broke", code="HIR_X") is True
        lines = log_path.read_text().splitlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["outcome"] == "sent"
        assert entry["code"] == "HIR_X"

    @pytest.mark.asyncio
    async def test_notify_swallows_http_exception(self, tmp_path):
        log_path = tmp_path / "audit.log"
        n = sl.SlackNotifier(webhook_url=VALID_URL, audit_log_path=log_path)
        with patch.object(n, "_send_message", AsyncMock(side_effect=RuntimeError("boom"))):
            # Must not raise — the contract is "scan logic keeps working".
            assert await n.notify("HIR", "broke", code="HIR_X") is False
        entry = json.loads(log_path.read_text().splitlines()[0])
        assert entry["outcome"] == "error"
        assert "boom" in entry["error"]

    @pytest.mark.asyncio
    async def test_dedup_window_inherited(self, tmp_path):
        log_path = tmp_path / "audit.log"
        n = sl.SlackNotifier(webhook_url=VALID_URL, audit_log_path=log_path)
        with patch.object(n, "_send_message", AsyncMock(return_value=True)) as send:
            await n.notify("HIR", "broke", code="HIR_X")
            await n.notify("HIR", "broke", code="HIR_X")
        # Identical (code, body) within the 30-min window → second call skipped.
        send.assert_awaited_once()
