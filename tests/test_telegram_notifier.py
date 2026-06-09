"""
Tests for core.notifiers.telegram + the get_notifier() registry.

Phase 1 covers outbound only:
  • Registry returns None when env vars missing — feature is optional.
  • Malformed TELEGRAM_CHAT_ID fails LOUDLY at load time (not silently).
  • notify() composes + truncates the message, dedups identical sends,
    swallows HTTP errors, and writes the audit log.
  • notify() never raises into the caller's path.
  • Outbound payload to Telegram has the expected shape.
"""
import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, AsyncMock, MagicMock

import pytest

from core.notifiers import telegram as tg
from core import notifiers as nfr_pkg


# ---------------------------------------------------------------------------
# Registry — get_notifier() / reset_notifier()
# ---------------------------------------------------------------------------

class TestNotifierRegistry:

    def setup_method(self):
        nfr_pkg.reset_notifier()

    def teardown_method(self):
        nfr_pkg.reset_notifier()

    def test_no_env_returns_none(self, monkeypatch):
        monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
        monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
        assert nfr_pkg.get_notifier() is None

    def test_only_token_set_returns_none(self, monkeypatch):
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "abc:def")
        monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
        assert nfr_pkg.get_notifier() is None

    def test_only_chat_id_set_returns_none(self, monkeypatch):
        monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
        monkeypatch.setenv("TELEGRAM_CHAT_ID", "12345")
        assert nfr_pkg.get_notifier() is None

    def test_both_set_returns_telegram_notifier(self, monkeypatch):
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123:abc")
        monkeypatch.setenv("TELEGRAM_CHAT_ID", "98765")
        n = nfr_pkg.get_notifier()
        assert isinstance(n, tg.TelegramNotifier)

    def test_malformed_chat_id_returns_none_but_logs_error(self, monkeypatch, caplog):
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123:abc")
        monkeypatch.setenv("TELEGRAM_CHAT_ID", "not-an-int")
        n = nfr_pkg.get_notifier()
        assert n is None
        # ValueError must be loud (logged) not silent — we want the operator
        # to notice they typo'd the chat id, rather than have alerts vanish.
        assert any("Telegram notifier disabled" in r.message for r in caplog.records)

    def test_reset_re_evaluates_env(self, monkeypatch):
        monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
        monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
        assert nfr_pkg.get_notifier() is None
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123:abc")
        monkeypatch.setenv("TELEGRAM_CHAT_ID", "1")
        # Cached None — wouldn't see the env change without reset_notifier()
        assert nfr_pkg.get_notifier() is None
        nfr_pkg.reset_notifier()
        assert isinstance(nfr_pkg.get_notifier(), tg.TelegramNotifier)


# ---------------------------------------------------------------------------
# TelegramNotifier — __init__ validation
# ---------------------------------------------------------------------------

class TestTelegramNotifierInit:

    def test_rejects_empty_token(self):
        with pytest.raises(ValueError, match="TELEGRAM_BOT_TOKEN"):
            tg.TelegramNotifier(token="", chat_id="1")

    def test_rejects_non_int_chat_id(self):
        with pytest.raises(ValueError, match="TELEGRAM_CHAT_ID"):
            tg.TelegramNotifier(token="123:abc", chat_id="not-an-int")

    def test_accepts_negative_chat_id_for_groups(self):
        n = tg.TelegramNotifier(token="123:abc", chat_id="-100123456789")
        assert n._chat_id_int == -100123456789

    def test_strips_whitespace_on_chat_id(self):
        n = tg.TelegramNotifier(token="123:abc", chat_id="  42 \n")
        assert n._chat_id_int == 42


# ---------------------------------------------------------------------------
# TelegramNotifier — message composition & truncation
# ---------------------------------------------------------------------------

class TestComposition:

    def _notifier(self, **overrides):
        kwargs = dict(token="123:abc", chat_id="1", max_body_chars=100)
        kwargs.update(overrides)
        return tg.TelegramNotifier(**kwargs)

    def test_compose_joins_title_body(self):
        n = self._notifier()
        out = n._compose("Alert", "Something happened", options=None)
        assert "Alert" in out and "Something happened" in out

    def test_compose_appends_options_block(self):
        n = self._notifier()
        out = n._compose("HIR", "thing broke", options=["REAUTH", "ABORT"])
        assert "Options: REAUTH, ABORT" in out
        assert "dashboard" in out
        assert "/resolve" not in out

    def test_compose_truncates_long_messages(self):
        n = self._notifier(max_body_chars=40)
        out = n._compose("T", "x" * 200, options=None)
        assert len(out) <= 40
        assert out.endswith("…")

    def test_compose_skips_empty_body(self):
        n = self._notifier()
        out = n._compose("Just a title", "", options=None)
        assert "Just a title" in out
        # No leading blank-line gap or trailing empty lines that would
        # confuse Telegram clients.
        assert out.strip() == out

    def test_urgency_prefix_high(self):
        n = self._notifier()
        assert n._urgency_prefix("high") == "⚠ "

    def test_urgency_prefix_default(self):
        n = self._notifier()
        assert n._urgency_prefix("normal") == ""
        assert n._urgency_prefix("anything-unknown") == ""


# ---------------------------------------------------------------------------
# TelegramNotifier — dedup window
# ---------------------------------------------------------------------------

class TestDedup:

    @pytest.fixture
    def quiet_audit(self, tmp_path, monkeypatch):
        """Redirect the audit log to tmp_path so tests don't litter the repo."""
        monkeypatch.setattr(tg, "_AUDIT_LOG_DEFAULT", tmp_path / "audit.log")

    @pytest.mark.asyncio
    async def test_first_send_goes_through(self, quiet_audit):
        n = tg.TelegramNotifier(token="123:abc", chat_id="1")
        with patch.object(n, "_send_message", AsyncMock(return_value=True)) as send:
            ok = await n.notify("t", "b", code="HIR_X")
        assert ok is True
        send.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_immediate_repeat_skipped(self, quiet_audit):
        n = tg.TelegramNotifier(token="123:abc", chat_id="1")
        with patch.object(n, "_send_message", AsyncMock(return_value=True)) as send:
            await n.notify("t", "b", code="HIR_X")
            send.reset_mock()
            ok = await n.notify("t", "b", code="HIR_X")
        assert ok is False
        send.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_different_body_re_fires(self, quiet_audit):
        n = tg.TelegramNotifier(token="123:abc", chat_id="1")
        with patch.object(n, "_send_message", AsyncMock(return_value=True)) as send:
            await n.notify("t", "first body", code="HIR_X")
            await n.notify("t", "different body", code="HIR_X")
        # Both went through — different body = different dedup key
        assert send.await_count == 2

    @pytest.mark.asyncio
    async def test_dedup_window_expires(self, quiet_audit):
        n = tg.TelegramNotifier(token="123:abc", chat_id="1", dedup_seconds=1)
        with patch.object(n, "_send_message", AsyncMock(return_value=True)) as send:
            await n.notify("t", "b", code="HIR_X")
            await asyncio.sleep(1.05)
            await n.notify("t", "b", code="HIR_X")
        assert send.await_count == 2


# ---------------------------------------------------------------------------
# TelegramNotifier — HTTP send path
# ---------------------------------------------------------------------------

class TestSendMessage:

    @pytest.fixture
    def quiet_audit(self, tmp_path, monkeypatch):
        monkeypatch.setattr(tg, "_AUDIT_LOG_DEFAULT", tmp_path / "audit.log")

    @pytest.mark.asyncio
    async def test_payload_shape(self, quiet_audit):
        """Confirm the Telegram API payload has chat_id (int) + text +
        disable_web_page_preview. Bot token must NEVER appear in the body."""
        n = tg.TelegramNotifier(token="SECRET-TOKEN", chat_id="42")
        captured: dict = {}

        class FakeResp:
            status = 200
            async def json(self): return {"ok": True}
            async def __aenter__(self): return self
            async def __aexit__(self, *args): return False

        class FakeSession:
            def __init__(self, *args, **kwargs): pass
            def post(self, url, json=None):
                captured["url"] = url
                captured["json"] = json
                return FakeResp()
            async def __aenter__(self): return self
            async def __aexit__(self, *args): return False

        with patch("aiohttp.ClientSession", FakeSession):
            ok = await n.notify("Hello", "world", code="X")

        assert ok is True
        assert captured["json"]["chat_id"] == 42  # int, not str
        assert "Hello" in captured["json"]["text"]
        assert "world" in captured["json"]["text"]
        assert captured["json"]["disable_web_page_preview"] is True
        # URL has the token in the path (that's how the API works) but it
        # should never appear in the JSON body.
        assert "SECRET-TOKEN" not in json.dumps(captured["json"])

    @pytest.mark.asyncio
    async def test_http_500_returns_false(self, quiet_audit):
        n = tg.TelegramNotifier(token="t", chat_id="1")

        class FakeResp:
            status = 500
            async def json(self): return {}
            async def __aenter__(self): return self
            async def __aexit__(self, *args): return False

        class FakeSession:
            def __init__(self, *args, **kwargs): pass
            def post(self, *a, **kw): return FakeResp()
            async def __aenter__(self): return self
            async def __aexit__(self, *args): return False

        with patch("aiohttp.ClientSession", FakeSession):
            ok = await n.notify("t", "b", code="X")
        assert ok is False

    @pytest.mark.asyncio
    async def test_aiohttp_exception_swallowed(self, quiet_audit):
        n = tg.TelegramNotifier(token="t", chat_id="1")

        class FakeSession:
            def __init__(self, *args, **kwargs):
                raise OSError("network unreachable")

        with patch("aiohttp.ClientSession", FakeSession):
            # Must not raise — never break scan logic on Telegram outage
            ok = await n.notify("t", "b", code="X")
        assert ok is False


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

class TestAuditLog:

    @pytest.mark.asyncio
    async def test_sent_outcome_logged(self, tmp_path):
        log_path = tmp_path / "audit.log"
        n = tg.TelegramNotifier(token="t", chat_id="1", audit_log_path=log_path)
        with patch.object(n, "_send_message", AsyncMock(return_value=True)):
            await n.notify("Title", "Body", code="HIR_FOO")
        lines = log_path.read_text().splitlines()
        assert len(lines) == 1
        rec = json.loads(lines[0])
        assert rec["outcome"] == "sent"
        assert rec["code"] == "HIR_FOO"
        assert "Title" in rec["message_preview"]

    @pytest.mark.asyncio
    async def test_dedup_outcome_logged(self, tmp_path):
        log_path = tmp_path / "audit.log"
        n = tg.TelegramNotifier(token="t", chat_id="1", audit_log_path=log_path)
        with patch.object(n, "_send_message", AsyncMock(return_value=True)):
            await n.notify("T", "B", code="X")
            await n.notify("T", "B", code="X")
        outcomes = [json.loads(l)["outcome"] for l in log_path.read_text().splitlines()]
        assert outcomes == ["sent", "skip-dedup"]

    @pytest.mark.asyncio
    async def test_error_outcome_logged(self, tmp_path):
        log_path = tmp_path / "audit.log"
        n = tg.TelegramNotifier(token="t", chat_id="1", audit_log_path=log_path)
        send = AsyncMock(side_effect=OSError("boom"))
        with patch.object(n, "_send_message", send):
            await n.notify("T", "B", code="X")
        rec = json.loads(log_path.read_text().splitlines()[0])
        assert rec["outcome"] == "error"
        assert "boom" in rec["error"]

    @pytest.mark.asyncio
    async def test_audit_write_failure_is_silent(self, tmp_path):
        # If the audit log itself is unwritable, the notifier must not raise.
        # Force a write failure by pointing the audit path at a *directory*
        # — open(..., "a") on a directory raises IsADirectoryError on POSIX.
        unwritable_dir = tmp_path / "audit-dir"
        unwritable_dir.mkdir()
        n = tg.TelegramNotifier(
            token="t", chat_id="1", audit_log_path=unwritable_dir,
        )
        with patch.object(n, "_send_message", AsyncMock(return_value=True)):
            ok = await n.notify("T", "B", code="X")
        # send still reported success, the failed audit-write must not
        # have propagated
        assert ok is True


# ---------------------------------------------------------------------------
# Package-level notify() helper — fire-and-forget from sync caller
# ---------------------------------------------------------------------------

class TestFireAndForget:

    def setup_method(self):
        nfr_pkg.reset_notifier()

    def teardown_method(self):
        nfr_pkg.reset_notifier()

    def test_no_notifier_is_noop(self, monkeypatch):
        monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
        # Must not raise even with nothing configured
        nfr_pkg.notify("title", "body")

    def test_sync_caller_dispatches_via_thread(self, monkeypatch, tmp_path):
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "t:abc")
        monkeypatch.setenv("TELEGRAM_CHAT_ID", "1")
        monkeypatch.setattr(tg, "_AUDIT_LOG_DEFAULT", tmp_path / "audit.log")

        called: dict = {}
        async def fake_send(self, text):
            called["text"] = text
            return True

        with patch.object(tg.TelegramNotifier, "_send_message", fake_send):
            nfr_pkg.notify("FromSync", "via fire-and-forget", code="X")
            # Wait for the daemon thread to finish — it runs asyncio.run()
            # which is brief.
            import time
            for _ in range(50):
                if "text" in called:
                    break
                time.sleep(0.02)
        assert "FromSync" in called.get("text", "")
