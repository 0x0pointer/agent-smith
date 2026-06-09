"""
Tests for the multi-notifier registry (core.notifiers.__init__).

Covers:
  • get_notifiers() returns every env-configured sink.
  • notify() fans out — one bad sink doesn't suppress the others.
  • Back-compat: get_notifier() / reset_notifier() still work.
  • reset_notifiers() re-evaluates env on next call.
"""
import pytest

from core import notifiers as nfr_pkg
from core.notifiers.telegram import TelegramNotifier
from core.notifiers.slack import SlackNotifier
from core.notifiers.discord import DiscordNotifier


SLACK_URL = "https://hooks.slack.com/services/T000/B000/abcdef"
DISCORD_URL = "https://discord.com/api/webhooks/123456789/abcdef"


class TestMultiNotifierLoad:

    def setup_method(self):
        nfr_pkg.reset_notifiers()

    def teardown_method(self):
        nfr_pkg.reset_notifiers()

    def test_no_env_returns_empty_list(self, monkeypatch):
        for k in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID",
                  "SLACK_WEBHOOK_URL", "DISCORD_WEBHOOK_URL"):
            monkeypatch.delenv(k, raising=False)
        assert nfr_pkg.get_notifiers() == []

    def test_only_telegram_loads(self, monkeypatch):
        for k in ("SLACK_WEBHOOK_URL", "DISCORD_WEBHOOK_URL"):
            monkeypatch.delenv(k, raising=False)
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123:abc")
        monkeypatch.setenv("TELEGRAM_CHAT_ID", "42")
        ns = nfr_pkg.get_notifiers()
        assert len(ns) == 1
        assert isinstance(ns[0], TelegramNotifier)

    def test_only_slack_loads(self, monkeypatch):
        for k in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "DISCORD_WEBHOOK_URL"):
            monkeypatch.delenv(k, raising=False)
        monkeypatch.setenv("SLACK_WEBHOOK_URL", SLACK_URL)
        ns = nfr_pkg.get_notifiers()
        assert len(ns) == 1
        assert isinstance(ns[0], SlackNotifier)

    def test_only_discord_loads(self, monkeypatch):
        for k in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "SLACK_WEBHOOK_URL"):
            monkeypatch.delenv(k, raising=False)
        monkeypatch.setenv("DISCORD_WEBHOOK_URL", DISCORD_URL)
        ns = nfr_pkg.get_notifiers()
        assert len(ns) == 1
        assert isinstance(ns[0], DiscordNotifier)

    def test_all_three_load_together(self, monkeypatch):
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123:abc")
        monkeypatch.setenv("TELEGRAM_CHAT_ID", "42")
        monkeypatch.setenv("SLACK_WEBHOOK_URL", SLACK_URL)
        monkeypatch.setenv("DISCORD_WEBHOOK_URL", DISCORD_URL)
        ns = nfr_pkg.get_notifiers()
        types = {type(x) for x in ns}
        assert types == {TelegramNotifier, SlackNotifier, DiscordNotifier}

    def test_one_bad_url_doesnt_break_the_others(self, monkeypatch, caplog):
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123:abc")
        monkeypatch.setenv("TELEGRAM_CHAT_ID", "42")
        monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://evil.example.com/x")  # bad prefix
        monkeypatch.setenv("DISCORD_WEBHOOK_URL", DISCORD_URL)
        ns = nfr_pkg.get_notifiers()
        # Slack is dropped, but Telegram + Discord still register.
        types = {type(x) for x in ns}
        assert types == {TelegramNotifier, DiscordNotifier}
        # And the operator sees the misconfig in logs, not silent disable.
        assert any("Slack notifier disabled" in r.message for r in caplog.records)


class TestBackCompatSingular:

    def setup_method(self):
        nfr_pkg.reset_notifiers()

    def teardown_method(self):
        nfr_pkg.reset_notifiers()

    def test_get_notifier_returns_first_sink(self, monkeypatch):
        monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
        monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
        monkeypatch.delenv("DISCORD_WEBHOOK_URL", raising=False)
        monkeypatch.setenv("SLACK_WEBHOOK_URL", SLACK_URL)
        n = nfr_pkg.get_notifier()
        assert isinstance(n, SlackNotifier)

    def test_get_notifier_returns_none_when_empty(self, monkeypatch):
        for k in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID",
                  "SLACK_WEBHOOK_URL", "DISCORD_WEBHOOK_URL"):
            monkeypatch.delenv(k, raising=False)
        assert nfr_pkg.get_notifier() is None

    def test_reset_notifier_alias_still_works(self, monkeypatch):
        # The plural form is canonical now but old call sites use reset_notifier.
        monkeypatch.setenv("SLACK_WEBHOOK_URL", SLACK_URL)
        assert nfr_pkg.get_notifier() is not None
        monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
        nfr_pkg.reset_notifier()  # the singular alias
        assert nfr_pkg.get_notifier() is None


class TestNotifyFanout:

    def setup_method(self):
        nfr_pkg.reset_notifiers()

    def teardown_method(self):
        nfr_pkg.reset_notifiers()

    @pytest.mark.asyncio
    async def test_notify_schedules_one_send_per_sink(self, monkeypatch):
        """notify() must call .notify on every configured sink, not just one.

        The fire-and-forget machinery defers actual HTTP — we just verify
        that every sink's coroutine is scheduled and eventually awaited.
        """
        import asyncio
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123:abc")
        monkeypatch.setenv("TELEGRAM_CHAT_ID", "42")
        monkeypatch.setenv("SLACK_WEBHOOK_URL", SLACK_URL)
        monkeypatch.setenv("DISCORD_WEBHOOK_URL", DISCORD_URL)

        sinks = nfr_pkg.get_notifiers()
        sent: list[str] = []

        async def _fake_notify(self, title, body, **kw):
            sent.append(type(self).__name__)
            return True

        # Monkey-patch each sink's .notify method directly so we capture
        # the fanout without actually hitting any external API.
        for s in sinks:
            monkeypatch.setattr(s, "notify", _fake_notify.__get__(s, type(s)))

        # Call from an active event loop so _fire_and_forget uses the
        # create_task path (synchronous test contexts otherwise spawn
        # threads which are harder to await in a unit test).
        nfr_pkg.notify("HIR_TEST", "body", code="HIR_TEST")

        # Yield once so the just-scheduled tasks can run.
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        assert sorted(sent) == sorted(["TelegramNotifier", "SlackNotifier", "DiscordNotifier"])

    def test_notify_with_no_sinks_is_noop(self, monkeypatch):
        # Should not raise — and certainly should not look up event loops.
        for k in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID",
                  "SLACK_WEBHOOK_URL", "DISCORD_WEBHOOK_URL"):
            monkeypatch.delenv(k, raising=False)
        nfr_pkg.notify("any", "thing")  # must just return
