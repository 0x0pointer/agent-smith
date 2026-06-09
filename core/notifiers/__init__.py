"""
Notifier registry — out-of-band alert sinks for HIR / watchdog / scan-complete
/ periodic-status events. Supports Telegram, Slack, and Discord. Any
combination can be enabled by setting the matching env vars; notify() fans
out to every configured sink in parallel.

Lookup is lazy: the first call to get_notifiers() instantiates whichever
adapters are configured (env-driven) and caches the list. When nothing is
configured, the list is empty and callers no-op gracefully.

Public API:
  • get_notifiers()                — returns the cached list (possibly empty)
  • get_notifier()                 — back-compat shim, returns the first or None
  • notify(title, body, **kwargs)  — fire-and-forget convenience helper that
                                     schedules sends to every configured sink
                                     without blocking the caller's path.
  • reset_notifiers() / reset_notifier()
                                   — drop the cached list (next call re-reads env)
"""
from __future__ import annotations

import asyncio
import logging
import os
import threading
from typing import Any, List

_log = logging.getLogger(__name__)

# Cached singleton list — populated on first get_notifiers() call.
_UNSET: Any = object()
_notifiers: Any = _UNSET


def get_notifiers() -> List[Any]:
    """Return the list of active notifiers. Empty list when nothing is
    configured. Env vars are read exactly once per process — call
    reset_notifiers() to re-evaluate after editing .env."""
    global _notifiers
    if _notifiers is _UNSET:
        _notifiers = _load_notifiers()
    return _notifiers


def get_notifier():
    """Back-compat shim. Returns the first configured notifier, or None."""
    notifiers = get_notifiers()
    return notifiers[0] if notifiers else None


def reset_notifiers() -> None:
    """Drop the cached notifier list so the next get_notifiers() re-reads env."""
    global _notifiers
    _notifiers = _UNSET


# Alias for callers that used the singular form before.
reset_notifier = reset_notifiers


def _load_notifiers() -> List[Any]:
    """Inspect the environment and return every configured notifier.

    Each adapter fails loudly on bad config (e.g. bad webhook URL) — that's
    a typo we want the operator to see, not silently disable. A successful
    load may return any subset of [Telegram, Slack, Discord]."""
    out: List[Any] = []

    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    if token and chat_id:
        try:
            from core.notifiers.telegram import TelegramNotifier
            out.append(TelegramNotifier(token=token, chat_id=chat_id))
        except ValueError as e:
            _log.error("Telegram notifier disabled — bad config: %s", e)
        except Exception as e:
            _log.warning("Telegram notifier failed to initialize: %s", e)

    slack_url = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
    if slack_url:
        try:
            from core.notifiers.slack import SlackNotifier
            out.append(SlackNotifier(webhook_url=slack_url))
        except ValueError as e:
            _log.error("Slack notifier disabled — bad config: %s", e)
        except Exception as e:
            _log.warning("Slack notifier failed to initialize: %s", e)

    discord_url = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()
    if discord_url:
        try:
            from core.notifiers.discord import DiscordNotifier
            out.append(DiscordNotifier(webhook_url=discord_url))
        except ValueError as e:
            _log.error("Discord notifier disabled — bad config: %s", e)
        except Exception as e:
            _log.warning("Discord notifier failed to initialize: %s", e)

    return out


def notify(title: str, body: str, **kwargs) -> None:
    """Fire-and-forget notification to every configured sink.

    Safe to call from sync or async contexts. Never raises. When no
    notifier is configured, returns immediately without side effects.

    Keyword arguments are forwarded to each notifier's .notify():
      • urgency: "low" | "normal" | "high"   (default "normal")
      • code: short machine-readable identifier used for dedup
      • options: list[str] of choice tokens to render alongside the body
    """
    notifiers = get_notifiers()
    if not notifiers:
        return
    for nfr in notifiers:
        try:
            _fire_and_forget(nfr.notify(title, body, **kwargs))
        except Exception as e:
            # Each notifier promised never to raise; a failure here means
            # scheduling broke somehow. Swallow + log so scan logic continues
            # and any other sinks still get attempted.
            _log.warning("notifier dispatch failed (%s): %s", type(nfr).__name__, e)


def _fire_and_forget(coro) -> None:
    """Schedule a coroutine without awaiting its result.

    Tries the current event loop first (cheapest path — the dashboard
    process is already async). When no loop is running, falls back to a
    short-lived daemon thread that runs asyncio.run() so callers in sync
    contexts (e.g. core.session.trigger_intervention) still get delivery.
    Errors inside the coroutine are caught and logged here.
    """
    async def _wrapped():
        try:
            await coro
        except Exception as e:
            _log.warning("notifier coroutine failed: %s", e)

    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_wrapped())
        return
    except RuntimeError:
        pass

    def _run_in_thread():
        try:
            asyncio.run(_wrapped())
        except Exception as e:
            _log.warning("notifier thread failed: %s", e)

    threading.Thread(target=_run_in_thread, daemon=True).start()
