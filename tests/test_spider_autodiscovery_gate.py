"""Regression tests: spider spec auto-discovery must not be defeated by a
false-negative crawl-success gate.

Observed in the wild: a thorough-mode crawl found 42 endpoints, but its merged
output (katana + playwright + ZAP, plus crawled page bodies) contained the
substring "no such file or directory", so ``_spider_succeeded`` branded it a
failure. ``spider_ok`` went False, the ``else`` branch that runs
``_spider_autodiscovery_note`` was skipped, and the target's 39-operation
OpenAPI spec (/static/openapi.json) was never imported — the coverage matrix
collapsed to the handful of endpoints the model registered by hand.

Two fixes, two groups of tests:
  1. ``_spider_succeeded`` trusts discovered URLs over an incidental hard-fail
     substring.
  2. ``_handle_spider`` runs auto-discovery REGARDLESS of ``spider_ok`` — the
     spec probe hits the target directly and doesn't need the crawl.
"""
from unittest.mock import AsyncMock, patch

import pytest

from mcp_server.scan_tools._common import _spider_succeeded
import mcp_server.scan_tools.spider as spider


# ── Bug 2: _spider_succeeded no longer false-negatives a productive crawl ──────

class TestSpiderSucceeded:

    def test_empty_is_failure(self):
        assert _spider_succeeded("") is False
        assert _spider_succeeded("   \n  ") is False

    def test_hard_fail_signal_without_urls_is_failure(self):
        # genuine failure: the tool didn't run and produced no crawl URLs
        assert _spider_succeeded("bash: katana: command not found") is False
        assert _spider_succeeded("exec: \"playwright\": no such file or directory") is False

    def test_urls_present_overrides_incidental_hard_fail_substring(self):
        # THE REGRESSION: 42-endpoint crawl whose output happens to contain a
        # hard-fail phrase in a crawled page body / one sub-spider's stderr.
        raw = (
            "http://t/\n"
            "http://t/api/transactions\n"
            "http://t/dashboard\n"
            "[page body] error: no such file or directory\n"  # incidental
        )
        assert _spider_succeeded(raw) is True

    def test_normal_crawl_is_success(self):
        assert _spider_succeeded("http://t/\nhttp://t/login\nhttps://t/api") is True

    def test_ran_but_found_nothing_is_still_success(self):
        # non-empty, no URLs, no hard-fail signal → the tool executed (unchanged)
        assert _spider_succeeded("crawl complete: 0 urls discovered") is True


# ── Bug 1: auto-discovery runs regardless of the spider_ok gate ────────────────

@pytest.fixture
def _patched_spider(monkeypatch):
    """Stub out everything _handle_spider touches except the gate + auto-discovery
    hook under test, so the test asserts only the wiring."""
    monkeypatch.setattr(spider, "_run_spider_fast", AsyncMock(return_value="http://t/\nhttp://t/login"))
    monkeypatch.setattr(spider, "_run_spider_thorough", AsyncMock(return_value="http://t/\nhttp://t/login"))
    monkeypatch.setattr(spider, "_record", lambda *a, **k: None)
    monkeypatch.setattr(spider.scan_session, "get", lambda: {"depth": "standard"})
    monkeypatch.setattr(spider.cost_tracker, "start", lambda *a, **k: "cid")
    monkeypatch.setattr(spider.cost_tracker, "finish", lambda *a, **k: None)
    monkeypatch.setattr(spider.log, "tool_call", lambda *a, **k: None)
    monkeypatch.setattr(spider.log, "tool_result", lambda *a, **k: None)
    autodisc = AsyncMock(return_value="\n\n🧭 AUTO-DISCOVERY: registered 39 endpoint(s)")
    monkeypatch.setattr(spider, "_spider_autodiscovery_note", autodisc)
    # wrap is imported inside the function from scan_engine
    monkeypatch.setattr("mcp_server.scan_engine.wrap", lambda *a, **k: "SPIDER_RESULT")
    return autodisc


@pytest.mark.asyncio
async def test_autodiscovery_runs_when_spider_gate_fails(_patched_spider, monkeypatch):
    """The regression: spider_ok=False must NOT skip auto-discovery."""
    monkeypatch.setattr(spider, "_evaluate_spider_gate", lambda *a, **k: False)
    out = await spider._handle_spider("http://t/", "", {})
    _patched_spider.assert_awaited_once()                # auto-discovery still ran
    assert "AUTO-DISCOVERY" in out
    assert "SPIDER WARNING" in out                        # warning still shown on a weak crawl


@pytest.mark.asyncio
async def test_autodiscovery_runs_when_spider_gate_passes(_patched_spider, monkeypatch):
    """Unchanged happy path: spider_ok=True also runs auto-discovery, no warning."""
    monkeypatch.setattr(spider, "_evaluate_spider_gate", lambda *a, **k: True)
    out = await spider._handle_spider("http://t/", "", {})
    _patched_spider.assert_awaited_once()
    assert "AUTO-DISCOVERY" in out
    assert "SPIDER WARNING" not in out
