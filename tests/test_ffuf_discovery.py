"""FG9 — ffuf path parsing + CH-6 auto-register.

scan(tool='ffuf') runs ``ffuf -u URL/FUZZ -w WL -of json -s``. ``-s`` (silent)
prints one bare matched FUZZ word per line and ``-of json`` is inert without
``-o``, so stdout is bare words. The old parser only understood JSON / a text
table / http-prefixed lines, so it returned [] on real output — the summarizer
reported "no paths" and the auto-register block registered zero endpoints on
every scan. These tests pin the bare-word shape and prove the reconstructed URLs
reach discover_and_register.
"""
import json

import pytest

from mcp_server.scan_engine.summarizers.web import (
    _parse_ffuf_bare_words,
    _summarize_ffuf,
    parse_ffuf_paths,
)

BARE_SILENT_OUTPUT = "admin\nlogin\n.git\nconfig.php\n"


# ── bare-word parser (the shape that was silently dropped) ────────────────────

def test_bare_words_reconstruct_urls_against_base():
    paths = _parse_ffuf_bare_words(BARE_SILENT_OUTPUT, "http://t.test")
    urls = [p["url"] for p in paths]
    assert urls == [
        "http://t.test/admin",
        "http://t.test/login",
        "http://t.test/.git",
        "http://t.test/config.php",
    ]
    assert all(p["status"] == 0 and p["length"] == 0 for p in paths)


def test_bare_words_need_a_base_url():
    # No base to join onto → nothing can be reconstructed (auth for the handler's
    # startswith('http') filter to keep working).
    assert _parse_ffuf_bare_words(BARE_SILENT_OUTPUT, "") == []


def test_bare_words_skip_chatter_and_dupe_slashes():
    raw = "# comment\n[INFO] progress line\n:: banner ::\n\nadmin\n/api\nhttp://x/y\n"
    urls = [p["url"] for p in _parse_ffuf_bare_words(raw, "http://t.test/")]
    # only the two real payload tokens survive; the leading-slash one is normalized
    assert urls == ["http://t.test/admin", "http://t.test/api"]


# ── parse_ffuf_paths dispatch across all three shapes ─────────────────────────

def test_dispatch_prefers_json():
    raw = json.dumps({"results": [
        {"url": "http://t.test/admin", "status": 200, "length": 12},
    ]})
    paths = parse_ffuf_paths(raw, "http://ignored")
    assert paths == [{"url": "http://t.test/admin", "status": 200, "length": 12}]


def test_dispatch_falls_back_to_text_table():
    raw = "200      GET      512      http://t.test/robots.txt\n"
    paths = parse_ffuf_paths(raw, "http://t.test")
    assert paths and paths[0]["url"] == "http://t.test/robots.txt"
    assert paths[0]["status"] == 200


def test_dispatch_falls_back_to_bare_words():
    paths = parse_ffuf_paths(BARE_SILENT_OUTPUT, "http://t.test")
    assert [p["url"] for p in paths] == [
        "http://t.test/admin", "http://t.test/login",
        "http://t.test/.git", "http://t.test/config.php",
    ]


# ── summarizer no longer reports "no paths" on real -s output ─────────────────

def test_summarizer_finds_bare_word_paths():
    result = _summarize_ffuf(BARE_SILENT_OUTPUT, {"url": "http://t.test"})
    assert result.evidence["total"] == 4
    assert "http://t.test/admin" in [p["url"] for p in result.evidence["paths"]]
    assert result.summary == "ffuf found 4 path(s)"


def test_summarizer_json_regression_still_parses():
    raw = json.dumps({"results": [
        {"url": "http://t.test/a", "status": 200, "length": 1},
        {"url": "http://t.test/b", "status": 301, "length": 2},
    ]})
    result = _summarize_ffuf(raw, {"url": "http://t.test"})
    assert result.evidence["total"] == 2


def test_summarizer_empty_stays_empty():
    result = _summarize_ffuf("", {"url": "http://t.test"})
    assert result.evidence == {"paths": [], "total": 0}
    assert result.summary == "ffuf: no paths discovered"


# ── auto-register wiring: reconstructed URLs reach discover_and_register ───────

@pytest.mark.asyncio
async def test_handle_ffuf_auto_registers_bare_word_paths(monkeypatch):
    import mcp_server.scan_engine as scan_engine
    import mcp_server.scan_engine.discovery as discovery
    import mcp_server.scan_tools.handlers_net as hn
    from tools import kali_runner

    async def fake_exec(cmd, timeout=None):
        return BARE_SILENT_OUTPUT

    captured = {}

    async def fake_register(target, spider_urls, auth_context="none", auth=None):
        captured["target"] = target
        captured["urls"] = list(spider_urls)
        return {"registered": len(spider_urls), "cells": len(spider_urls) * 12}

    monkeypatch.setattr(kali_runner, "exec_command", fake_exec)
    monkeypatch.setattr(hn, "_record", lambda *a, **k: None)
    monkeypatch.setattr(scan_engine, "wrap", lambda tool, raw, ctx: f"[wrapped {tool}]")
    monkeypatch.setattr(discovery, "discover_and_register", fake_register)

    result = await hn._handle_ffuf("http://t.test", "", {})

    assert captured["urls"] == [
        "http://t.test/admin", "http://t.test/login",
        "http://t.test/.git", "http://t.test/config.php",
    ]
    # the operator-facing note reports the auto-registered endpoints/cells
    assert "AUTO-DISCOVERY" in result and "registered 4" in result
