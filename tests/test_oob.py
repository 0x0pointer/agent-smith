"""
Tests for out-of-band (OOB) blind-vuln confirmation:
  - core.oob pure helpers (command building + interactsh output parsing)
  - core.session.assets OOB listener + interaction registry
  - session() oob_start / oob_mint / oob_poll handlers (Kali I/O mocked)
"""
import json
import pytest
from unittest.mock import AsyncMock, patch

from core import oob


# ── pure helpers ────────────────────────────────────────────────────────────────

def test_build_start_command_public_has_no_server_flag():
    cmd = oob.build_start_command()
    assert "interactsh-client -json -o" in cmd
    assert "-server" not in cmd
    assert "-token" not in cmd


def test_build_start_command_self_hosted_adds_server_and_token():
    cmd = oob.build_start_command(server_url="https://oob.example.com", token="sekret")
    assert "-server" in cmd and "https://oob.example.com" in cmd
    assert "-token" in cmd and "sekret" in cmd


def test_parse_base_domain_extracts_payload_domain():
    out = (
        "  banner art line\n"
        "[INF] Listing 1 payload for OOB Testing\n"
        "c8r4k2m9x7q1.oast.fun\n"
    )
    assert oob.parse_base_domain(out) == "c8r4k2m9x7q1.oast.fun"


def test_parse_base_domain_self_hosted():
    out = "[INF] Listing 1 payload\nabc123def0.oob.example.com\n"
    assert oob.parse_base_domain(out) == "abc123def0.oob.example.com"


def test_parse_base_domain_none_when_absent():
    assert oob.parse_base_domain("[INF] starting up\nno domain here\n") == ""


def test_mint_subdomain_composes_under_base():
    assert oob.mint_subdomain("c8r4.oast.fun", "deadbeef1234") == "deadbeef1234.c8r4.oast.fun"
    # No base → fall back to the bare correlation id.
    assert oob.mint_subdomain("", "deadbeef1234") == "deadbeef1234"


def test_parse_interactions_filters_by_correlation():
    text = (
        '{"protocol":"http","full-id":"deadbeef1234.c8r4.oast.fun","remote-address":"1.2.3.4"}\n'
        '{"protocol":"dns","full-id":"otherid.c8r4.oast.fun","remote-address":"5.6.7.8"}\n'
        "not-json line\n"
    )
    hits = oob.parse_interactions(text, "deadbeef1234")
    assert len(hits) == 1 and hits[0]["protocol"] == "http"
    # No filter → both JSON lines.
    assert len(oob.parse_interactions(text)) == 2


# ── assets: listener + registry ─────────────────────────────────────────────────

def _start_session():
    import core.session as scan_session
    scan_session.start("https://example.com")


def test_set_get_oob_listener():
    import core.session.assets as A
    _start_session()
    assert A.get_oob_listener() is None
    A.set_oob_listener("c8r4.oast.fun", oob.OOB_OUT_FILE)
    listener = A.get_oob_listener()
    assert listener["base_domain"] == "c8r4.oast.fun"
    assert listener["out_file"] == oob.OOB_OUT_FILE


def test_oob_interactions_register_and_mark_polled():
    import core.session.assets as A
    import core.session as scan_session
    _start_session()
    A.update_known_assets("oob_interactions", [{
        "subdomain": "x.c8r4.oast.fun", "correlation_id": "corr1",
        "linked_cell_id": "cell-1", "minted_at": "2026-06-22T10:00:00Z",
        "polled": False, "hits": 0,
    }])
    reg = scan_session.get()["known_assets"]["oob_interactions"]
    assert len(reg) == 1 and reg[0]["correlation_id"] == "corr1"
    # Dedup on correlation_id — a second mint with same id does not duplicate.
    A.update_known_assets("oob_interactions", [{"correlation_id": "corr1", "subdomain": "dup"}])
    assert len(scan_session.get()["known_assets"]["oob_interactions"]) == 1
    # mark_oob_polled flips the flag + records hits.
    A.mark_oob_polled("corr1", 3)
    reg = scan_session.get()["known_assets"]["oob_interactions"]
    assert reg[0]["polled"] is True and reg[0]["hits"] == 3


# ── session handlers (Kali I/O mocked) ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_oob_start_parses_and_stores_domain():
    from mcp_server.session_tools import _do_oob_start
    _start_session()
    fake_out = "[INF] Listing 1 payload for OOB Testing\nc8r4k2m9x7q1.oast.fun\n"
    with patch("tools.kali_runner.exec_command", new=AsyncMock(return_value=fake_out)):
        res = await _do_oob_start()
    assert "c8r4k2m9x7q1.oast.fun" in res
    import core.session.assets as A
    assert A.get_oob_listener()["base_domain"] == "c8r4k2m9x7q1.oast.fun"


@pytest.mark.asyncio
async def test_oob_mint_requires_listener_then_registers():
    from mcp_server.session_tools import _do_oob_mint
    import core.session as scan_session
    import core.session.assets as A
    _start_session()
    # No listener yet.
    res = _do_oob_mint({"cell_id": "cell-1"})
    assert "oob_start" in res
    # With a listener, minting registers a callback.
    A.set_oob_listener("c8r4.oast.fun", oob.OOB_OUT_FILE)
    res = _do_oob_mint({"cell_id": "cell-1"})
    assert "c8r4.oast.fun" in res
    reg = scan_session.get()["known_assets"]["oob_interactions"]
    assert len(reg) == 1 and reg[0]["linked_cell_id"] == "cell-1"


@pytest.mark.asyncio
async def test_oob_poll_writes_artifact_on_hit(tmp_path, monkeypatch):
    from mcp_server.session_tools import _do_oob_poll
    import core.session.assets as A
    import mcp_server.scan_engine.artifacts as artifacts
    adir = tmp_path / "artifacts"
    adir.mkdir()
    monkeypatch.setattr(artifacts, "_ARTIFACTS_DIR", adir)

    _start_session()
    A.set_oob_listener("c8r4.oast.fun", oob.OOB_OUT_FILE)
    A.update_known_assets("oob_interactions", [{
        "subdomain": "corr1.c8r4.oast.fun", "correlation_id": "corr1",
        "minted_at": "2026-06-22T10:00:00Z", "polled": False, "hits": 0,
    }])
    jsonl = '{"protocol":"dns","full-id":"corr1.c8r4.oast.fun","remote-address":"9.9.9.9"}\n'

    with patch("tools.kali_runner.exec_command", new=AsyncMock(return_value=jsonl)):
        res = await _do_oob_poll({"correlation_id": "corr1"})
    assert "OOB CONFIRMED" in res and "artifact_id=oob_interaction_" in res
    # The artifact actually exists on disk (so it can close a coverage cell).
    assert list(adir.glob("oob_interaction_*.txt"))


@pytest.mark.asyncio
async def test_oob_poll_no_hits_is_graceful():
    from mcp_server.session_tools import _do_oob_poll
    import core.session.assets as A
    _start_session()
    A.set_oob_listener("c8r4.oast.fun", oob.OOB_OUT_FILE)
    with patch("tools.kali_runner.exec_command", new=AsyncMock(return_value="")):
        res = await _do_oob_poll({"correlation_id": "missing"})
    assert "No OOB interactions" in res


# ── pluggable backend: http (dumb logger) mode ───────────────────────────────────

def test_resolve_mode():
    assert oob.resolve_mode("") == "interactsh"
    assert oob.resolve_mode("interactsh") == "interactsh"
    assert oob.resolve_mode("http") == "http"
    assert oob.resolve_mode("garbage") == "interactsh"


def test_mint_http_callback_appends_id():
    assert oob.mint_http_callback("https://oob-logger.example.com", "abc123") == \
        "https://oob-logger.example.com/abc123"
    assert oob.mint_http_callback("https://oob-logger.example.com/", "abc123") == \
        "https://oob-logger.example.com/abc123"


def test_http_poll_url_templating():
    assert oob.http_poll_url("https://x/logs/{id}", "abc") == "https://x/logs/abc"
    assert oob.http_poll_url("https://x/logs", "abc") == "https://x/logs"
    assert oob.http_poll_url("", "abc") == ""


def test_parse_http_hits_matches_correlation():
    log = "GET /abc123 HTTP/1.1 from 1.2.3.4\nGET /other from 9.9.9.9\n"
    hits = oob.parse_http_hits(log, "abc123")
    assert len(hits) == 1 and hits[0]["protocol"] == "http"
    assert oob.parse_http_hits(log, "") == []


@pytest.mark.asyncio
async def test_oob_start_http_mode_records_logger(monkeypatch):
    from mcp_server.session_tools import _do_oob_start
    import core.session.assets as A
    _start_session()
    monkeypatch.setenv("OOB_MODE", "http")
    monkeypatch.setenv("OOB_SERVER_URL", "https://oob-logger.example.com")
    monkeypatch.setenv("OOB_POLL_URL", "https://oob-logger.example.com/logs/{id}")
    # http mode launches no Kali process — exec_command must NOT be needed.
    res = await _do_oob_start()
    assert "mode=http" in res and "oob-logger.example.com" in res
    listener = A.get_oob_listener()
    assert listener["mode"] == "http"
    assert listener["poll_url"] == "https://oob-logger.example.com/logs/{id}"


@pytest.mark.asyncio
async def test_oob_start_http_mode_requires_url(monkeypatch):
    from mcp_server.session_tools import _do_oob_start
    _start_session()
    monkeypatch.setenv("OOB_MODE", "http")
    monkeypatch.delenv("OOB_SERVER_URL", raising=False)
    res = await _do_oob_start()
    assert "OOB_MODE=http needs OOB_SERVER_URL" in res


@pytest.mark.asyncio
async def test_oob_http_mint_and_poll_with_logger(monkeypatch, tmp_path):
    from mcp_server.session_tools import _do_oob_start, _do_oob_mint, _do_oob_poll
    import core.session as scan_session
    import mcp_server.scan_engine.artifacts as artifacts
    adir = tmp_path / "artifacts"
    adir.mkdir()
    monkeypatch.setattr(artifacts, "_ARTIFACTS_DIR", adir)
    monkeypatch.setenv("OOB_MODE", "http")
    monkeypatch.setenv("OOB_SERVER_URL", "https://oob-logger.example.com")
    monkeypatch.setenv("OOB_POLL_URL", "https://oob-logger.example.com/logs/{id}")
    _start_session()

    await _do_oob_start()
    mint = _do_oob_mint({"cell_id": "cell-9"})
    assert "oob-logger.example.com/" in mint
    cid = scan_session.get()["known_assets"]["oob_interactions"][0]["correlation_id"]

    # The logger's read endpoint returns a line mentioning the correlation id.
    log = f"GET /{cid} HTTP/1.1 from 203.0.113.7\n"
    with patch("tools.kali_runner.exec_command", new=AsyncMock(return_value=log)):
        res = await _do_oob_poll({"correlation_id": cid})
    assert "OOB CONFIRMED" in res
    assert list(adir.glob("oob_interaction_*.txt"))


@pytest.mark.asyncio
async def test_oob_http_poll_manual_when_no_poll_url(monkeypatch):
    from mcp_server.session_tools import _do_oob_start, _do_oob_mint, _do_oob_poll
    import core.session as scan_session
    monkeypatch.setenv("OOB_MODE", "http")
    monkeypatch.setenv("OOB_SERVER_URL", "https://oob-logger.example.com")
    monkeypatch.delenv("OOB_POLL_URL", raising=False)
    _start_session()
    await _do_oob_start()
    _do_oob_mint({"cell_id": "c"})
    cid = scan_session.get()["known_assets"]["oob_interactions"][0]["correlation_id"]
    res = await _do_oob_poll({"correlation_id": cid})
    assert "no OOB_POLL_URL configured" in res and cid in res
