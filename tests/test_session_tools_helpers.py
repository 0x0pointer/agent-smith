"""
Tests for mcp_server.session_tools helper functions:
  - _has_ctf_flag()
  - _effective_tools()
  - _do_start() skill name list contains /threat-modeling (not /threat-model)
"""
import pytest
from unittest.mock import patch

import mcp_server._app as _app
from mcp_server.session_tools import _has_ctf_flag, _effective_tools, _do_start


# ---------------------------------------------------------------------------
# _has_ctf_flag
# ---------------------------------------------------------------------------

def test_has_ctf_flag_empty_data_returns_false():
    assert _has_ctf_flag({}) is False


def test_has_ctf_flag_no_findings_returns_false():
    assert _has_ctf_flag({"findings": []}) is False


def test_has_ctf_flag_detects_ctf_pattern_in_title():
    data = {"findings": [{"title": "Flag: CTF{s0me_flag_here}", "evidence": "", "description": ""}]}
    assert _has_ctf_flag(data) is True


def test_has_ctf_flag_detects_htb_pattern_in_evidence():
    data = {"findings": [{"title": "RCE", "evidence": "HTB{h4sh_here}", "description": ""}]}
    assert _has_ctf_flag(data) is True


def test_has_ctf_flag_detects_pattern_in_description():
    data = {"findings": [{"title": "x", "evidence": "", "description": "flag{found_it_here}"}]}
    assert _has_ctf_flag(data) is True


def test_has_ctf_flag_skips_short_flag_values():
    """Pattern requires >=4 chars inside braces."""
    data = {"findings": [{"title": "CTF{x}", "evidence": "", "description": ""}]}
    assert _has_ctf_flag(data) is False


def test_has_ctf_flag_detects_session_ctf_marker(monkeypatch):
    """When session.json has ctf=True, flag pattern check is bypassed."""
    import core.session
    core.session.start("example.com")
    # Manually set ctf marker
    import core.session as sess
    current = sess.get()
    current["ctf"] = True
    monkeypatch.setattr(sess, "_current", current)
    assert _has_ctf_flag({}) is True


def test_has_ctf_flag_multiple_findings_one_match():
    data = {
        "findings": [
            {"title": "Info leak", "evidence": "No flag", "description": "clean"},
            {"title": "RCE", "evidence": "CTF{pwned_flag_2024}", "description": ""},
        ]
    }
    assert _has_ctf_flag(data) is True


def test_has_ctf_flag_no_prefix_mismatch():
    """Prefix must be 2–10 alphanumeric chars; a single char should not match."""
    data = {"findings": [{"title": "x{long_enough}", "evidence": "", "description": ""}]}
    # 'x' is 1 char — does not satisfy {2,10}, so no match
    assert _has_ctf_flag(data) is False


# ---------------------------------------------------------------------------
# _effective_tools
# ---------------------------------------------------------------------------

def test_effective_tools_returns_in_memory_tools():
    _app._session_tools_called.clear()
    _app._session_tools_called.add("nmap")
    result = _effective_tools()
    assert "nmap" in result


def test_effective_tools_returns_session_json_tools(monkeypatch):
    """Tools persisted in session.json are included even if not in memory."""
    import core.session
    core.session.start("example.com")
    core.session.add_tool_called("httpx")
    _app._session_tools_called.clear()
    result = _effective_tools()
    assert "httpx" in result


def test_effective_tools_merges_both_sources(monkeypatch):
    """Union of in-memory and session.json sources."""
    import core.session
    core.session.start("example.com")
    core.session.add_tool_called("nuclei")
    _app._session_tools_called.clear()
    _app._session_tools_called.add("ffuf")
    result = _effective_tools()
    assert "nuclei" in result
    assert "ffuf" in result


def test_effective_tools_deduplicates(monkeypatch):
    """Same tool in both sources appears only once."""
    import core.session
    core.session.start("example.com")
    core.session.add_tool_called("nmap")
    _app._session_tools_called.clear()
    _app._session_tools_called.add("nmap")
    result = _effective_tools()
    assert len([t for t in result if t == "nmap"]) == 1


def test_effective_tools_no_session_returns_in_memory_only(monkeypatch):
    """When no session is running, only the in-memory set is returned."""
    import core.session
    monkeypatch.setattr(core.session, "_current", None)
    _app._session_tools_called.clear()
    _app._session_tools_called.add("subfinder")
    result = _effective_tools()
    assert "subfinder" in result


# ---------------------------------------------------------------------------
# _do_start — must return directive response with concrete next action
# ---------------------------------------------------------------------------

def test_do_start_returns_directive_response(coverage_file):
    """Start message must include a concrete next action, not a skill menu."""
    result = _do_start({"target": "example.com", "depth": "recon"})
    assert "EXECUTE NOW" in result
    assert "scan(tool='httpx'" in result
    assert "example.com" in result
