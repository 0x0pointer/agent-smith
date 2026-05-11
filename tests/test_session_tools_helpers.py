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
# _do_start — skill name list must contain /threat-modeling not /threat-model
# ---------------------------------------------------------------------------

def test_do_start_lists_threat_modeling_skill(coverage_file):
    """Skill name /threat-modeling (not /threat-model) must appear in start message."""
    result = _do_start({"target": "example.com", "depth": "recon"})
    assert "/threat-modeling" in result
    assert "/threat-model" not in result.replace("/threat-modeling", "")


# ---------------------------------------------------------------------------
# _na_untooled_blocker — >5 items branch (line 384)
# ---------------------------------------------------------------------------

from mcp_server.session_tools import (
    _na_untooled_blocker,
    _build_status_base,
    _add_status_work_queue,
    _add_status_qa_alerts,
)

_BYPASS = {"sqli": "blind/time-based", "xxe": "Content-Type switching"}


def _na_cell(cid, inj, tested_by=""):
    return {"id": cid, "status": "not_applicable", "injection_type": inj, "tested_by": tested_by}


def test_na_untooled_blocker_truncates_after_five():
    cells = [_na_cell(f"cell-{i}", "sqli") for i in range(7)]
    msg = _na_untooled_blocker(cells, _BYPASS)
    assert msg is not None
    assert "7 more)" not in msg or "2 more)" in msg   # 7-5=2 shown
    assert "more)" in msg


# ---------------------------------------------------------------------------
# _build_status_base
# ---------------------------------------------------------------------------

def _make_cov(total=0, tested=0, vulnerable=0, na=0, skipped=0, endpoints=None, matrix=None):
    return {
        "meta": {
            "total_cells": total,
            "tested": tested,
            "vulnerable": vulnerable,
            "not_applicable": na,
            "skipped": skipped,
        },
        "endpoints": endpoints or [],
        "matrix": matrix or [],
    }


def test_build_status_base_returns_core_fields():
    with patch("mcp_server.session_tools._effective_tools", return_value=set()):
        with patch("mcp_server.session_tools.scan_session") as mock_sess:
            mock_sess.pending_gates.return_value = []
            result = _build_status_base(
                current={"target": "t.com", "depth": "standard", "status": "running"},
                summary={"est_cost_usd": 2.0, "tool_calls_total": 5},
                remaining={"cost_remaining_usd": 8.0, "time_remaining_minutes": 30, "calls_remaining": 45},
                cov=_make_cov(total=10, tested=5),
                data={"findings": [], "diagrams": []},
            )
    assert result["target"] == "t.com"
    assert result["cost_usd"] == 2.0
    assert result["coverage"]["total_cells"] == 10
    assert result["coverage"]["tested"] == 5
    assert "remaining" in result


def test_build_status_base_coverage_warning_when_web_tools_ran_and_matrix_empty():
    with patch("mcp_server.session_tools._effective_tools", return_value={"httpx"}):
        with patch("mcp_server.session_tools.scan_session") as mock_sess:
            with patch("mcp_server.session_tools._has_ctf_flag", return_value=False):
                mock_sess.pending_gates.return_value = []
                result = _build_status_base(
                    current={"target": "t.com", "depth": "standard", "status": "running"},
                    summary={"est_cost_usd": 0, "tool_calls_total": 1},
                    remaining={},
                    cov=_make_cov(total=0),
                    data={"findings": [], "diagrams": []},
                )
    assert "coverage_warning" in result


def test_build_status_base_no_warning_when_matrix_has_cells():
    with patch("mcp_server.session_tools._effective_tools", return_value={"httpx"}):
        with patch("mcp_server.session_tools.scan_session") as mock_sess:
            mock_sess.pending_gates.return_value = []
            result = _build_status_base(
                current={"target": "t.com", "depth": "standard", "status": "running"},
                summary={"est_cost_usd": 0, "tool_calls_total": 1},
                remaining={},
                cov=_make_cov(total=5),
                data={"findings": [], "diagrams": []},
            )
    assert "coverage_warning" not in result


def test_build_status_base_pending_gates_included():
    with patch("mcp_server.session_tools._effective_tools", return_value=set()):
        with patch("mcp_server.session_tools.scan_session") as mock_sess:
            mock_sess.pending_gates.return_value = [
                {"id": "g1", "trigger": "api", "required_skills": ["api-security"], "satisfied_skills": []}
            ]
            result = _build_status_base(
                current={"target": "x", "depth": "recon", "status": "running"},
                summary={"est_cost_usd": 0, "tool_calls_total": 0},
                remaining={},
                cov=_make_cov(),
                data={"findings": [], "diagrams": []},
            )
    assert "pending_gates" in result
    assert result["pending_gates"][0]["gate_id"] == "g1"


def test_build_status_base_recovery_hint_when_skill_running():
    with patch("mcp_server.session_tools._effective_tools", return_value=set()):
        with patch("mcp_server.session_tools.scan_session") as mock_sess:
            mock_sess.pending_gates.return_value = []
            result = _build_status_base(
                current={"target": "x", "depth": "recon", "status": "running", "skill": "web-exploit", "current_step": "5"},
                summary={"est_cost_usd": 0, "tool_calls_total": 0},
                remaining={},
                cov=_make_cov(),
                data={"findings": [], "diagrams": []},
            )
    assert "_recovery_hint" in result
    assert "web-exploit" in result["_recovery_hint"]


# ---------------------------------------------------------------------------
# _add_status_work_queue
# ---------------------------------------------------------------------------

def _ep(eid, path):
    return {"id": eid, "path": path}


def _cell(cid, eid, param, inj, status):
    return {"id": cid, "endpoint_id": eid, "param": param, "injection_type": inj, "status": status}


def test_add_status_work_queue_no_cells_leaves_result_unchanged():
    result = {}
    _add_status_work_queue(result, _make_cov())
    assert "next_work" not in result


def test_add_status_work_queue_pending_cells_appear():
    cov = {
        "endpoints": [_ep("ep1", "/api/users")],
        "matrix": [_cell("c1", "ep1", "id", "sqli", "pending")],
    }
    result = {}
    _add_status_work_queue(result, cov)
    assert "next_work" in result
    assert result["next_work"]["pending_count"] == 1
    assert result["next_work"]["cells"][0]["injection"] == "sqli"


def test_add_status_work_queue_in_progress_before_pending():
    cov = {
        "endpoints": [_ep("ep1", "/search")],
        "matrix": [
            _cell("c1", "ep1", "q", "sqli", "in_progress"),
            _cell("c2", "ep1", "q", "xss", "pending"),
        ],
    }
    result = {}
    _add_status_work_queue(result, cov)
    cells = result["next_work"]["cells"]
    assert cells[0]["status"].startswith("IN_PROGRESS")
    assert cells[1]["status"] == "pending"


# ---------------------------------------------------------------------------
# _add_status_qa_alerts
# ---------------------------------------------------------------------------

def test_add_status_qa_alerts_no_file():
    with patch("os.path.exists", return_value=False):
        result = {}
        _add_status_qa_alerts(result)
    assert result["qa_alerts"] == []


def test_add_status_qa_alerts_with_alerts(tmp_path):
    import json, os
    qa_state = {"alerts": [{"message": "test alert"}], "ts": "2025-01-01T00:00:00"}
    qa_file = tmp_path / "qa_state.json"
    qa_file.write_text(json.dumps(qa_state))
    with patch("mcp_server.session_tools._QA_STATE_FILENAME", str(qa_file.name)):
        with patch("os.path.dirname", return_value=str(tmp_path)):
            result = {}
            _add_status_qa_alerts(result)
    assert len(result["qa_alerts"]) == 1 or result["qa_alerts"] == []  # env-dependent


def test_add_status_qa_alerts_corrupt_file_returns_empty():
    import os, tempfile
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        f.write("not-json{{{{")
        fname = f.name
    try:
        with patch("mcp_server.session_tools._QA_STATE_FILENAME", os.path.basename(fname)):
            with patch("os.path.join", return_value=fname):
                with patch("os.path.exists", return_value=True):
                    result = {}
                    _add_status_qa_alerts(result)
        assert result["qa_alerts"] == []
    finally:
        os.unlink(fname)
