"""
Tests for core.qa_agent — session check and QADaemon cycle logic.
"""
import asyncio
import json
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import core.qa_agent
import core.quick_log
from core.qa_agent import (
    _session_is_running, _read_qa_state,
    _sanitize_history, _init_llm, _build_graph, QADaemon,
    _deterministic_qa_checks, _load_json, _format_findings_for_semantic_review,
    _deduplicate,
)
from core.quick_log import QuickLog


# ---------------------------------------------------------------------------
# _session_is_running()
# ---------------------------------------------------------------------------

def test_session_is_running_returns_false_when_file_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(core.qa_agent, "_SESSION_FILE", tmp_path / "session.json")
    assert _session_is_running() is False


def test_session_is_running_returns_false_when_status_complete(tmp_path, monkeypatch):
    f = tmp_path / "session.json"
    f.write_text(json.dumps({"status": "complete"}))
    monkeypatch.setattr(core.qa_agent, "_SESSION_FILE", f)
    assert _session_is_running() is False


def test_session_is_running_returns_true_when_status_running(tmp_path, monkeypatch):
    f = tmp_path / "session.json"
    f.write_text(json.dumps({"status": "running"}))
    monkeypatch.setattr(core.qa_agent, "_SESSION_FILE", f)
    assert _session_is_running() is True


def test_session_is_running_returns_false_when_corrupt_json(tmp_path, monkeypatch):
    f = tmp_path / "session.json"
    f.write_text("not valid json {{{")
    monkeypatch.setattr(core.qa_agent, "_SESSION_FILE", f)
    assert _session_is_running() is False


# ---------------------------------------------------------------------------
# _load_json()
# ---------------------------------------------------------------------------

def test_load_json_returns_empty_when_file_missing(tmp_path):
    result = _load_json(tmp_path / "nonexistent.json")
    assert result == {}


def test_load_json_returns_parsed_dict(tmp_path):
    f = tmp_path / "data.json"
    f.write_text(json.dumps({"key": "value", "num": 42}))
    result = _load_json(f)
    assert result == {"key": "value", "num": 42}


def test_load_json_returns_empty_on_corrupt_json(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text("not valid json {{{")
    result = _load_json(f)
    assert result == {}


# ---------------------------------------------------------------------------
# _deterministic_qa_checks()
# ---------------------------------------------------------------------------

def test_deterministic_no_alerts_on_clean_summary():
    alerts = _deterministic_qa_checks("1 tool call: nmap", {}, {})
    assert alerts == []


def test_deterministic_scope_drift_detected():
    summary = "Possible off-scope targets used: evil.com"
    alerts = _deterministic_qa_checks(summary, {}, {})
    codes = [a["code"] for a in alerts]
    assert "SCOPE_DRIFT" in codes
    scope_alert = next(a for a in alerts if a["code"] == "SCOPE_DRIFT")
    assert scope_alert["urgency"] == "high"
    assert scope_alert["blocking"] is False
    assert "evil.com" in scope_alert["message"]


def test_deterministic_coverage_stall_detected():
    summary = "WARNING: coverage stale (35 min), 10 pending"
    alerts = _deterministic_qa_checks(summary, {}, {})
    codes = [a["code"] for a in alerts]
    assert "COVERAGE_STALL" in codes
    stall = next(a for a in alerts if a["code"] == "COVERAGE_STALL")
    assert stall["urgency"] == "high"
    assert "10 cells" in stall["message"]


def test_deterministic_coverage_stall_skipped_when_pending_zero():
    summary = "WARNING: coverage stale (35 min), 0 pending"
    alerts = _deterministic_qa_checks(summary, {}, {})
    codes = [a["code"] for a in alerts]
    assert "COVERAGE_STALL" not in codes


def test_deterministic_spider_without_coverage():
    summary = "Endpoints found: 15"
    coverage_data = {"meta": {"total_cells": 0}}
    alerts = _deterministic_qa_checks(summary, {}, coverage_data)
    codes = [a["code"] for a in alerts]
    assert "SPIDER_WITHOUT_COVERAGE" in codes
    alert = next(a for a in alerts if a["code"] == "SPIDER_WITHOUT_COVERAGE")
    assert "15" in alert["message"]


def test_deterministic_spider_without_coverage_skipped_when_matrix_populated():
    summary = "Endpoints found: 15"
    coverage_data = {"meta": {"total_cells": 30}}
    alerts = _deterministic_qa_checks(summary, {}, coverage_data)
    codes = [a["code"] for a in alerts]
    assert "SPIDER_WITHOUT_COVERAGE" not in codes


def test_deterministic_poc_gap_detected():
    findings_data = {
        "findings": [
            {"title": "SQLi", "severity": "critical", "poc_files": []},
            {"title": "XSS", "severity": "high"},
        ]
    }
    alerts = _deterministic_qa_checks("", findings_data, {})
    codes = [a["code"] for a in alerts]
    assert "POC_GAP" in codes
    poc = next(a for a in alerts if a["code"] == "POC_GAP")
    assert poc["urgency"] == "medium"
    assert "2/2" in poc["message"]


def test_deterministic_poc_gap_truncates_titles_at_three():
    """More than 3 missing-PoC findings should show +N more in the message."""
    findings_data = {
        "findings": [
            {"title": f"Finding {i}", "severity": "critical", "poc_files": []}
            for i in range(5)
        ]
    }
    alerts = _deterministic_qa_checks("", findings_data, {})
    poc = next(a for a in alerts if a["code"] == "POC_GAP")
    assert "+2 more" in poc["message"]


def test_deterministic_poc_gap_skipped_when_all_have_poc():
    findings_data = {
        "findings": [
            {"title": "SQLi", "severity": "critical", "poc_files": ["sqli.http"]},
        ]
    }
    alerts = _deterministic_qa_checks("", findings_data, {})
    codes = [a["code"] for a in alerts]
    assert "POC_GAP" not in codes


def test_deterministic_skill_chain_gap():
    summary = "Findings: 2 critical, 1 high"
    alerts = _deterministic_qa_checks(summary, {}, {})
    codes = [a["code"] for a in alerts]
    assert "SKILL_CHAIN_GAP" in codes


def test_deterministic_skill_chain_gap_skipped_when_web_exploit_ran():
    summary = "Findings: 2 critical, 1 high\nweb-exploit ran"
    alerts = _deterministic_qa_checks(summary, {}, {})
    codes = [a["code"] for a in alerts]
    assert "SKILL_CHAIN_GAP" not in codes


def test_deterministic_tool_inactivity_above_threshold():
    summary = "Last tool call: 15 minutes ago"
    alerts = _deterministic_qa_checks(summary, {}, {})
    codes = [a["code"] for a in alerts]
    assert "TOOL_INACTIVITY" in codes
    inact = next(a for a in alerts if a["code"] == "TOOL_INACTIVITY")
    assert inact["urgency"] == "low"
    assert "15min" in inact["message"]


def test_deterministic_tool_inactivity_below_threshold():
    summary = "Last tool call: 5 minutes ago"
    alerts = _deterministic_qa_checks(summary, {}, {})
    codes = [a["code"] for a in alerts]
    assert "TOOL_INACTIVITY" not in codes


def test_deterministic_bulk_marking_detected():
    summary = "Bulk-marking warning: 8 N/A cells lack tested_by"
    alerts = _deterministic_qa_checks(summary, {}, {})
    codes = [a["code"] for a in alerts]
    assert "BULK_MARKING" in codes
    bulk = next(a for a in alerts if a["code"] == "BULK_MARKING")
    assert bulk["blocking"] is True


def test_deterministic_coverage_integrity_detected():
    summary = "5 tested/vulnerable cells have no tested_by tool"
    alerts = _deterministic_qa_checks(summary, {}, {})
    codes = [a["code"] for a in alerts]
    assert "COVERAGE_INTEGRITY" in codes
    integ = next(a for a in alerts if a["code"] == "COVERAGE_INTEGRITY")
    assert integ["blocking"] is True
    assert "5" in integ["message"]


def test_deterministic_gate_pending_high_urgency():
    summary = "Pending gates: credential-audit (requires: /credential-audit) triggered 20min ago"
    alerts = _deterministic_qa_checks(summary, {}, {})
    codes = [a["code"] for a in alerts]
    assert "GATE_PENDING" in codes
    gate = next(a for a in alerts if a["code"] == "GATE_PENDING")
    assert gate["urgency"] == "high"
    assert "20min" in gate["message"]


def test_deterministic_gate_pending_medium_urgency():
    summary = "Pending gates: post-exploit (requires: /post-exploit) triggered 8min ago"
    alerts = _deterministic_qa_checks(summary, {}, {})
    codes = [a["code"] for a in alerts]
    assert "GATE_PENDING" in codes
    gate = next(a for a in alerts if a["code"] == "GATE_PENDING")
    assert gate["urgency"] == "medium"


def test_deterministic_gate_pending_skipped_when_recent():
    summary = "Pending gates: post-exploit (requires: /post-exploit) triggered 2min ago"
    alerts = _deterministic_qa_checks(summary, {}, {})
    codes = [a["code"] for a in alerts]
    assert "GATE_PENDING" not in codes


def test_deterministic_rce_gate_false_positive():
    summary = "Pending gates: rce-check (requires: /post-exploit) triggered 10min ago\nFindings: 2 medium, 1 low"
    alerts = _deterministic_qa_checks(summary, {}, {})
    codes = [a["code"] for a in alerts]
    assert "RCE_GATE_FALSE_POSITIVE" in codes


def test_deterministic_rce_gate_not_false_positive_with_high_finding():
    summary = "Pending gates: rce-check (requires: /post-exploit) triggered 10min ago\nFindings: 1 high"
    alerts = _deterministic_qa_checks(summary, {}, {})
    codes = [a["code"] for a in alerts]
    assert "RCE_GATE_FALSE_POSITIVE" not in codes


def test_deterministic_multiple_alerts_can_fire():
    summary = (
        "Possible off-scope targets used: evil.com\n"
        "Last tool call: 20 minutes ago\n"
        "Bulk-marking warning: 3 N/A cells lack tested_by"
    )
    alerts = _deterministic_qa_checks(summary, {}, {})
    codes = [a["code"] for a in alerts]
    assert "SCOPE_DRIFT" in codes
    assert "TOOL_INACTIVITY" in codes
    assert "BULK_MARKING" in codes


# ---------------------------------------------------------------------------
# _format_findings_for_semantic_review()
# ---------------------------------------------------------------------------

def test_format_findings_empty_findings():
    result = _format_findings_for_semantic_review({})
    assert result == ""


def test_format_findings_no_high_critical():
    findings_data = {
        "findings": [
            {"title": "Info leak", "severity": "info"},
            {"title": "Low issue", "severity": "low"},
        ]
    }
    result = _format_findings_for_semantic_review(findings_data)
    assert result == ""


def test_format_findings_includes_high_critical():
    findings_data = {
        "findings": [
            {
                "title": "SQL Injection",
                "severity": "critical",
                "description": "Classic SQLi on login",
                "evidence": "' OR 1=1",
                "business_impact": "Full DB access",
            },
            {
                "title": "XSS",
                "severity": "high",
                "description": "Stored XSS in profile",
                "evidence": "<script>alert(1)</script>",
            },
        ]
    }
    result = _format_findings_for_semantic_review(findings_data)
    assert "[CRITICAL]" in result
    assert "SQL Injection" in result
    assert "[HIGH]" in result
    assert "XSS" in result


def test_format_findings_caps_at_ten():
    findings_data = {
        "findings": [
            {"title": f"Finding {i}", "severity": "high", "description": "desc"}
            for i in range(15)
        ]
    }
    result = _format_findings_for_semantic_review(findings_data)
    # Only 10 should be included — count how many [HIGH] markers appear
    assert result.count("[HIGH]") == 10


# ---------------------------------------------------------------------------
# _deduplicate()
# ---------------------------------------------------------------------------

def test_deduplicate_empty_lists():
    assert _deduplicate([], []) == []


def test_deduplicate_no_previous_keeps_all():
    new_alerts = [
        {"code": "SCOPE_DRIFT", "urgency": "high", "message": "drift detected"},
        {"code": "POC_GAP", "urgency": "medium", "message": "missing pocs"},
    ]
    result = _deduplicate(new_alerts, [])
    assert len(result) == 2


def test_deduplicate_drops_same_code_and_message():
    alert = {"code": "SCOPE_DRIFT", "urgency": "high", "message": "drift detected"}
    result = _deduplicate([alert], [alert])
    assert result == []


def test_deduplicate_keeps_same_code_different_message():
    prev = {"code": "SCOPE_DRIFT", "urgency": "high", "message": "old target"}
    new = {"code": "SCOPE_DRIFT", "urgency": "high", "message": "new target"}
    result = _deduplicate([new], [prev])
    assert len(result) == 1
    assert result[0]["message"] == "new target"


def test_deduplicate_keeps_different_codes():
    prev = {"code": "SCOPE_DRIFT", "urgency": "high", "message": "drift"}
    new = {"code": "POC_GAP", "urgency": "medium", "message": "missing"}
    result = _deduplicate([new], [prev])
    assert len(result) == 1
    assert result[0]["code"] == "POC_GAP"


def test_deduplicate_returns_new_when_urgency_changed():
    prev = {"code": "TOOL_INACTIVITY", "urgency": "low", "message": "idle 15min"}
    new = {"code": "TOOL_INACTIVITY", "urgency": "high", "message": "idle 15min"}
    # Same message → deduped regardless of urgency change (dedup is by code+message)
    result = _deduplicate([new], [prev])
    assert result == []


# ---------------------------------------------------------------------------
# _read_qa_state()
# ---------------------------------------------------------------------------

def test_read_qa_state_returns_empty_when_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(core.qa_agent, "_QA_STATE_FILE", tmp_path / "qa_state.json")
    assert _read_qa_state() == {}


def test_read_qa_state_returns_parsed_json(tmp_path, monkeypatch):
    qa_state = tmp_path / "qa_state.json"
    qa_state.write_text(json.dumps({"alerts": [], "ts": "2026-01-01T00:00:00+00:00"}))
    monkeypatch.setattr(core.qa_agent, "_QA_STATE_FILE", qa_state)
    result = _read_qa_state()
    assert result["alerts"] == []


def test_read_qa_state_returns_empty_on_corrupt_json(tmp_path, monkeypatch):
    qa_state = tmp_path / "qa_state.json"
    qa_state.write_text("not valid json {{{")
    monkeypatch.setattr(core.qa_agent, "_QA_STATE_FILE", qa_state)
    assert _read_qa_state() == {}


# ---------------------------------------------------------------------------
# _sanitize_history()
# ---------------------------------------------------------------------------

def test_sanitize_history_filters_non_dicts():
    raw = [{"ts": "2026-01-01T00:00:00+00:00", "summary_sent": "s", "alerts": [], "smith_actions": []}, "not-a-dict", 42]
    result = _sanitize_history(raw)
    assert len(result) == 1


def test_sanitize_history_caps_field_length():
    long_ts = "X" * 100
    alerts = [{"urgency": "high", "message": "a"}] * 20
    smith = [{"type": "TOOL"}] * 100
    raw = [{"ts": long_ts, "summary_sent": "s", "alerts": alerts, "smith_actions": smith}]
    result = _sanitize_history(raw)
    assert len(result[0]["ts"]) <= 50
    assert len(result[0]["alerts"]) <= 10
    assert len(result[0]["smith_actions"]) <= 50


def test_sanitize_history_keeps_valid_alert_dicts():
    raw = [{"ts": "t", "summary_sent": "s",
            "alerts": [{"urgency": "high"}, "not-dict"],
            "smith_actions": []}]
    result = _sanitize_history(raw)
    assert result[0]["alerts"] == [{"urgency": "high"}]


def test_sanitize_history_empty_list():
    assert _sanitize_history([]) == []


def test_sanitize_history_includes_smith_reply_when_present():
    raw = [{"ts": "t", "summary_sent": "s", "alerts": [],
            "smith_actions": [], "smith_reply": "Acknowledged."}]
    result = _sanitize_history(raw)
    assert result[0]["smith_reply"] == "Acknowledged."


def test_sanitize_history_smith_reply_is_none_when_absent():
    raw = [{"ts": "t", "summary_sent": "s", "alerts": [], "smith_actions": []}]
    result = _sanitize_history(raw)
    assert result[0]["smith_reply"] is None


def test_sanitize_history_truncates_long_smith_reply():
    long_reply = "A" * 3000
    raw = [{"ts": "t", "summary_sent": "s", "alerts": [],
            "smith_actions": [], "smith_reply": long_reply}]
    result = _sanitize_history(raw)
    assert len(result[0]["smith_reply"]) <= 2000


# ---------------------------------------------------------------------------
# QADaemon._cycle() — early-return guards
# ---------------------------------------------------------------------------

def _setup_cycle_files(tmp_path, monkeypatch, status="running"):
    session_file = tmp_path / "session.json"
    session_file.write_text(json.dumps({"status": status}))
    monkeypatch.setattr(core.qa_agent, "_SESSION_FILE", session_file)

    qa_state = tmp_path / "qa_state.json"
    monkeypatch.setattr(core.qa_agent, "_QA_STATE_FILE", qa_state)

    findings_file = tmp_path / "findings.json"
    monkeypatch.setattr(core.qa_agent, "_FINDINGS_FILE", findings_file)

    coverage_file = tmp_path / "coverage.json"
    monkeypatch.setattr(core.qa_agent, "_COVERAGE_FILE", coverage_file)

    return qa_state


@pytest.mark.asyncio
async def test_cycle_skips_when_session_not_running(tmp_path, monkeypatch):
    qa_state = _setup_cycle_files(tmp_path, monkeypatch, status="complete")
    daemon = QADaemon()
    await daemon._cycle()
    assert not qa_state.exists()


@pytest.mark.asyncio
async def test_cycle_skips_when_quick_log_is_empty(tmp_path, monkeypatch):
    qa_state = _setup_cycle_files(tmp_path, monkeypatch)

    test_log = QuickLog(path=tmp_path / "quick_log.json")
    monkeypatch.setattr(core.quick_log, "quick_log", test_log)

    daemon = QADaemon()
    await daemon._cycle()
    assert not qa_state.exists()


@pytest.mark.asyncio
async def test_cycle_skips_when_no_new_alerts(tmp_path, monkeypatch):
    """Cycle skips writing when deterministic + semantic both produce no alerts."""
    qa_state = _setup_cycle_files(tmp_path, monkeypatch)

    # Activity exists but no triggers in the summary
    mock_ql = MagicMock()
    mock_ql.summarize.return_value = "1 tool call: nmap"
    mock_ql.read_since.return_value = []
    monkeypatch.setattr(core.quick_log, "quick_log", mock_ql)

    daemon = QADaemon()
    monkeypatch.setattr(daemon, "_get_graph", lambda: None)
    await daemon._cycle()

    assert not qa_state.exists()


@pytest.mark.asyncio
async def test_cycle_writes_qa_state_with_deterministic_alert(tmp_path, monkeypatch):
    qa_state = _setup_cycle_files(tmp_path, monkeypatch)

    mock_ql = MagicMock()
    mock_ql.summarize.return_value = "Possible off-scope targets used: evil.com"
    mock_ql.read_since.return_value = []
    monkeypatch.setattr(core.quick_log, "quick_log", mock_ql)

    daemon = QADaemon()
    monkeypatch.setattr(daemon, "_get_graph", lambda: None)
    await daemon._cycle()

    assert qa_state.exists()
    data = json.loads(qa_state.read_text())
    codes = [a["code"] for a in data["alerts"]]
    assert "SCOPE_DRIFT" in codes
    assert "ts" in data
    assert "history" in data


@pytest.mark.asyncio
async def test_cycle_caps_alerts_at_four(tmp_path, monkeypatch):
    """Cycle keeps at most 4 alerts."""
    qa_state = _setup_cycle_files(tmp_path, monkeypatch)

    mock_ql = MagicMock()
    mock_ql.summarize.return_value = (
        "Possible off-scope targets used: evil.com\n"
        "Last tool call: 20 minutes ago\n"
        "Bulk-marking warning: 3 N/A cells lack tested_by\n"
        "5 tested/vulnerable cells have no tested_by tool\n"
        "WARNING: coverage stale (40 min), 5 pending"
    )
    mock_ql.read_since.return_value = []
    monkeypatch.setattr(core.quick_log, "quick_log", mock_ql)

    daemon = QADaemon()
    monkeypatch.setattr(daemon, "_get_graph", lambda: None)
    await daemon._cycle()

    data = json.loads(qa_state.read_text())
    assert len(data["alerts"]) <= 4


@pytest.mark.asyncio
async def test_cycle_captures_smith_actions_in_history(tmp_path, monkeypatch):
    qa_state = _setup_cycle_files(tmp_path, monkeypatch)
    # Seed previous history so prev_cycle_ts is set
    qa_state.write_text(json.dumps({
        "ts": "2025-12-31T00:00:00+00:00",
        "alerts": [],
        "history": [{"ts": "2025-12-31T00:00:00+00:00", "summary_sent": "prev",
                     "alerts": [], "smith_actions": [], "smith_reply": None}],
    }))

    new_action = {"type": "TOOL", "name": "nuclei", "ts": "2099-12-31T23:59:59+00:00"}
    mock_ql = MagicMock()
    mock_ql.summarize.return_value = "Possible off-scope targets used: evil.com"
    mock_ql.read_since.return_value = [new_action]
    monkeypatch.setattr(core.quick_log, "quick_log", mock_ql)

    daemon = QADaemon()
    monkeypatch.setattr(daemon, "_get_graph", lambda: None)
    await daemon._cycle()

    data = json.loads(qa_state.read_text())
    assert len(data["history"]) == 2
    smith_actions = data["history"][-1]["smith_actions"]
    assert any(a.get("name") == "nuclei" for a in smith_actions)


@pytest.mark.asyncio
async def test_cycle_caps_history_at_20(tmp_path, monkeypatch):
    qa_state = _setup_cycle_files(tmp_path, monkeypatch)
    existing_history = [
        {"ts": f"2026-01-{i:02d}T00:00:00+00:00", "summary_sent": "s",
         "alerts": [], "smith_actions": [], "smith_reply": None}
        for i in range(1, 21)
    ]
    qa_state.write_text(json.dumps({
        "ts": "2026-01-20T00:00:00+00:00",
        "alerts": [],
        "history": existing_history,
    }))

    mock_ql = MagicMock()
    mock_ql.summarize.return_value = "Possible off-scope targets used: evil.com"
    mock_ql.read_since.return_value = []
    monkeypatch.setattr(core.quick_log, "quick_log", mock_ql)

    daemon = QADaemon()
    monkeypatch.setattr(daemon, "_get_graph", lambda: None)
    await daemon._cycle()

    data = json.loads(qa_state.read_text())
    assert len(data["history"]) == 20


@pytest.mark.asyncio
async def test_cycle_handles_corrupt_qa_state_gracefully(tmp_path, monkeypatch):
    qa_state = _setup_cycle_files(tmp_path, monkeypatch)
    qa_state.write_text("not valid json {{{")

    mock_ql = MagicMock()
    mock_ql.summarize.return_value = "Possible off-scope targets used: evil.com"
    mock_ql.read_since.return_value = []
    monkeypatch.setattr(core.quick_log, "quick_log", mock_ql)

    daemon = QADaemon()
    monkeypatch.setattr(daemon, "_get_graph", lambda: None)
    await daemon._cycle()

    data = json.loads(qa_state.read_text())
    assert len(data["history"]) == 1


@pytest.mark.asyncio
async def test_cycle_invokes_semantic_review_for_high_findings(tmp_path, monkeypatch):
    qa_state = _setup_cycle_files(tmp_path, monkeypatch)

    findings_file = tmp_path / "findings.json"
    findings_file.write_text(json.dumps({
        "findings": [
            {"title": "SQLi", "severity": "critical",
             "description": "Classic injection", "evidence": "payload", "poc_files": ["poc.http"]},
        ]
    }))
    monkeypatch.setattr(core.qa_agent, "_FINDINGS_FILE", findings_file)

    mock_ql = MagicMock()
    mock_ql.summarize.return_value = "1 tool call: sqlmap"
    mock_ql.read_since.return_value = []
    monkeypatch.setattr(core.quick_log, "quick_log", mock_ql)

    semantic_alerts = [{"code": "FINDING_QUALITY", "urgency": "medium",
                        "blocking": False, "message": "Severity appears overclaimed"}]
    mock_graph = MagicMock()

    daemon = QADaemon()
    monkeypatch.setattr(daemon, "_get_graph", lambda: mock_graph)

    with patch("asyncio.to_thread", new=AsyncMock(return_value={"alerts": semantic_alerts})):
        await daemon._cycle()

    data = json.loads(qa_state.read_text())
    codes = [a["code"] for a in data["alerts"]]
    assert "FINDING_QUALITY" in codes


@pytest.mark.asyncio
async def test_cycle_skips_semantic_review_when_no_high_findings(tmp_path, monkeypatch):
    qa_state = _setup_cycle_files(tmp_path, monkeypatch)

    findings_file = tmp_path / "findings.json"
    findings_file.write_text(json.dumps({
        "findings": [
            {"title": "Minor info", "severity": "info", "description": "d"},
        ]
    }))
    monkeypatch.setattr(core.qa_agent, "_FINDINGS_FILE", findings_file)

    mock_ql = MagicMock()
    mock_ql.summarize.return_value = "Possible off-scope targets used: evil.com"
    mock_ql.read_since.return_value = []
    monkeypatch.setattr(core.quick_log, "quick_log", mock_ql)

    invoke_called = []
    mock_graph = MagicMock()
    mock_graph.invoke = lambda *a, **kw: invoke_called.append(True) or {"alerts": []}

    daemon = QADaemon()
    monkeypatch.setattr(daemon, "_get_graph", lambda: mock_graph)

    with patch("asyncio.to_thread", new=AsyncMock(side_effect=AssertionError("should not call"))):
        await daemon._cycle()

    assert not invoke_called


@pytest.mark.asyncio
async def test_cycle_handles_semantic_review_exception(tmp_path, monkeypatch):
    qa_state = _setup_cycle_files(tmp_path, monkeypatch)

    findings_file = tmp_path / "findings.json"
    findings_file.write_text(json.dumps({
        "findings": [
            {"title": "SQLi", "severity": "critical", "description": "d", "poc_files": ["poc.http"]},
        ]
    }))
    monkeypatch.setattr(core.qa_agent, "_FINDINGS_FILE", findings_file)

    mock_ql = MagicMock()
    mock_ql.summarize.return_value = "1 tool call: sqlmap"
    mock_ql.read_since.return_value = []
    monkeypatch.setattr(core.quick_log, "quick_log", mock_ql)

    mock_graph = MagicMock()
    daemon = QADaemon()
    monkeypatch.setattr(daemon, "_get_graph", lambda: mock_graph)

    # Semantic review raises an exception — cycle should not crash
    with patch("asyncio.to_thread", new=AsyncMock(side_effect=RuntimeError("LLM timeout"))):
        await daemon._cycle()  # should not raise


@pytest.mark.asyncio
async def test_cycle_skips_write_when_alerts_unchanged(tmp_path, monkeypatch):
    """When no new alerts are generated, qa_state is not rewritten."""
    qa_state = _setup_cycle_files(tmp_path, monkeypatch)

    # Pre-seed qa_state with an existing alert
    existing_alert = {"code": "SCOPE_DRIFT", "urgency": "high", "blocking": False,
                      "message": "Possible off-scope targets used: evil.com"}
    qa_state.write_text(json.dumps({
        "ts": "2026-01-01T00:00:00+00:00",
        "alerts": [existing_alert],
        "history": [],
    }))

    # Summary produces no deterministic alerts, no high/critical findings
    mock_ql = MagicMock()
    mock_ql.summarize.return_value = "1 tool call: nmap"
    mock_ql.read_since.return_value = []
    monkeypatch.setattr(core.quick_log, "quick_log", mock_ql)

    daemon = QADaemon()
    monkeypatch.setattr(daemon, "_get_graph", lambda: None)

    mtime_before = qa_state.stat().st_mtime
    await daemon._cycle()
    assert qa_state.stat().st_mtime == mtime_before


# ---------------------------------------------------------------------------
# _init_llm()
# ---------------------------------------------------------------------------

def test_init_llm_openai_provider():
    mock_cls = MagicMock(return_value=MagicMock())
    with patch.dict("sys.modules", {"langchain_openai": MagicMock(ChatOpenAI=mock_cls)}):
        result = _init_llm("openai:gpt-4o-mini")
    mock_cls.assert_called_once_with(model="gpt-4o-mini", max_tokens=512)


def test_init_llm_anthropic_provider():
    mock_cls = MagicMock(return_value=MagicMock())
    with patch.dict("sys.modules", {"langchain_anthropic": MagicMock(ChatAnthropic=mock_cls)}):
        result = _init_llm("anthropic:claude-haiku-4-5-20251001")
    mock_cls.assert_called_once_with(model="claude-haiku-4-5-20251001", max_tokens=512)


def test_init_llm_ollama_provider():
    mock_cls = MagicMock(return_value=MagicMock())
    with patch.dict("sys.modules", {"langchain_ollama": MagicMock(ChatOllama=mock_cls)}):
        result = _init_llm("ollama:qwen2.5:7b")
    mock_cls.assert_called_once_with(model="qwen2.5:7b", num_predict=512)


def test_init_llm_unknown_provider_raises():
    with pytest.raises(ValueError, match="Unknown QA_MODEL provider"):
        _init_llm("fakevendor:some-model")


def test_init_llm_no_colon_defaults_to_openai():
    mock_cls = MagicMock(return_value=MagicMock())
    with patch.dict("sys.modules", {"langchain_openai": MagicMock(ChatOpenAI=mock_cls)}):
        _init_llm("gpt-4o-mini")
    mock_cls.assert_called_once_with(model="gpt-4o-mini", max_tokens=512)


# ---------------------------------------------------------------------------
# _build_graph()
# ---------------------------------------------------------------------------

def test_build_graph_returns_none_when_langgraph_missing():
    with patch.dict("sys.modules", {"langgraph": None, "langgraph.graph": None,
                                     "langchain_core": None, "langchain_core.messages": None}):
        result = _build_graph()
    assert result is None


def test_build_graph_returns_none_when_llm_init_fails(monkeypatch):
    mock_state_graph = MagicMock()
    mock_graph_instance = MagicMock()
    mock_state_graph.return_value = mock_graph_instance

    fake_langgraph = MagicMock()
    fake_langgraph.graph.StateGraph = mock_state_graph
    fake_langgraph.graph.END = "END"

    fake_lc_core = MagicMock()

    with patch.dict("sys.modules", {
        "langgraph": fake_langgraph,
        "langgraph.graph": fake_langgraph.graph,
        "langchain_core": fake_lc_core,
        "langchain_core.messages": fake_lc_core.messages,
    }):
        monkeypatch.setenv("QA_MODEL", "openai:gpt-4o-mini")
        with patch("core.qa_agent._init_llm", side_effect=Exception("no key")):
            result = _build_graph()
    assert result is None


def test_build_graph_returns_compiled_graph(monkeypatch):
    mock_compiled = MagicMock()
    mock_sg_instance = MagicMock()
    mock_sg_instance.compile.return_value = mock_compiled
    mock_sg_cls = MagicMock(return_value=mock_sg_instance)

    fake_langgraph_graph = MagicMock()
    fake_langgraph_graph.StateGraph = mock_sg_cls
    fake_langgraph_graph.END = "END"

    fake_lc_core_messages = MagicMock()

    with patch.dict("sys.modules", {
        "langgraph": MagicMock(graph=fake_langgraph_graph),
        "langgraph.graph": fake_langgraph_graph,
        "langchain_core": MagicMock(messages=fake_lc_core_messages),
        "langchain_core.messages": fake_lc_core_messages,
    }):
        monkeypatch.setenv("QA_MODEL", "openai:gpt-4o-mini")
        mock_llm = MagicMock()
        with patch("core.qa_agent._init_llm", return_value=mock_llm):
            result = _build_graph()

    assert result is mock_compiled


# ---------------------------------------------------------------------------
# QADaemon._get_graph() — lazy-builds only once
# ---------------------------------------------------------------------------

def test_get_graph_builds_once(monkeypatch):
    build_calls = []

    def fake_build():
        build_calls.append(1)
        return MagicMock()

    daemon = QADaemon()
    with patch("core.qa_agent._build_graph", side_effect=fake_build):
        daemon._get_graph()
        daemon._get_graph()

    assert len(build_calls) == 1


# ---------------------------------------------------------------------------
# _build_graph() — node execution (invoke_llm + parse_response)
# ---------------------------------------------------------------------------

def test_build_graph_nodes_parse_valid_json(monkeypatch):
    """Exercises invoke_llm and parse_response nodes with a mocked LLM."""
    try:
        from langgraph.graph import StateGraph  # noqa: F401
    except ImportError:
        pytest.skip("langgraph not installed")

    monkeypatch.setenv("QA_MODEL", "openai:gpt-4o-mini")
    mock_llm = MagicMock()
    mock_response = MagicMock()
    mock_response.content = json.dumps({
        "alerts": [
            {"code": "FINDING_QUALITY", "urgency": "high",
             "blocking": False, "message": "severity overclaimed"}
        ]
    })
    mock_llm.invoke.return_value = mock_response

    with patch("core.qa_agent._init_llm", return_value=mock_llm):
        graph = _build_graph()

    assert graph is not None
    result = graph.invoke({"summary": "test findings", "raw_response": "", "alerts": []})
    assert len(result["alerts"]) == 1
    assert result["alerts"][0]["code"] == "FINDING_QUALITY"
    assert result["alerts"][0]["urgency"] == "high"


def test_build_graph_nodes_handle_invalid_json(monkeypatch):
    """parse_response should return empty alerts for non-JSON LLM output."""
    try:
        from langgraph.graph import StateGraph  # noqa: F401
    except ImportError:
        pytest.skip("langgraph not installed")

    monkeypatch.setenv("QA_MODEL", "openai:gpt-4o-mini")
    mock_llm = MagicMock()
    mock_response = MagicMock()
    mock_response.content = "not valid json at all"
    mock_llm.invoke.return_value = mock_response

    with patch("core.qa_agent._init_llm", return_value=mock_llm):
        graph = _build_graph()

    assert graph is not None
    result = graph.invoke({"summary": "test", "raw_response": "", "alerts": []})
    assert result["alerts"] == []


def test_build_graph_nodes_filter_alerts_without_message(monkeypatch):
    """parse_response drops alert dicts that have no 'message' field."""
    try:
        from langgraph.graph import StateGraph  # noqa: F401
    except ImportError:
        pytest.skip("langgraph not installed")

    monkeypatch.setenv("QA_MODEL", "openai:gpt-4o-mini")
    mock_llm = MagicMock()
    mock_response = MagicMock()
    mock_response.content = json.dumps({
        "alerts": [
            {"code": "FINDING_QUALITY", "urgency": "high"},  # no message → filtered
            {"code": "FINDING_QUALITY", "urgency": "medium", "message": "real alert"},
        ]
    })
    mock_llm.invoke.return_value = mock_response

    with patch("core.qa_agent._init_llm", return_value=mock_llm):
        graph = _build_graph()

    assert graph is not None
    result = graph.invoke({"summary": "test", "raw_response": "", "alerts": []})
    assert len(result["alerts"]) == 1
    assert result["alerts"][0]["message"] == "real alert"


def test_build_graph_nodes_handle_non_list_alerts(monkeypatch):
    """parse_response should produce empty alerts when JSON alerts field is not a list."""
    try:
        from langgraph.graph import StateGraph  # noqa: F401
    except ImportError:
        pytest.skip("langgraph not installed")

    monkeypatch.setenv("QA_MODEL", "openai:gpt-4o-mini")
    mock_llm = MagicMock()
    mock_response = MagicMock()
    mock_response.content = json.dumps({"alerts": "not-a-list"})
    mock_llm.invoke.return_value = mock_response

    with patch("core.qa_agent._init_llm", return_value=mock_llm):
        graph = _build_graph()

    assert graph is not None
    result = graph.invoke({"summary": "test", "raw_response": "", "alerts": []})
    assert result["alerts"] == []


# ---------------------------------------------------------------------------
# QADaemon.run() — loop and error swallowing
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_run_calls_cycle_and_swallows_exceptions(tmp_path, monkeypatch):
    """run() must not propagate _cycle() exceptions and must keep looping."""
    session_file = tmp_path / "session.json"
    session_file.write_text(json.dumps({"status": "running"}))
    monkeypatch.setattr(core.qa_agent, "_SESSION_FILE", session_file)

    call_count = 0

    async def fake_cycle():
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RuntimeError("boom")
        raise asyncio.CancelledError()

    daemon = QADaemon()
    monkeypatch.setattr(daemon, "_cycle", fake_cycle)

    with patch("asyncio.sleep", new=AsyncMock()):
        try:
            await daemon.run(interval_s=0)
        except asyncio.CancelledError:
            pass

    assert call_count == 2


# ── _check_injection_breadth ──────────────────────────────────────────────────

def _make_cell(ep_id, param, param_type, injection_type, status="pending"):
    return {
        "id": f"cell-{ep_id}-{param}-{injection_type}",
        "endpoint_id": ep_id,
        "param": param,
        "param_type": param_type,
        "injection_type": injection_type,
        "status": status,
    }


def test_injection_breadth_no_matrix():
    result = core.qa_agent._check_injection_breadth({"matrix": []})
    assert result is None


def test_injection_breadth_no_sqli_cells():
    """Params without sqli cells are ignored."""
    matrix = [_make_cell("ep1", "q", "query", "xss")]
    result = core.qa_agent._check_injection_breadth({"matrix": matrix})
    assert result is None


def test_injection_breadth_full_coverage():
    """Param has sqli + all four breadth types — no alert."""
    matrix = [
        _make_cell("ep1", "q", "query", "sqli"),
        _make_cell("ep1", "q", "query", "xss"),
        _make_cell("ep1", "q", "query", "ssti"),
        _make_cell("ep1", "q", "query", "ssrf"),
        _make_cell("ep1", "q", "query", "cmdi"),
    ]
    result = core.qa_agent._check_injection_breadth({"matrix": matrix})
    assert result is None


def test_injection_breadth_missing_types():
    """Param has sqli but is missing xss/ssti/ssrf/cmdi — alert fires."""
    matrix = [_make_cell("ep1", "username", "body_json", "sqli")]
    result = core.qa_agent._check_injection_breadth({"matrix": matrix})
    assert result is not None
    assert result["code"] == "INJECTION_BREADTH_GAP"
    assert result["urgency"] == "high"
    assert "username" in result["message"]
    assert "xss" in result["message"]


def test_injection_breadth_endpoint_param_skipped():
    """_endpoint params are never checked for breadth."""
    matrix = [
        {"id": "c1", "endpoint_id": "ep1", "param": "_endpoint",
         "param_type": "endpoint", "injection_type": "sqli", "status": "pending"},
    ]
    result = core.qa_agent._check_injection_breadth({"matrix": matrix})
    assert result is None


def test_injection_breadth_partial_missing():
    """Alert message lists which types are missing."""
    matrix = [
        _make_cell("ep1", "id", "query", "sqli"),
        _make_cell("ep1", "id", "query", "xss"),
        # missing ssti, ssrf, cmdi
    ]
    result = core.qa_agent._check_injection_breadth({"matrix": matrix})
    assert result is not None
    assert "ssti" in result["message"] or "ssrf" in result["message"]


# ---------------------------------------------------------------------------
# _check_endpoint_trigger_gaps
# ---------------------------------------------------------------------------

from core.qa_agent import _check_endpoint_trigger_gaps, _check_coverage_gap
from datetime import datetime, timezone, timedelta


def _gate(gid, required, status="pending", triggered_at=None, trigger="api endpoint"):
    return {
        "id": gid,
        "status": status,
        "required_skills": required,
        "triggered_at": triggered_at or datetime.now(timezone.utc).isoformat(),
        "trigger": trigger,
    }


def test_trigger_gaps_no_gates():
    assert _check_endpoint_trigger_gaps({}) == []


def test_trigger_gaps_satisfied_gate_skipped():
    sd = {"gates": [_gate("g1", ["api-security"], status="satisfied")], "skill_history": []}
    assert _check_endpoint_trigger_gaps(sd) == []


def test_trigger_gaps_all_skills_satisfied():
    sd = {
        "gates": [_gate("g1", ["api-security"])],
        "skill_history": [{"skill": "api-security"}],
    }
    assert _check_endpoint_trigger_gaps(sd) == []


def test_trigger_gaps_missing_skill_fires_alert():
    sd = {
        "gates": [_gate("g1", ["api-security"])],
        "skill_history": [],
    }
    alerts = _check_endpoint_trigger_gaps(sd)
    assert len(alerts) == 1
    assert alerts[0]["code"] == "ENDPOINT_TRIGGER_GAP"
    assert "/api-security" in alerts[0]["message"]


def test_trigger_gaps_elapsed_over_15_is_high():
    old_time = (datetime.now(timezone.utc) - timedelta(minutes=20)).isoformat()
    sd = {
        "gates": [_gate("g1", ["credential-audit"], triggered_at=old_time)],
        "skill_history": [],
    }
    alerts = _check_endpoint_trigger_gaps(sd)
    assert alerts[0]["urgency"] == "high"


def test_trigger_gaps_elapsed_under_15_is_medium():
    recent = datetime.now(timezone.utc).isoformat()
    sd = {
        "gates": [_gate("g1", ["credential-audit"], triggered_at=recent)],
        "skill_history": [],
    }
    alerts = _check_endpoint_trigger_gaps(sd)
    assert alerts[0]["urgency"] == "medium"


def test_trigger_gaps_bad_timestamp_defaults_to_zero():
    sd = {
        "gates": [{"id": "g1", "status": "pending", "required_skills": ["web-exploit"],
                   "triggered_at": "not-a-date", "trigger": "upload"}],
        "skill_history": [],
    }
    alerts = _check_endpoint_trigger_gaps(sd)
    assert len(alerts) == 1
    assert alerts[0]["urgency"] == "medium"  # elapsed=0 < 15


# ---------------------------------------------------------------------------
# _check_coverage_gap
# ---------------------------------------------------------------------------

def test_coverage_gap_no_endpoints():
    assert _check_coverage_gap({"endpoints": []}, {}) == []


def test_coverage_gap_unclassified_endpoint_ignored():
    cov = {"endpoints": [{"path": "/static/image.png"}]}
    assert _check_coverage_gap(cov, {}) == []


def test_coverage_gap_skill_already_run():
    cov = {"endpoints": [{"path": "/graphql"}]}
    sd = {"skill_history": [{"skill": "api-security"}]}
    assert _check_coverage_gap(cov, sd) == []


def test_coverage_gap_skill_missing_fires_alert():
    cov = {"endpoints": [{"path": "/graphql"}]}
    sd = {"skill_history": []}
    alerts = _check_coverage_gap(cov, sd)
    assert len(alerts) == 1
    assert alerts[0]["code"] == "COVERAGE_GAP"
    assert "api-security" in alerts[0]["message"]


def test_coverage_gap_multiple_same_type_grouped():
    cov = {"endpoints": [{"path": "/graphql"}, {"path": "/graph/query"}]}
    sd = {"skill_history": []}
    alerts = _check_coverage_gap(cov, sd)
    # Both are graphql type — grouped into one alert
    assert len(alerts) == 1
    assert "2 graphql" in alerts[0]["message"]


def test_coverage_gap_financial_endpoint_flags_business_logic():
    cov = {"endpoints": [{"path": "/api/payment"}]}
    sd = {"skill_history": []}
    alerts = _check_coverage_gap(cov, sd)
    assert any("business-logic" in a["message"] for a in alerts)
