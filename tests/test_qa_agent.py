"""
Tests for core.qa_agent — deterministic checks and QADaemon cycle logic.

All check functions operate on structured data (quick_log entries, JSON dicts).
No regex parsing of summary text.
"""
import asyncio
import json
import pytest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import core.qa_agent
import core.quick_log
from core.qa_agent import (
    _session_is_running, _read_qa_state,
    _sanitize_history, QADaemon,
    _deterministic_qa_checks, _load_json,
    _deduplicate, _merge_alerts,
    _check_tool_inactivity, _check_bulk_marking,
    _check_coverage_integrity, _check_no_spider_after_httpx,
    _check_missing_skill,
    _check_suspicious_speed, _check_na_abuse, _check_depth_after_finding,
    _check_whitebox_passes, _check_premature_complete, _check_stuck_on_target,
    _check_chain_correlation,
    _maybe_inject_web_exploit_directive, _maybe_inject_param_fuzz_directive,
    _maybe_inject_business_logic_directive, _check_core_skill_chain,
    _hir, _check_auth_failure, _check_budget_limit, _check_zero_endpoints,
    _check_target_unreachable, _check_exploit_escalation, _check_repeated_tool_failure,
    _ts_age_secs, _check_unregistered_findings,
)
from core.quick_log import QuickLog


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts(offset_min: int = 0) -> str:
    """ISO timestamp offset_min minutes in the past."""
    return (datetime.now(timezone.utc) - timedelta(minutes=offset_min)).isoformat()


def _tool_entry(name: str = "nmap", target: str = "https://example.com", offset_min: int = 1) -> dict:
    return {"type": "TOOL", "name": name, "target": target, "ts": _ts(offset_min)}


def _spider_entry(endpoints_found: int = 10, offset_min: int = 1) -> dict:
    return {"type": "SPIDER", "endpoints_found": endpoints_found, "ts": _ts(offset_min)}


def _coverage_entry(pending: int = 0, na_untooled: int = 0, untooled: int = 0,
                    offset_min: int = 1) -> dict:
    return {
        "type": "COVERAGE", "pending": pending, "tested": 5,
        "na_untooled": na_untooled, "untooled": untooled,
        "ts": _ts(offset_min),
    }


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
    assert _load_json(tmp_path / "nonexistent.json") == {}


def test_load_json_returns_parsed_dict(tmp_path):
    f = tmp_path / "data.json"
    f.write_text(json.dumps({"key": "value", "num": 42}))
    assert _load_json(f) == {"key": "value", "num": 42}


def test_load_json_returns_empty_on_corrupt_json(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text("not valid json {{{")
    assert _load_json(f) == {}


# ---------------------------------------------------------------------------
# _check_tool_inactivity
# ---------------------------------------------------------------------------

def test_tool_inactivity_no_tools():
    assert _check_tool_inactivity([]) is None


def test_tool_inactivity_below_threshold():
    entries = [_tool_entry(offset_min=5)]
    assert _check_tool_inactivity(entries) is None


def test_tool_inactivity_under_15_min_no_alert():
    # Changed threshold: only fires at >15 min (not medium at 10-15)
    entries = [_tool_entry(offset_min=12)]
    assert _check_tool_inactivity(entries) is None


def test_tool_inactivity_high_over_15(tmp_path, monkeypatch):
    import core.steering as st_mod
    import core.qa_agent as qa_mod
    steering_file = tmp_path / "steering_queue.json"
    # Patch both the steering module path and the qa_agent local copy so
    # _has_pending_directives() reads the temp file (no stale real-file state).
    monkeypatch.setattr(st_mod, "_STEERING_FILE", steering_file)
    # Also patch qa_agent's local copy so _has_pending_directives() reads temp file.
    monkeypatch.setattr(qa_mod, "_STEERING_FILE", steering_file)
    entries = [_tool_entry(offset_min=20)]
    alert = _check_tool_inactivity(entries)
    assert alert is not None
    assert alert["urgency"] == "high"
    q = st_mod.SteeringQueue()
    assert any(d["code"] == "RESUME_REQUIRED" for d in q._load())


def test_tool_inactivity_counts_spider_entries():
    entries = [_spider_entry(offset_min=5)]
    assert _check_tool_inactivity(entries) is None


# ---------------------------------------------------------------------------
# _check_chain_correlation
# ---------------------------------------------------------------------------

def _hc_finding(title, target="https://t"):
    return {"title": title, "severity": "high", "target": target}


def test_chain_correlation_needs_two_same_target_findings():
    # Single finding → no nudge.
    assert _check_chain_correlation({"findings": [_hc_finding("a")]}) is None
    # Two findings on different targets → no shared-target chain candidate.
    data = {"findings": [_hc_finding("a", "https://x"), _hc_finding("b", "https://y")]}
    assert _check_chain_correlation(data) is None


def test_chain_correlation_skips_when_chain_exists():
    data = {
        "findings": [_hc_finding("a"), _hc_finding("b")],
        "chains": [{"name": "already"}],
    }
    assert _check_chain_correlation(data) is None


def test_chain_correlation_fires_and_injects_directive(tmp_path, monkeypatch):
    import core.steering as st_mod
    import core.qa_agent as qa_mod
    steering_file = tmp_path / "steering_queue.json"
    monkeypatch.setattr(st_mod, "_STEERING_FILE", steering_file)
    monkeypatch.setattr(qa_mod, "_STEERING_FILE", steering_file)

    data = {"findings": [_hc_finding("Open redirect"), _hc_finding("OAuth code theft")]}
    alert = _check_chain_correlation(data)
    assert alert is not None
    assert alert["code"] == "CHAIN_CORRELATION"
    assert alert["blocking"] is False
    q = st_mod.SteeringQueue()
    assert any(d["trigger"] == "CHAIN_CORRELATION" for d in q._load())


def test_chain_correlation_ignores_false_positives():
    data = {"findings": [
        _hc_finding("a"),
        {**_hc_finding("b"), "status": "false_positive"},
    ]}
    assert _check_chain_correlation(data) is None


# ---------------------------------------------------------------------------
# _check_bulk_marking
# ---------------------------------------------------------------------------

def test_bulk_marking_no_coverage_entries():
    assert _check_bulk_marking([]) is None


def test_bulk_marking_below_threshold():
    entries = [_coverage_entry(na_untooled=5)]
    assert _check_bulk_marking(entries) is None


def test_bulk_marking_fires():
    entries = [_coverage_entry(na_untooled=15)]
    alert = _check_bulk_marking(entries)
    assert alert is not None
    assert alert["code"] == "BULK_MARKING"
    assert alert["blocking"] is True
    assert "15" in alert["message"]


# ---------------------------------------------------------------------------
# _check_coverage_integrity
# ---------------------------------------------------------------------------

def test_coverage_integrity_no_entries():
    assert _check_coverage_integrity([]) is None


def test_coverage_integrity_zero_untooled():
    entries = [_coverage_entry(untooled=0)]
    assert _check_coverage_integrity(entries) is None


def test_coverage_integrity_fires():
    entries = [_coverage_entry(untooled=5)]
    alert = _check_coverage_integrity(entries)
    assert alert is not None
    assert alert["code"] == "COVERAGE_INTEGRITY"
    assert alert["blocking"] is True
    assert "5" in alert["message"]


# ---------------------------------------------------------------------------
# _check_unregistered_findings — discovery-before-testing gap
# ---------------------------------------------------------------------------

def test_unregistered_findings_none_when_all_registered():
    cov = {"endpoints": [{"path": "/login", "_normalized": "/login"}]}
    fnd = {"findings": [{"target": "http://t/login", "status": "confirmed"}]}
    assert _check_unregistered_findings(fnd, cov) is None


def test_unregistered_findings_none_when_matrix_empty():
    # zero registered endpoints is a different signal (handled by _check_zero_endpoints)
    fnd = {"findings": [{"target": "http://t/anything"}]}
    assert _check_unregistered_findings(fnd, {"endpoints": []}) is None


def test_unregistered_findings_advisory_not_blocking():
    """The gap-guard now nudges but does NOT block completion or steer the model.
    The blocking + STOP-opening-new-ground steering suppressed creative
    exploitation (see the coverage-grind regression analysis)."""
    cov = {"endpoints": [{"path": "/login", "_normalized": "/login"}]}
    fnd = {"findings": [{"target": "http://t/transfer"}]}
    alert = _check_unregistered_findings(fnd, cov)
    assert alert is not None
    assert alert["code"] == "DISCOVERY_GAP"
    assert alert["blocking"] is False
    assert alert["urgency"] == "low"
    assert "/transfer" in alert["message"]


def test_unregistered_findings_no_steer_directive(monkeypatch):
    """Even with many unregistered findings, no steering directive is emitted —
    the model should keep exploiting freely, not be told to STOP opening new ground."""
    import core.steering as steering
    calls = []
    monkeypatch.setattr(steering.steering_queue, "add_directive",
                        lambda **kw: calls.append(kw))
    cov = {"endpoints": [{"path": "/login", "_normalized": "/login"}]}
    fnd = {"findings": [{"target": f"http://t/u{i}"} for i in range(5)]}
    alert = _check_unregistered_findings(fnd, cov)
    assert alert["code"] == "DISCOVERY_GAP"
    assert calls == []  # no steering directive emitted


# ---------------------------------------------------------------------------
# _check_no_spider_after_httpx
# ---------------------------------------------------------------------------

def test_no_spider_no_httpx():
    entries = [_tool_entry("nmap")]
    assert _check_no_spider_after_httpx(entries) is None


def test_no_spider_httpx_with_spider():
    entries = [_tool_entry("httpx"), _spider_entry()]
    assert _check_no_spider_after_httpx(entries) is None


def test_no_spider_fires_after_httpx():
    entries = [_tool_entry("httpx"), _tool_entry("nuclei")]
    alert = _check_no_spider_after_httpx(entries)
    assert alert is not None
    assert alert["code"] == "NO_SPIDER"
    assert alert["urgency"] == "medium"


# ---------------------------------------------------------------------------
# _check_missing_skill (was _check_coverage_gap)
# ---------------------------------------------------------------------------

def test_missing_skill_no_endpoints():
    assert _check_missing_skill({"endpoints": []}, {}) == []


def test_missing_skill_unclassified_endpoint_ignored():
    cov = {"endpoints": [{"path": "/static/image.png"}]}
    assert _check_missing_skill(cov, {}) == []


def test_missing_skill_skill_already_run():
    cov = {"endpoints": [{"path": "/graphql"}]}
    sd  = {"skill_history": [{"skill": "api-security"}]}
    assert _check_missing_skill(cov, sd) == []


def test_missing_skill_fires_alert():
    cov = {"endpoints": [{"path": "/graphql"}]}
    alerts = _check_missing_skill(cov, {"skill_history": []})
    assert len(alerts) == 1
    assert alerts[0]["code"] == "MISSING_SKILL"
    assert "api-security" in alerts[0]["message"]


def test_missing_skill_multiple_same_type_grouped():
    cov = {"endpoints": [{"path": "/graphql"}, {"path": "/graph/query"}]}
    alerts = _check_missing_skill(cov, {"skill_history": []})
    assert len(alerts) == 1
    assert "2 graphql" in alerts[0]["message"]


def test_missing_skill_financial_flags_business_logic():
    cov = {"endpoints": [{"path": "/api/payment"}]}
    alerts = _check_missing_skill(cov, {"skill_history": []})
    assert any("business-logic" in a["message"] for a in alerts)


def test_missing_skill_import_error_returns_empty(monkeypatch):
    import sys
    import types
    original = sys.modules.get("core.coverage")
    broken = types.ModuleType("core.coverage")
    sys.modules["core.coverage"] = broken
    try:
        from core.qa_agent import _check_missing_skill
        assert _check_missing_skill({"endpoints": [{"path": "/graphql"}]}, {}) == []
    finally:
        if original is not None:
            sys.modules["core.coverage"] = original
        else:
            sys.modules.pop("core.coverage", None)


# ---------------------------------------------------------------------------
# _deterministic_qa_checks — signature and integration
# ---------------------------------------------------------------------------

def test_deterministic_no_alerts_on_clean_state(tmp_path, monkeypatch):
    import core.steering as st_mod
    monkeypatch.setattr(st_mod, "_STEERING_FILE", tmp_path / "steering_queue.json")
    entries = [_tool_entry(offset_min=2)]
    alerts = _deterministic_qa_checks(entries, {}, {}, {"target": "https://example.com"})
    assert alerts == []


def test_deterministic_bulk_marking_detected(tmp_path, monkeypatch):
    import core.steering as st_mod
    monkeypatch.setattr(st_mod, "_STEERING_FILE", tmp_path / "steering_queue.json")
    entries = [_coverage_entry(na_untooled=15)]
    alerts = _deterministic_qa_checks(entries, {}, {}, {})
    assert any(a["code"] == "BULK_MARKING" for a in alerts)


def test_deterministic_multiple_alerts_fire(tmp_path, monkeypatch):
    import core.steering as st_mod
    monkeypatch.setattr(st_mod, "_STEERING_FILE", tmp_path / "steering_queue.json")
    entries = [
        _tool_entry("nmap", "https://example.com", offset_min=20),  # inactivity
        _coverage_entry(na_untooled=15),                             # bulk marking
    ]
    alerts = _deterministic_qa_checks(entries, {}, {}, {"target": "https://example.com"})
    codes = {a["code"] for a in alerts}
    assert "BULK_MARKING" in codes


# ---------------------------------------------------------------------------
# _deduplicate()
# ---------------------------------------------------------------------------

def test_deduplicate_empty_lists():
    assert _deduplicate([], []) == []


def test_deduplicate_no_previous_keeps_all():
    new_alerts = [
        {"code": "TOOL_INACTIVITY", "urgency": "high", "message": "stalled"},
        {"code": "BULK_MARKING",    "urgency": "high", "message": "bulk"},
    ]
    assert len(_deduplicate(new_alerts, [])) == 2


def test_deduplicate_drops_same_code_and_message():
    alert = {"code": "BULK_MARKING", "urgency": "high", "message": "bulk detected"}
    assert _deduplicate([alert], [alert]) == []


def test_deduplicate_keeps_same_code_different_message():
    prev = {"code": "TOOL_INACTIVITY", "urgency": "high", "message": "idle 15min"}
    new  = {"code": "TOOL_INACTIVITY", "urgency": "high", "message": "idle 25min"}
    result = _deduplicate([new], [prev])
    assert len(result) == 1
    assert result[0]["message"] == "idle 25min"


def test_deduplicate_keeps_different_codes():
    prev = {"code": "BULK_MARKING",   "urgency": "high", "message": "bulk"}
    new  = {"code": "TOOL_INACTIVITY","urgency": "high", "message": "idle"}
    result = _deduplicate([new], [prev])
    assert len(result) == 1
    assert result[0]["code"] == "TOOL_INACTIVITY"


def test_deduplicate_same_message_deduped_regardless_of_urgency():
    prev = {"code": "TOOL_INACTIVITY", "urgency": "low",  "message": "idle 15min"}
    new  = {"code": "TOOL_INACTIVITY", "urgency": "high", "message": "idle 15min"}
    assert _deduplicate([new], [prev]) == []


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
    assert _read_qa_state()["alerts"] == []


def test_read_qa_state_returns_empty_on_corrupt_json(tmp_path, monkeypatch):
    qa_state = tmp_path / "qa_state.json"
    qa_state.write_text("not valid json {{{")
    monkeypatch.setattr(core.qa_agent, "_QA_STATE_FILE", qa_state)
    assert _read_qa_state() == {}


# ---------------------------------------------------------------------------
# _sanitize_history()
# ---------------------------------------------------------------------------

def test_sanitize_history_filters_non_dicts():
    raw = [{"ts": "2026-01-01T00:00:00+00:00", "alerts": [], "smith_actions": []},
           "not-a-dict", 42]
    assert len(_sanitize_history(raw)) == 1


def test_sanitize_history_caps_field_length():
    long_ts = "X" * 100
    alerts = [{"urgency": "high", "message": "a"}] * 20
    smith  = [{"type": "TOOL"}] * 100
    raw = [{"ts": long_ts, "alerts": alerts, "smith_actions": smith}]
    result = _sanitize_history(raw)
    assert len(result[0]["ts"]) <= 50
    assert len(result[0]["alerts"]) <= 10
    assert len(result[0]["smith_actions"]) <= 50


def test_sanitize_history_keeps_valid_alert_dicts():
    raw = [{"ts": "t", "alerts": [{"urgency": "high"}, "not-dict"], "smith_actions": []}]
    assert _sanitize_history(raw)[0]["alerts"] == [{"urgency": "high"}]


def test_sanitize_history_empty_list():
    assert _sanitize_history([]) == []


def test_sanitize_history_smith_reply_preserved():
    raw = [{"ts": "t", "alerts": [], "smith_actions": [], "smith_reply": "Acknowledged."}]
    assert _sanitize_history(raw)[0]["smith_reply"] == "Acknowledged."


def test_sanitize_history_smith_reply_none_when_absent():
    raw = [{"ts": "t", "alerts": [], "smith_actions": []}]
    assert _sanitize_history(raw)[0]["smith_reply"] is None


def test_sanitize_history_truncates_long_smith_reply():
    raw = [{"ts": "t", "alerts": [], "smith_actions": [], "smith_reply": "A" * 3000}]
    assert len(_sanitize_history(raw)[0]["smith_reply"]) <= 2000


def test_sanitize_history_no_summary_sent_in_output():
    raw = [{"ts": "t", "summary_sent": "old prompt", "alerts": [], "smith_actions": []}]
    result = _sanitize_history(raw)
    assert "summary_sent" not in result[0]


# ---------------------------------------------------------------------------
# QADaemon._cycle() — guards and state
# ---------------------------------------------------------------------------

def _setup_cycle_files(tmp_path, monkeypatch, status="running", session_extra=None):
    session_data = {"status": status}
    if session_extra:
        session_data.update(session_extra)
    session_file = tmp_path / "session.json"
    session_file.write_text(json.dumps(session_data))
    monkeypatch.setattr(core.qa_agent, "_SESSION_FILE", session_file)

    qa_state = tmp_path / "qa_state.json"
    monkeypatch.setattr(core.qa_agent, "_QA_STATE_FILE", qa_state)

    findings_file = tmp_path / "findings.json"
    monkeypatch.setattr(core.qa_agent, "_FINDINGS_FILE", findings_file)

    coverage_file = tmp_path / "coverage.json"
    monkeypatch.setattr(core.qa_agent, "_COVERAGE_FILE", coverage_file)

    return qa_state


def _mock_ql(entries=None, since=None):
    m = MagicMock()
    m.read_all.return_value = entries or []
    m.read_since.return_value = since or []
    return m


@pytest.mark.asyncio
async def test_cycle_skips_when_session_not_running(tmp_path, monkeypatch):
    qa_state = _setup_cycle_files(tmp_path, monkeypatch, status="complete")
    daemon = QADaemon()
    await daemon._cycle()
    assert not qa_state.exists()


@pytest.mark.asyncio
async def test_cycle_skips_when_quick_log_is_empty(tmp_path, monkeypatch):
    qa_state = _setup_cycle_files(tmp_path, monkeypatch)
    monkeypatch.setattr(core.quick_log, "quick_log", QuickLog(path=tmp_path / "ql.json"))
    daemon = QADaemon()
    await daemon._cycle()
    assert not qa_state.exists()


@pytest.mark.asyncio
async def test_cycle_skips_when_no_new_alerts(tmp_path, monkeypatch):
    qa_state = _setup_cycle_files(tmp_path, monkeypatch)
    monkeypatch.setattr(core.quick_log, "quick_log",
                        _mock_ql(entries=[_tool_entry(offset_min=2)]))
    daemon = QADaemon()
    await daemon._cycle()
    assert not qa_state.exists()


@pytest.mark.asyncio
async def test_cycle_writes_qa_state_with_deterministic_alert(tmp_path, monkeypatch):
    import core.steering as st_mod
    monkeypatch.setattr(st_mod, "_STEERING_FILE", tmp_path / "steering_queue.json")
    qa_state = _setup_cycle_files(tmp_path, monkeypatch)
    # BULK_MARKING fires when na_untooled > 10
    monkeypatch.setattr(core.quick_log, "quick_log",
                        _mock_ql(entries=[_coverage_entry(na_untooled=15)]))
    daemon = QADaemon()
    await daemon._cycle()
    assert qa_state.exists()
    data = json.loads(qa_state.read_text())
    assert any(a["code"] == "BULK_MARKING" for a in data["alerts"])
    assert "ts" in data
    assert "history" in data


@pytest.mark.asyncio
async def test_cycle_caps_alerts_at_four(tmp_path, monkeypatch):
    import core.steering as st_mod
    monkeypatch.setattr(st_mod, "_STEERING_FILE", tmp_path / "steering_queue.json")
    qa_state = _setup_cycle_files(tmp_path, monkeypatch)
    monkeypatch.setattr(core.quick_log, "quick_log",
                        _mock_ql(entries=[_coverage_entry(na_untooled=15)]))

    six_alerts = [
        {"code": f"ALERT{i}", "urgency": "high", "blocking": False, "message": f"msg{i}"}
        for i in range(6)
    ]
    with patch("core.qa_agent._deterministic_qa_checks", return_value=six_alerts):
        daemon = QADaemon()
        await daemon._cycle()

    data = json.loads(qa_state.read_text())
    assert len(data["alerts"]) <= 4


@pytest.mark.asyncio
async def test_cycle_captures_smith_actions_in_history(tmp_path, monkeypatch):
    import core.steering as st_mod
    monkeypatch.setattr(st_mod, "_STEERING_FILE", tmp_path / "steering_queue.json")
    qa_state = _setup_cycle_files(tmp_path, monkeypatch)
    qa_state.write_text(json.dumps({
        "ts": "2025-12-31T00:00:00+00:00",
        "alerts": [],
        "history": [{"ts": "2025-12-31T00:00:00+00:00",
                     "alerts": [], "smith_actions": [], "smith_reply": None}],
    }))
    new_action = {"type": "TOOL", "name": "nuclei", "ts": "2099-12-31T23:59:59+00:00"}
    monkeypatch.setattr(core.quick_log, "quick_log",
                        _mock_ql(entries=[_coverage_entry(na_untooled=15)], since=[new_action]))
    daemon = QADaemon()
    await daemon._cycle()
    data = json.loads(qa_state.read_text())
    assert len(data["history"]) == 2
    assert any(a.get("name") == "nuclei" for a in data["history"][-1]["smith_actions"])


@pytest.mark.asyncio
async def test_cycle_caps_history_at_20(tmp_path, monkeypatch):
    import core.steering as st_mod
    monkeypatch.setattr(st_mod, "_STEERING_FILE", tmp_path / "steering_queue.json")
    qa_state = _setup_cycle_files(tmp_path, monkeypatch)
    existing_history = [
        {"ts": f"2026-01-{i:02d}T00:00:00+00:00",
         "alerts": [], "smith_actions": [], "smith_reply": None}
        for i in range(1, 21)
    ]
    qa_state.write_text(json.dumps({
        "ts": "2026-01-20T00:00:00+00:00",
        "alerts": [],
        "history": existing_history,
    }))
    monkeypatch.setattr(core.quick_log, "quick_log",
                        _mock_ql(entries=[_coverage_entry(na_untooled=15)]))
    daemon = QADaemon()
    await daemon._cycle()
    data = json.loads(qa_state.read_text())
    assert len(data["history"]) == 20


@pytest.mark.asyncio
async def test_cycle_handles_corrupt_qa_state_gracefully(tmp_path, monkeypatch):
    import core.steering as st_mod
    monkeypatch.setattr(st_mod, "_STEERING_FILE", tmp_path / "steering_queue.json")
    qa_state = _setup_cycle_files(tmp_path, monkeypatch)
    qa_state.write_text("not valid json {{{")
    monkeypatch.setattr(core.quick_log, "quick_log",
                        _mock_ql(entries=[_coverage_entry(na_untooled=15)]))
    daemon = QADaemon()
    await daemon._cycle()
    data = json.loads(qa_state.read_text())
    assert len(data["history"]) == 1


@pytest.mark.asyncio
async def test_cycle_skips_write_when_alerts_unchanged(tmp_path, monkeypatch):
    qa_state = _setup_cycle_files(tmp_path, monkeypatch)
    existing_alert = {"code": "BULK_MARKING", "urgency": "high", "blocking": True,
                      "message": "Bulk-marking detected: 15 N/A cells have no tested_by tool — run actual tools before marking N/A"}
    qa_state.write_text(json.dumps({
        "ts": "2026-01-01T00:00:00+00:00",
        "alerts": [existing_alert],
        "history": [],
    }))
    monkeypatch.setattr(core.quick_log, "quick_log",
                        _mock_ql(entries=[_tool_entry(offset_min=2)]))
    daemon = QADaemon()
    mtime_before = qa_state.stat().st_mtime
    await daemon._cycle()
    assert qa_state.stat().st_mtime == mtime_before


@pytest.mark.asyncio
async def test_cycle_history_has_no_summary_sent(tmp_path, monkeypatch):
    import core.steering as st_mod
    monkeypatch.setattr(st_mod, "_STEERING_FILE", tmp_path / "steering_queue.json")
    qa_state = _setup_cycle_files(tmp_path, monkeypatch)
    monkeypatch.setattr(core.quick_log, "quick_log",
                        _mock_ql(entries=[_coverage_entry(na_untooled=15)]))
    daemon = QADaemon()
    await daemon._cycle()
    data = json.loads(qa_state.read_text())
    for entry in data["history"]:
        assert "summary_sent" not in entry


# ---------------------------------------------------------------------------
# _merge_alerts()
# ---------------------------------------------------------------------------

def test_merge_alerts_changed_alerts_first():
    new_alert  = {"code": "BULK_MARKING",  "urgency": "high", "message": "new"}
    persistent = {"code": "TOOL_INACTIVITY","urgency": "high", "message": "idle"}
    result = _merge_alerts([new_alert], [new_alert, persistent], cap=4)
    assert result[0]["code"] == "BULK_MARKING"


def test_merge_alerts_preserves_persistent_when_new_fires():
    persistent1 = {"code": "TOOL_INACTIVITY",   "urgency": "high",   "message": "idle"}
    persistent2 = {"code": "COVERAGE_INTEGRITY", "urgency": "high",   "message": "untooled"}
    new_alert   = {"code": "BULK_MARKING",       "urgency": "high",   "message": "new bulk"}
    result = _merge_alerts([new_alert], [new_alert, persistent1, persistent2], cap=4)
    codes = {a["code"] for a in result}
    assert codes == {"BULK_MARKING", "TOOL_INACTIVITY", "COVERAGE_INTEGRITY"}


def test_merge_alerts_respects_cap():
    alerts = [{"code": f"A{i}", "urgency": "low", "message": f"m{i}"} for i in range(6)]
    assert len(_merge_alerts(alerts, alerts, cap=4)) == 4


def test_merge_alerts_no_duplicate_codes():
    a = {"code": "BULK_MARKING", "urgency": "high", "message": "same"}
    assert len(_merge_alerts([a], [a], cap=4)) == 1


def test_merge_alerts_empty_inputs():
    assert _merge_alerts([], []) == []


# ---------------------------------------------------------------------------
# QADaemon.run() — loop and error swallowing
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_run_calls_cycle_and_swallows_exceptions(tmp_path, monkeypatch):
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


# ===========================================================================
# NEW TESTS — additional coverage for previously uncovered functions
# ===========================================================================

# ---------------------------------------------------------------------------
# Helper entry builders
# ---------------------------------------------------------------------------

def _http_entry(offset_min=1, status_code=200, target="https://example.com", error=False):
    e = {
        "type": "TOOL", "name": "http_request", "target": target,
        "ts": _ts(offset_min), "status_code": status_code,
    }
    if error:
        e["error"] = True
    return e


def _finding_entry(severity="high", target="https://example.com", offset_min=25):
    return {
        "severity": severity, "target": target, "ts": _ts(offset_min),
        "title": f"Test {severity} finding", "id": "f-1",
    }


def _skill_history_entry(skill: str, offset_min: int = 25) -> dict:
    return {"skill": skill, "ts": _ts(offset_min), "reason": "test"}


def _error_tool_entry(name="nmap", target="https://example.com", offset_min=1):
    return {"type": "TOOL", "name": name, "target": target, "ts": _ts(offset_min), "error": True}


# ---------------------------------------------------------------------------
# _ts_age_secs
# ---------------------------------------------------------------------------

def test_ts_age_secs_valid_ts():
    now = datetime.now(timezone.utc)
    ts = (now - timedelta(seconds=120)).isoformat()
    age = _ts_age_secs(ts, now)
    assert 115 < age < 125


def test_ts_age_secs_empty_string():
    now = datetime.now(timezone.utc)
    assert _ts_age_secs("", now) == 0.0


def test_ts_age_secs_invalid_string():
    now = datetime.now(timezone.utc)
    assert _ts_age_secs("not-a-timestamp", now) == 0.0


# ---------------------------------------------------------------------------
# _check_suspicious_speed
# ---------------------------------------------------------------------------

def test_suspicious_speed_fewer_than_2_coverage_entries():
    entries = [_coverage_entry(offset_min=1)]
    assert _check_suspicious_speed(entries) is None


def test_suspicious_speed_low_cells_closed():
    entries = [
        {**_coverage_entry(offset_min=5), "cells_closed": 5},
        {**_coverage_entry(offset_min=1), "cells_closed": 5},
    ]
    assert _check_suspicious_speed(entries) is None


def test_suspicious_speed_fires_when_too_many_cells_closed(tmp_path, monkeypatch):
    import core.steering as st_mod
    import core.qa_agent as qa_mod
    steering_file = tmp_path / "steering_queue.json"
    monkeypatch.setattr(st_mod, "_STEERING_FILE", steering_file)
    monkeypatch.setattr(qa_mod, "_STEERING_FILE", steering_file)

    entries = [
        {**_coverage_entry(offset_min=5), "cells_closed": 15},
        {**_coverage_entry(offset_min=1), "cells_closed": 10},
    ]
    alert = _check_suspicious_speed(entries)
    assert alert is not None
    assert alert["code"] == "SUSPICIOUS_SPEED"
    assert alert["urgency"] == "high"
    assert "25" in alert["message"]


def test_suspicious_speed_directive_injected(tmp_path, monkeypatch):
    import core.steering as st_mod
    import core.qa_agent as qa_mod
    steering_file = tmp_path / "steering_queue.json"
    monkeypatch.setattr(st_mod, "_STEERING_FILE", steering_file)
    monkeypatch.setattr(qa_mod, "_STEERING_FILE", steering_file)

    entries = [
        {**_coverage_entry(offset_min=5), "cells_closed": 15},
        {**_coverage_entry(offset_min=1), "cells_closed": 10},
    ]
    _check_suspicious_speed(entries)
    q = st_mod.SteeringQueue()
    assert any(d.get("trigger") == "SUSPICIOUS_SPEED" for d in q._load())


# ---------------------------------------------------------------------------
# _check_na_abuse
# ---------------------------------------------------------------------------

def test_na_abuse_no_matrix():
    assert _check_na_abuse({}) is None


def test_na_abuse_fewer_than_10_addressed():
    matrix = [{"status": "not_applicable"}] * 5
    assert _check_na_abuse({"matrix": matrix}) is None


def test_na_abuse_low_na_rate():
    matrix = (
        [{"status": "tested"}] * 8 +
        [{"status": "not_applicable"}] * 2
    )
    assert _check_na_abuse({"matrix": matrix}) is None


def test_na_abuse_fires_high_na_rate(tmp_path, monkeypatch):
    import core.steering as st_mod
    import core.qa_agent as qa_mod
    steering_file = tmp_path / "steering_queue.json"
    monkeypatch.setattr(st_mod, "_STEERING_FILE", steering_file)
    monkeypatch.setattr(qa_mod, "_STEERING_FILE", steering_file)

    matrix = (
        [{"status": "not_applicable"}] * 8 +
        [{"status": "tested"}] * 2
    )
    alert = _check_na_abuse({"matrix": matrix})
    assert alert is not None
    assert alert["code"] == "NA_ABUSE"
    assert "80%" in alert["message"]


def test_na_abuse_directive_injected(tmp_path, monkeypatch):
    import core.steering as st_mod
    import core.qa_agent as qa_mod
    steering_file = tmp_path / "steering_queue.json"
    monkeypatch.setattr(st_mod, "_STEERING_FILE", steering_file)
    monkeypatch.setattr(qa_mod, "_STEERING_FILE", steering_file)

    matrix = (
        [{"status": "not_applicable"}] * 8 +
        [{"status": "tested"}] * 2
    )
    _check_na_abuse({"matrix": matrix})
    q = st_mod.SteeringQueue()
    assert any(d.get("trigger") == "NA_ABUSE" for d in q._load())


# ---------------------------------------------------------------------------
# _check_depth_after_finding
# ---------------------------------------------------------------------------

def test_depth_after_finding_no_high_critical():
    findings = {"findings": [_finding_entry(severity="low")]}
    assert _check_depth_after_finding([], findings) is None


def test_depth_after_finding_finding_too_recent():
    findings = {"findings": [_finding_entry(severity="high", offset_min=5)]}
    assert _check_depth_after_finding([], findings) is None


def test_depth_after_finding_tools_ran_after():
    finding = _finding_entry(severity="high", offset_min=25)
    # tool entry with ts after the finding
    tool = _tool_entry("sqlmap", "https://example.com", offset_min=10)
    findings = {"findings": [finding]}
    assert _check_depth_after_finding([tool], findings) is None


def test_depth_after_finding_fires(tmp_path, monkeypatch):
    import core.steering as st_mod
    import core.qa_agent as qa_mod
    steering_file = tmp_path / "steering_queue.json"
    monkeypatch.setattr(st_mod, "_STEERING_FILE", steering_file)
    monkeypatch.setattr(qa_mod, "_STEERING_FILE", steering_file)

    findings = {"findings": [_finding_entry(severity="high", offset_min=25)]}
    alert = _check_depth_after_finding([], findings)
    assert alert is not None
    assert alert["code"] == "DEPTH_AFTER_FINDING"
    assert "Test high finding" in alert["message"]


def test_depth_after_finding_directive_injected(tmp_path, monkeypatch):
    import core.steering as st_mod
    import core.qa_agent as qa_mod
    steering_file = tmp_path / "steering_queue.json"
    monkeypatch.setattr(st_mod, "_STEERING_FILE", steering_file)
    monkeypatch.setattr(qa_mod, "_STEERING_FILE", steering_file)

    findings = {"findings": [_finding_entry(severity="critical", offset_min=30)]}
    _check_depth_after_finding([], findings)
    q = st_mod.SteeringQueue()
    assert any(d.get("trigger") == "DEPTH_AFTER_FINDING" for d in q._load())


# ---------------------------------------------------------------------------
# _check_whitebox_passes
# ---------------------------------------------------------------------------

def test_whitebox_passes_not_thorough():
    assert _check_whitebox_passes([], {"depth": "normal"}) is None


def test_whitebox_passes_enough_runs():
    entries = [_tool_entry("semgrep")] * 3
    assert _check_whitebox_passes(entries, {"depth": "thorough"}) is None


def test_whitebox_passes_fires_at_zero(tmp_path, monkeypatch):
    import core.steering as st_mod
    import core.qa_agent as qa_mod
    steering_file = tmp_path / "steering_queue.json"
    monkeypatch.setattr(st_mod, "_STEERING_FILE", steering_file)
    monkeypatch.setattr(qa_mod, "_STEERING_FILE", steering_file)

    wb = {"depth": "thorough", "skill_history": [{"skill": "codebase"}]}
    alert = _check_whitebox_passes([], wb)
    assert alert is not None
    assert alert["code"] == "WHITEBOX_PASSES"
    assert "0/3" in alert["message"]


def test_whitebox_passes_skipped_on_blackbox():
    # No codebase / semgrep / trufflehog → black-box scan → gate must NOT fire.
    assert _check_whitebox_passes([], {"depth": "thorough"}) is None
    assert _check_whitebox_passes([], {"depth": "thorough", "skill_history": [{"skill": "web-exploit"}]}) is None


def test_whitebox_passes_fires_at_one(tmp_path, monkeypatch):
    import core.steering as st_mod
    import core.qa_agent as qa_mod
    steering_file = tmp_path / "steering_queue.json"
    monkeypatch.setattr(st_mod, "_STEERING_FILE", steering_file)
    monkeypatch.setattr(qa_mod, "_STEERING_FILE", steering_file)

    entries = [_tool_entry("semgrep")]
    alert = _check_whitebox_passes(entries, {"depth": "thorough"})
    assert alert is not None
    assert "1/3" in alert["message"]
    assert "pass 2" in alert["message"]


def test_whitebox_passes_directive_injected(tmp_path, monkeypatch):
    import core.steering as st_mod
    import core.qa_agent as qa_mod
    steering_file = tmp_path / "steering_queue.json"
    monkeypatch.setattr(st_mod, "_STEERING_FILE", steering_file)
    monkeypatch.setattr(qa_mod, "_STEERING_FILE", steering_file)

    _check_whitebox_passes([], {"depth": "thorough", "skill_history": [{"skill": "codebase"}]})
    q = st_mod.SteeringQueue()
    assert any(d.get("trigger") == "WHITEBOX_PASSES" for d in q._load())


# ---------------------------------------------------------------------------
# _check_premature_complete
# ---------------------------------------------------------------------------

def test_premature_complete_not_thorough():
    assert _check_premature_complete([], {"depth": "normal"}) is None


def test_premature_complete_no_complete_event():
    entries = [_tool_entry("semgrep")]
    assert _check_premature_complete(entries, {"depth": "thorough"}) is None


def test_premature_complete_enough_passes():
    entries = [_tool_entry("semgrep")] * 3 + [{"type": "COMPLETE", "ts": _ts(1)}]
    assert _check_premature_complete(entries, {"depth": "thorough"}) is None


def test_premature_complete_fires():
    entries = [{"type": "COMPLETE", "ts": _ts(1)}]
    wb = {"depth": "thorough", "skill_history": [{"skill": "codebase"}]}
    alert = _check_premature_complete(entries, wb)
    assert alert is not None
    assert alert["code"] == "PREMATURE_COMPLETE"
    assert alert["blocking"] is True
    assert "0 done" in alert["message"]


def test_premature_complete_skipped_on_blackbox():
    # Black-box thorough scan (no codebase): the semgrep-pass gate must NOT block
    # completion (it would deadlock — semgrep has nothing to scan).
    entries = [{"type": "COMPLETE", "ts": _ts(1)}]
    assert _check_premature_complete(entries, {"depth": "thorough"}) is None


# ---------------------------------------------------------------------------
# _check_stuck_on_target
# ---------------------------------------------------------------------------

def test_stuck_on_target_too_few_tool_calls():
    entries = [_tool_entry(offset_min=5)] * 3
    assert _check_stuck_on_target(entries, {}, {},[]) is None


def test_stuck_on_target_spread_across_targets():
    entries = [
        _tool_entry("nmap", f"https://host{i}.com", offset_min=5)
        for i in range(5)
    ]
    assert _check_stuck_on_target(entries, {}, {},[]) is None


def test_stuck_on_target_recent_finding_allows_pass():
    entries = [_tool_entry("nmap", "https://example.com", offset_min=5)] * 5
    findings = {"findings": [_finding_entry(target="https://example.com", offset_min=10)]}
    assert _check_stuck_on_target(entries, findings, {}, []) is None


def test_stuck_on_target_first_detection(tmp_path, monkeypatch):
    import core.steering as st_mod
    import core.qa_agent as qa_mod
    steering_file = tmp_path / "steering_queue.json"
    monkeypatch.setattr(st_mod, "_STEERING_FILE", steering_file)
    monkeypatch.setattr(qa_mod, "_STEERING_FILE", steering_file)

    entries = [_tool_entry("nmap", "https://example.com", offset_min=5)] * 6
    alert = _check_stuck_on_target(entries, {}, {},[])
    assert alert is not None
    assert alert["code"] == "STUCK_ON_TARGET"
    assert "example.com" in alert["message"]


def test_stuck_on_target_second_detection_triggers_hir(tmp_path, monkeypatch):
    import core.steering as st_mod
    import core.qa_agent as qa_mod
    steering_file = tmp_path / "steering_queue.json"
    monkeypatch.setattr(st_mod, "_STEERING_FILE", steering_file)
    monkeypatch.setattr(qa_mod, "_STEERING_FILE", steering_file)

    # Simulate trigger_intervention and get_intervention
    with patch("core.session.get_intervention", return_value=None), \
         patch("core.session.trigger_intervention") as mock_trigger:
        entries = [_tool_entry("nmap", "https://example.com", offset_min=5)] * 6
        previous_alerts = [
            {"code": "STUCK_ON_TARGET", "message": "Stuck on target: 6 tool calls against 'https://example.com' ..."}
        ]
        alert = _check_stuck_on_target(entries, {}, {},previous_alerts)
        assert alert is not None
        assert alert["code"] == "STUCK_ON_TARGET"
        mock_trigger.assert_called_once()
        # Accept either calling convention — the dedup refactor moved the call
        # site to _hir() which forwards positional args; the previous direct
        # trigger_intervention call used kwargs. Using .get() instead of [] so
        # the short-circuit OR works (the kwargs path no longer has 'code').
        call_args = mock_trigger.call_args
        code = call_args.kwargs.get("code") or (call_args.args[0] if call_args.args else None)
        assert code == "HIR_STUCK_ON_TARGET"


def test_stuck_on_target_no_double_hir(tmp_path, monkeypatch):
    import core.steering as st_mod
    import core.qa_agent as qa_mod
    steering_file = tmp_path / "steering_queue.json"
    monkeypatch.setattr(st_mod, "_STEERING_FILE", steering_file)
    monkeypatch.setattr(qa_mod, "_STEERING_FILE", steering_file)

    existing_iv = {"code": "HIR_STUCK_ON_TARGET"}
    with patch("core.session.get_intervention", return_value=existing_iv), \
         patch("core.session.trigger_intervention") as mock_trigger:
        entries = [_tool_entry("nmap", "https://example.com", offset_min=5)] * 6
        previous_alerts = [
            {"code": "STUCK_ON_TARGET", "message": "Stuck on target: 6 tool calls against 'https://example.com' ..."}
        ]
        _check_stuck_on_target(entries, {}, {},previous_alerts)
        mock_trigger.assert_not_called()


def test_stuck_on_target_suppressed_after_resolution():
    # The STUCK HIR for this target was already resolved 2 min ago, and the 6
    # stale calls are OLDER than that resolution (no new spinning since) — must
    # NOT re-fire. Without the fix, those stale calls stay in the 30-min window
    # and re-trigger the HIR every cycle (the storm the operator hit).
    entries = [_tool_entry("nmap", "https://example.com", offset_min=10)] * 6
    session_data = {"intervention_history": [{
        "code": "HIR_STUCK_ON_TARGET",
        "situation": "Smith has made 6 tool calls against 'https://example.com' ...",
        "resolved_at": _ts(2),
    }]}
    previous_alerts = [
        {"code": "STUCK_ON_TARGET", "message": "Stuck on target: 6 ... 'https://example.com' ..."}
    ]
    assert _check_stuck_on_target(entries, {}, session_data, previous_alerts) is None


def test_stuck_on_target_refires_on_new_spinning_after_resolution(tmp_path, monkeypatch):
    # Resolved 10 min ago, then 5+ FRESH calls (1 min ago) with no progress →
    # genuinely still stuck after going deeper → SHOULD re-escalate.
    import core.steering as st_mod
    import core.qa_agent as qa_mod
    steering_file = tmp_path / "steering_queue.json"
    monkeypatch.setattr(st_mod, "_STEERING_FILE", steering_file)
    monkeypatch.setattr(qa_mod, "_STEERING_FILE", steering_file)

    session_data = {"intervention_history": [{
        "code": "HIR_STUCK_ON_TARGET",
        "situation": "...against 'https://example.com'...",
        "resolved_at": _ts(10),
    }]}
    entries = [_tool_entry("nmap", "https://example.com", offset_min=1)] * 6
    previous_alerts = [
        {"code": "STUCK_ON_TARGET", "message": "Stuck on target: 6 ... 'https://example.com' ..."}
    ]
    with patch("core.session.get_intervention", return_value=None), \
         patch("core.session.trigger_intervention"):
        alert = _check_stuck_on_target(entries, {}, session_data, previous_alerts)
    # Returns the alert (refire path taken) — the opposite of the suppressed case,
    # which returns None. (Whether _hir's min-gap fires the trigger is its own concern.)
    assert alert is not None and alert["code"] == "STUCK_ON_TARGET"


# ---------------------------------------------------------------------------
# _maybe_inject_web_exploit_directive
# ---------------------------------------------------------------------------

def test_maybe_inject_web_exploit_no_spider_ts():
    alerts = []
    _maybe_inject_web_exploit_directive("", set(), datetime.now(timezone.utc), alerts)
    assert alerts == []


def test_maybe_inject_web_exploit_already_run():
    alerts = []
    now = datetime.now(timezone.utc)
    spider_ts = (now - timedelta(minutes=30)).isoformat()
    _maybe_inject_web_exploit_directive(spider_ts, {"web-exploit"}, now, alerts)
    assert alerts == []


def test_maybe_inject_web_exploit_too_recent():
    alerts = []
    now = datetime.now(timezone.utc)
    spider_ts = (now - timedelta(minutes=5)).isoformat()
    _maybe_inject_web_exploit_directive(spider_ts, set(), now, alerts)
    assert alerts == []


def test_maybe_inject_web_exploit_fires(tmp_path, monkeypatch):
    import core.steering as st_mod
    import core.qa_agent as qa_mod
    steering_file = tmp_path / "steering_queue.json"
    monkeypatch.setattr(st_mod, "_STEERING_FILE", steering_file)
    monkeypatch.setattr(qa_mod, "_STEERING_FILE", steering_file)

    alerts = []
    now = datetime.now(timezone.utc)
    spider_ts = (now - timedelta(minutes=30)).isoformat()
    _maybe_inject_web_exploit_directive(spider_ts, set(), now, alerts)
    assert len(alerts) == 1
    assert alerts[0]["code"] == "MISSING_WEB_EXPLOIT"
    q = st_mod.SteeringQueue()
    assert any(d.get("trigger") == "MISSING_WEB_EXPLOIT" for d in q._load())


# ---------------------------------------------------------------------------
# _maybe_inject_param_fuzz_directive
# ---------------------------------------------------------------------------

def test_maybe_inject_param_fuzz_no_web_exploit_ts():
    alerts = []
    _maybe_inject_param_fuzz_directive("", set(), datetime.now(timezone.utc), alerts)
    assert alerts == []


def test_maybe_inject_param_fuzz_already_run():
    alerts = []
    now = datetime.now(timezone.utc)
    web_ts = (now - timedelta(minutes=30)).isoformat()
    _maybe_inject_param_fuzz_directive(web_ts, {"param-fuzz"}, now, alerts)
    assert alerts == []


def test_maybe_inject_param_fuzz_too_recent():
    alerts = []
    now = datetime.now(timezone.utc)
    web_ts = (now - timedelta(minutes=5)).isoformat()
    _maybe_inject_param_fuzz_directive(web_ts, set(), now, alerts)
    assert alerts == []


def test_maybe_inject_param_fuzz_fires(tmp_path, monkeypatch):
    import core.steering as st_mod
    import core.qa_agent as qa_mod
    steering_file = tmp_path / "steering_queue.json"
    monkeypatch.setattr(st_mod, "_STEERING_FILE", steering_file)
    monkeypatch.setattr(qa_mod, "_STEERING_FILE", steering_file)

    alerts = []
    now = datetime.now(timezone.utc)
    web_ts = (now - timedelta(minutes=30)).isoformat()
    _maybe_inject_param_fuzz_directive(web_ts, set(), now, alerts)
    assert len(alerts) == 1
    assert alerts[0]["code"] == "MISSING_PARAM_FUZZ"
    q = st_mod.SteeringQueue()
    assert any(d.get("trigger") == "MISSING_PARAM_FUZZ" for d in q._load())


def test_maybe_inject_param_fuzz_skips_directive_when_web_exploit_alert_pending(tmp_path, monkeypatch):
    """When MISSING_WEB_EXPLOIT is already in alerts list, skip adding directive."""
    import core.steering as st_mod
    import core.qa_agent as qa_mod
    steering_file = tmp_path / "steering_queue.json"
    monkeypatch.setattr(st_mod, "_STEERING_FILE", steering_file)
    monkeypatch.setattr(qa_mod, "_STEERING_FILE", steering_file)

    # pre-populate with MISSING_WEB_EXPLOIT so directive injection is suppressed
    existing_alert = {"code": "MISSING_WEB_EXPLOIT", "urgency": "high", "blocking": False, "message": "..."}
    alerts = [existing_alert]
    now = datetime.now(timezone.utc)
    web_ts = (now - timedelta(minutes=30)).isoformat()
    _maybe_inject_param_fuzz_directive(web_ts, set(), now, alerts)
    # alert appended but no steering directive
    assert any(a["code"] == "MISSING_PARAM_FUZZ" for a in alerts)
    q = st_mod.SteeringQueue()
    assert not any(d.get("trigger") == "MISSING_PARAM_FUZZ" for d in q._load())


# ---------------------------------------------------------------------------
# _maybe_inject_business_logic_directive
# ---------------------------------------------------------------------------

def test_maybe_inject_business_logic_not_thorough():
    alerts = []
    _maybe_inject_business_logic_directive("normal", [], {"web-exploit", "param-fuzz"}, datetime.now(timezone.utc), alerts)
    assert alerts == []


def test_maybe_inject_business_logic_missing_prerequisite_skills():
    alerts = []
    now = datetime.now(timezone.utc)
    # only web-exploit done, not param-fuzz
    _maybe_inject_business_logic_directive("thorough", [], {"web-exploit"}, now, alerts)
    assert alerts == []


def test_maybe_inject_business_logic_already_run():
    alerts = []
    now = datetime.now(timezone.utc)
    _maybe_inject_business_logic_directive(
        "thorough", [], {"web-exploit", "param-fuzz", "business-logic"}, now, alerts
    )
    assert alerts == []


def test_maybe_inject_business_logic_no_param_fuzz_ts():
    """No param-fuzz entry in skill_history — should return early."""
    alerts = []
    now = datetime.now(timezone.utc)
    _maybe_inject_business_logic_directive(
        "thorough", [], {"web-exploit", "param-fuzz"}, now, alerts
    )
    assert alerts == []


def test_maybe_inject_business_logic_param_fuzz_too_recent():
    alerts = []
    now = datetime.now(timezone.utc)
    skill_history = [_skill_history_entry("param-fuzz", offset_min=5)]
    _maybe_inject_business_logic_directive(
        "thorough", skill_history, {"web-exploit", "param-fuzz"}, now, alerts
    )
    assert alerts == []


def test_maybe_inject_business_logic_fires(tmp_path, monkeypatch):
    import core.steering as st_mod
    import core.qa_agent as qa_mod
    steering_file = tmp_path / "steering_queue.json"
    monkeypatch.setattr(st_mod, "_STEERING_FILE", steering_file)
    monkeypatch.setattr(qa_mod, "_STEERING_FILE", steering_file)

    alerts = []
    now = datetime.now(timezone.utc)
    skill_history = [_skill_history_entry("param-fuzz", offset_min=30)]
    _maybe_inject_business_logic_directive(
        "thorough", skill_history, {"web-exploit", "param-fuzz"}, now, alerts
    )
    assert len(alerts) == 1
    assert alerts[0]["code"] == "MISSING_BUSINESS_LOGIC"
    q = st_mod.SteeringQueue()
    assert any(d.get("trigger") == "MISSING_BUSINESS_LOGIC" for d in q._load())


# ---------------------------------------------------------------------------
# _check_core_skill_chain
# ---------------------------------------------------------------------------

def test_core_skill_chain_no_spider():
    alerts = _check_core_skill_chain([], {})
    assert alerts == []


def test_core_skill_chain_missing_web_exploit(tmp_path, monkeypatch):
    import core.steering as st_mod
    import core.qa_agent as qa_mod
    steering_file = tmp_path / "steering_queue.json"
    monkeypatch.setattr(st_mod, "_STEERING_FILE", steering_file)
    monkeypatch.setattr(qa_mod, "_STEERING_FILE", steering_file)

    entries = [_spider_entry(endpoints_found=5, offset_min=30)]
    session_data = {"skill_history": [], "depth": "normal"}
    alerts = _check_core_skill_chain(entries, session_data)
    assert any(a["code"] == "MISSING_WEB_EXPLOIT" for a in alerts)


def test_core_skill_chain_missing_param_fuzz(tmp_path, monkeypatch):
    import core.steering as st_mod
    import core.qa_agent as qa_mod
    steering_file = tmp_path / "steering_queue.json"
    monkeypatch.setattr(st_mod, "_STEERING_FILE", steering_file)
    monkeypatch.setattr(qa_mod, "_STEERING_FILE", steering_file)

    entries = [_spider_entry(endpoints_found=5, offset_min=30)]
    session_data = {
        "skill_history": [_skill_history_entry("web-exploit", offset_min=30)],
        "depth": "normal",
    }
    alerts = _check_core_skill_chain(entries, session_data)
    assert any(a["code"] == "MISSING_PARAM_FUZZ" for a in alerts)


def test_core_skill_chain_missing_business_logic_thorough(tmp_path, monkeypatch):
    import core.steering as st_mod
    import core.qa_agent as qa_mod
    steering_file = tmp_path / "steering_queue.json"
    monkeypatch.setattr(st_mod, "_STEERING_FILE", steering_file)
    monkeypatch.setattr(qa_mod, "_STEERING_FILE", steering_file)

    entries = [_spider_entry(endpoints_found=5, offset_min=60)]
    session_data = {
        "skill_history": [
            _skill_history_entry("web-exploit", offset_min=60),
            _skill_history_entry("param-fuzz", offset_min=30),
        ],
        "depth": "thorough",
    }
    alerts = _check_core_skill_chain(entries, session_data)
    assert any(a["code"] == "MISSING_BUSINESS_LOGIC" for a in alerts)


def test_core_skill_chain_all_skills_present():
    entries = [_spider_entry(endpoints_found=5, offset_min=60)]
    session_data = {
        "skill_history": [
            _skill_history_entry("web-exploit", offset_min=60),
            _skill_history_entry("param-fuzz", offset_min=30),
            _skill_history_entry("business-logic", offset_min=15),
        ],
        "depth": "thorough",
    }
    # No missing skills since all are present
    alerts = _check_core_skill_chain(entries, session_data)
    codes = {a["code"] for a in alerts}
    assert "MISSING_WEB_EXPLOIT" not in codes
    assert "MISSING_PARAM_FUZZ" not in codes
    assert "MISSING_BUSINESS_LOGIC" not in codes


# ---------------------------------------------------------------------------
# _hir
# ---------------------------------------------------------------------------

def test_hir_calls_trigger_intervention_when_no_active():
    with patch("core.session.get_intervention", return_value=None), \
         patch("core.session.trigger_intervention") as mock_trigger:
        _hir("TEST_CODE", "situation", ["tried"], ["option1"])
        mock_trigger.assert_called_once_with("TEST_CODE", "situation", ["tried"], ["option1"])


def test_hir_does_not_call_trigger_when_active():
    with patch("core.session.get_intervention", return_value={"code": "existing"}), \
         patch("core.session.trigger_intervention") as mock_trigger:
        _hir("TEST_CODE", "situation", ["tried"], ["option1"])
        mock_trigger.assert_not_called()


def test_hir_swallows_exceptions():
    with patch("core.session.get_intervention", side_effect=RuntimeError("boom")):
        # Should not raise
        _hir("TEST_CODE", "situation", ["tried"], ["option1"])


# ---------------------------------------------------------------------------
# _hir min-gap backstop — prevents the burst the user observed (5 HIR_STUCK_ON_TARGET
# events fired within 137ms because get_intervention() read a stale cache).
# Even if dedup were defeated, this floor caps to 1 HIR per code per minute.
# ---------------------------------------------------------------------------

def test_hir_min_gap_blocks_second_trigger_within_window(monkeypatch):
    """Two _hir() calls for the same code inside the gap window must
    result in exactly ONE trigger_intervention. Simulates the QA-cycle
    race where get_intervention() returns None twice in a row before
    the first trigger's flush is observed by the second's read."""
    import core.qa_agent as qa_mod
    # Force a clean ledger so prior tests don't poison this one
    monkeypatch.setattr(qa_mod, "_last_hir_trigger_ts", {})
    with patch("core.session.get_intervention", return_value=None), \
         patch("core.session.trigger_intervention") as mock_trigger:
        qa_mod._hir("BURST_CODE", "s", [], [])
        qa_mod._hir("BURST_CODE", "s", [], [])  # within gap — must be blocked
        assert mock_trigger.call_count == 1


def test_hir_min_gap_allows_different_codes(monkeypatch):
    """The gap is PER CODE — an unrelated HIR (e.g. HIR_AUTH_FAILURE)
    must still fire even if HIR_STUCK_ON_TARGET just fired. Otherwise
    one burst-blocked code would suppress all other QA checks for 60s."""
    import core.qa_agent as qa_mod
    monkeypatch.setattr(qa_mod, "_last_hir_trigger_ts", {})
    with patch("core.session.get_intervention", return_value=None), \
         patch("core.session.trigger_intervention") as mock_trigger:
        qa_mod._hir("CODE_A", "s", [], [])
        qa_mod._hir("CODE_B", "s", [], [])  # different code, allowed
        assert mock_trigger.call_count == 2


def test_hir_min_gap_allows_retrigger_after_window(monkeypatch):
    """After _HIR_MIN_GAP_SECONDS has elapsed, the same code is allowed
    to re-fire. Tested by overriding the ledger entry to simulate a
    past trigger past the gap."""
    import core.qa_agent as qa_mod
    monkeypatch.setattr(qa_mod, "_last_hir_trigger_ts",
                        {"OLD_CODE": 0.0})  # epoch-1970 → way past the gap
    with patch("core.session.get_intervention", return_value=None), \
         patch("core.session.trigger_intervention") as mock_trigger:
        qa_mod._hir("OLD_CODE", "s", [], [])
        assert mock_trigger.call_count == 1


# ---------------------------------------------------------------------------
# _check_auth_failure
# ---------------------------------------------------------------------------

def test_auth_failure_too_few_entries():
    entries = [_http_entry(status_code=401)] * 3
    assert _check_auth_failure(entries) is None


def test_auth_failure_never_authed():
    entries = [_http_entry(status_code=401)] * 5
    assert _check_auth_failure(entries) is None


def test_auth_failure_low_failure_rate():
    entries = (
        [_http_entry(status_code=200)] * 5 +
        [_http_entry(status_code=401)] * 2
    )
    assert _check_auth_failure(entries) is None


def test_auth_failure_fires(tmp_path, monkeypatch):
    with patch("core.session.get_intervention", return_value=None), \
         patch("core.session.trigger_intervention") as mock_trigger:
        entries = (
            [_http_entry(status_code=200)] * 5 +
            [_http_entry(status_code=401)] * 8
        )
        alert = _check_auth_failure(entries)
        assert alert is not None
        assert alert["code"] == "HIR_AUTH_FAILURE"
        mock_trigger.assert_called_once()


def test_auth_failure_403_also_counts():
    with patch("core.session.get_intervention", return_value=None), \
         patch("core.session.trigger_intervention"):
        entries = (
            [_http_entry(status_code=200)] * 5 +
            [_http_entry(status_code=403)] * 8
        )
        alert = _check_auth_failure(entries)
        assert alert is not None
        assert alert["code"] == "HIR_AUTH_FAILURE"


# ---------------------------------------------------------------------------
# _check_budget_limit
# ---------------------------------------------------------------------------

def test_budget_limit_no_max_calls():
    assert _check_budget_limit({}, {}) is None


def test_budget_limit_below_90_percent():
    session_data = {"calls_used": 80, "max_tool_calls": 100}
    assert _check_budget_limit(session_data, {}) is None


def test_budget_limit_high_coverage():
    session_data = {"calls_used": 95, "max_tool_calls": 100}
    coverage_data = {"meta": {"total_cells": 100, "tested": 85, "not_applicable": 0}}
    assert _check_budget_limit(session_data, coverage_data) is None


def test_budget_limit_fires():
    with patch("core.session.get_intervention", return_value=None), \
         patch("core.session.trigger_intervention") as mock_trigger:
        session_data = {"calls_used": 95, "max_tool_calls": 100}
        coverage_data = {"meta": {"total_cells": 100, "tested": 50, "not_applicable": 0}}
        alert = _check_budget_limit(session_data, coverage_data)
        assert alert is not None
        assert alert["code"] == "HIR_BUDGET_LIMIT"
        mock_trigger.assert_called_once()


def test_budget_limit_no_total_cells_treated_as_done():
    # total=0 → coverage_pct = 1.0 → skip
    session_data = {"calls_used": 95, "max_tool_calls": 100}
    coverage_data = {"meta": {"total_cells": 0, "tested": 0, "not_applicable": 0}}
    assert _check_budget_limit(session_data, coverage_data) is None


# ---------------------------------------------------------------------------
# _check_zero_endpoints
# ---------------------------------------------------------------------------

def test_zero_endpoints_no_spider():
    assert _check_zero_endpoints([], {}) is None


def test_zero_endpoints_spider_found_some():
    entries = [_spider_entry(endpoints_found=5, offset_min=15)]
    assert _check_zero_endpoints(entries, {}) is None


def test_zero_endpoints_matrix_not_empty():
    entries = [_spider_entry(endpoints_found=0, offset_min=15)]
    coverage = {"meta": {"total_cells": 10}}
    assert _check_zero_endpoints(entries, coverage) is None


def test_zero_endpoints_spider_too_recent():
    entries = [_spider_entry(endpoints_found=0, offset_min=5)]
    assert _check_zero_endpoints(entries, {}) is None


def test_zero_endpoints_fires():
    with patch("core.session.get_intervention", return_value=None), \
         patch("core.session.trigger_intervention") as mock_trigger:
        entries = [_spider_entry(endpoints_found=0, offset_min=15)]
        alert = _check_zero_endpoints(entries, {})
        assert alert is not None
        assert alert["code"] == "HIR_NO_ENDPOINTS"
        mock_trigger.assert_called_once()


# ---------------------------------------------------------------------------
# _check_target_unreachable
# ---------------------------------------------------------------------------

def test_target_unreachable_too_few_tool_entries():
    entries = [_error_tool_entry()] * 2
    assert _check_target_unreachable(entries) is None


def test_target_unreachable_errors_on_different_targets():
    entries = [
        _error_tool_entry(target="https://a.com"),
        _error_tool_entry(target="https://b.com"),
        _error_tool_entry(target="https://c.com"),
    ]
    assert _check_target_unreachable(entries) is None


def test_target_unreachable_run_count_below_3():
    entries = [
        _error_tool_entry(target="https://example.com"),
        _error_tool_entry(target="https://example.com"),
        _tool_entry("nmap", "https://example.com"),  # success breaks the run
    ]
    assert _check_target_unreachable(entries) is None


def test_target_unreachable_fires():
    with patch("core.session.get_intervention", return_value=None), \
         patch("core.session.trigger_intervention") as mock_trigger:
        entries = [
            _error_tool_entry(target="https://example.com"),
            _error_tool_entry(target="https://example.com"),
            _error_tool_entry(target="https://example.com"),
        ]
        alert = _check_target_unreachable(entries)
        assert alert is not None
        assert alert["code"] == "HIR_TARGET_UNREACHABLE"
        mock_trigger.assert_called_once()


# ---------------------------------------------------------------------------
# _check_exploit_escalation
# ---------------------------------------------------------------------------

def test_exploit_escalation_not_benchmark():
    findings = {"findings": [_finding_entry(severity="critical", offset_min=20)]}
    assert _check_exploit_escalation([], findings, {"scan_mode": "pentest"}) is None


def test_exploit_escalation_no_findings():
    assert _check_exploit_escalation([], {}, {"scan_mode": "benchmark"}) is None


def test_exploit_escalation_finding_too_recent():
    findings = {"findings": [_finding_entry(severity="critical", offset_min=5)]}
    assert _check_exploit_escalation([], findings, {"scan_mode": "benchmark"}) is None


def test_exploit_escalation_exploit_tool_ran_after():
    finding = _finding_entry(severity="critical", offset_min=20)
    exploit_tool = _tool_entry("metasploit", "https://example.com", offset_min=10)
    findings = {"findings": [finding]}
    assert _check_exploit_escalation([exploit_tool], findings, {"scan_mode": "benchmark"}) is None


def test_exploit_escalation_fires(tmp_path, monkeypatch):
    import core.steering as st_mod
    import core.qa_agent as qa_mod
    steering_file = tmp_path / "steering_queue.json"
    monkeypatch.setattr(st_mod, "_STEERING_FILE", steering_file)
    monkeypatch.setattr(qa_mod, "_STEERING_FILE", steering_file)

    findings = {"findings": [_finding_entry(severity="critical", offset_min=20)]}
    alert = _check_exploit_escalation([], findings, {"scan_mode": "benchmark"})
    assert alert is not None
    assert alert["code"] == "EXPLOIT_ESCALATION"
    q = st_mod.SteeringQueue()
    assert any(d.get("trigger") == "EXPLOIT_ESCALATION" for d in q._load())


# ---------------------------------------------------------------------------
# _check_repeated_tool_failure
# ---------------------------------------------------------------------------

def test_repeated_tool_failure_too_few_error_entries():
    entries = [_error_tool_entry("nmap")] * 2
    assert _check_repeated_tool_failure(entries) is None


def test_repeated_tool_failure_different_tools():
    entries = [
        _error_tool_entry("nmap"),
        _error_tool_entry("nuclei"),
        _error_tool_entry("ffuf"),
    ]
    assert _check_repeated_tool_failure(entries) is None


def test_repeated_tool_failure_errors_too_old():
    entries = [
        {"type": "TOOL", "name": "nmap", "target": "https://example.com",
         "ts": _ts(25), "error": True},
        {"type": "TOOL", "name": "nmap", "target": "https://example.com",
         "ts": _ts(22), "error": True},
        {"type": "TOOL", "name": "nmap", "target": "https://example.com",
         "ts": _ts(21), "error": True},
    ]
    assert _check_repeated_tool_failure(entries) is None


def test_repeated_tool_failure_fires():
    with patch("core.session.get_intervention", return_value=None), \
         patch("core.session.trigger_intervention") as mock_trigger:
        entries = [_error_tool_entry("nmap", offset_min=1)] * 3
        alert = _check_repeated_tool_failure(entries)
        assert alert is not None
        assert alert["code"] == "HIR_TOOL_FAILURE"
        assert "nmap" in alert["message"]
        mock_trigger.assert_called_once()


# ── _cycle() Telegram notification path ───────────────────────────────────────

@pytest.mark.asyncio
async def test_cycle_calls_notify_for_high_urgency_alerts(tmp_path, monkeypatch):
    import core.steering as st_mod
    monkeypatch.setattr(st_mod, "_STEERING_FILE", tmp_path / "steering_queue.json")
    _setup_cycle_files(tmp_path, monkeypatch)
    monkeypatch.setattr(core.quick_log, "quick_log",
                        _mock_ql(entries=[_coverage_entry(na_untooled=15)]))

    high_alert = {"code": "BULK_MARKING", "urgency": "high", "blocking": False,
                  "message": "too many untooled"}
    with patch("core.qa_agent._deterministic_qa_checks", return_value=[high_alert]), \
         patch("core.notifiers.notify") as mock_notify:
        daemon = QADaemon()
        await daemon._cycle()

    mock_notify.assert_called_once_with(
        title="[QA] BULK_MARKING",
        body="too many untooled",
        urgency="high",
        code="BULK_MARKING",
    )


@pytest.mark.asyncio
async def test_cycle_notify_exception_is_swallowed(tmp_path, monkeypatch):
    import core.steering as st_mod
    monkeypatch.setattr(st_mod, "_STEERING_FILE", tmp_path / "steering_queue.json")
    qa_state = _setup_cycle_files(tmp_path, monkeypatch)
    monkeypatch.setattr(core.quick_log, "quick_log",
                        _mock_ql(entries=[_coverage_entry(na_untooled=15)]))

    high_alert = {"code": "BULK_MARKING", "urgency": "high", "blocking": False,
                  "message": "too many untooled"}
    with patch("core.qa_agent._deterministic_qa_checks", return_value=[high_alert]), \
         patch("core.notifiers.notify", side_effect=RuntimeError("sink down")):
        daemon = QADaemon()
        await daemon._cycle()  # must not raise

    assert qa_state.exists()  # cycle still wrote state despite notification failure
