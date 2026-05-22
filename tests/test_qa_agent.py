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
