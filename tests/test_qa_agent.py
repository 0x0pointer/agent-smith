"""
Tests for core.qa_agent — session check and QADaemon cycle logic.
"""
import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

import core.qa_agent
import core.quick_log
from core.qa_agent import _session_is_running, QADaemon
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
# QADaemon._cycle() — early-return guards
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cycle_skips_when_session_not_running(tmp_path, monkeypatch):
    monkeypatch.setattr(core.qa_agent, "_SESSION_FILE", tmp_path / "session.json")
    qa_state = tmp_path / "qa_state.json"
    monkeypatch.setattr(core.qa_agent, "_QA_STATE_FILE", qa_state)

    daemon = QADaemon()
    await daemon._cycle()

    assert not qa_state.exists()


@pytest.mark.asyncio
async def test_cycle_skips_when_graph_is_none(tmp_path, monkeypatch):
    session_file = tmp_path / "session.json"
    session_file.write_text(json.dumps({"status": "running"}))
    monkeypatch.setattr(core.qa_agent, "_SESSION_FILE", session_file)

    qa_state = tmp_path / "qa_state.json"
    monkeypatch.setattr(core.qa_agent, "_QA_STATE_FILE", qa_state)

    daemon = QADaemon()
    monkeypatch.setattr(daemon, "_get_graph", lambda: None)

    await daemon._cycle()

    assert not qa_state.exists()


@pytest.mark.asyncio
async def test_cycle_skips_when_quick_log_is_empty(tmp_path, monkeypatch):
    session_file = tmp_path / "session.json"
    session_file.write_text(json.dumps({"status": "running"}))
    monkeypatch.setattr(core.qa_agent, "_SESSION_FILE", session_file)

    qa_state = tmp_path / "qa_state.json"
    monkeypatch.setattr(core.qa_agent, "_QA_STATE_FILE", qa_state)

    test_log = QuickLog(path=tmp_path / "quick_log.json")
    monkeypatch.setattr(core.quick_log, "quick_log", test_log)

    mock_graph = MagicMock()
    daemon = QADaemon()
    monkeypatch.setattr(daemon, "_get_graph", lambda: mock_graph)

    await daemon._cycle()

    assert not qa_state.exists()


# ---------------------------------------------------------------------------
# QADaemon._cycle() — successful write
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cycle_writes_qa_state_with_alerts(tmp_path, monkeypatch):
    session_file = tmp_path / "session.json"
    session_file.write_text(json.dumps({"status": "running"}))
    monkeypatch.setattr(core.qa_agent, "_SESSION_FILE", session_file)

    qa_state = tmp_path / "qa_state.json"
    monkeypatch.setattr(core.qa_agent, "_QA_STATE_FILE", qa_state)

    test_log = QuickLog(path=tmp_path / "quick_log.json")
    await test_log.append({"type": "TOOL", "name": "nmap", "ts": "2026-01-01T00:00:00+00:00"})
    monkeypatch.setattr(core.quick_log, "quick_log", test_log)

    mock_graph = MagicMock()
    daemon = QADaemon()
    monkeypatch.setattr(daemon, "_get_graph", lambda: mock_graph)

    expected_alerts = [{"urgency": "high", "message": "test alert"}]
    mock_result = {"alerts": expected_alerts}

    with patch("asyncio.to_thread", new=AsyncMock(return_value=mock_result)):
        await daemon._cycle()

    assert qa_state.exists()
    data = json.loads(qa_state.read_text())
    assert data["alerts"] == expected_alerts
    assert "ts" in data
    assert "history" in data


@pytest.mark.asyncio
async def test_cycle_captures_smith_actions_in_history(tmp_path, monkeypatch):
    session_file = tmp_path / "session.json"
    session_file.write_text(json.dumps({"status": "running"}))
    monkeypatch.setattr(core.qa_agent, "_SESSION_FILE", session_file)

    qa_state = tmp_path / "qa_state.json"
    monkeypatch.setattr(core.qa_agent, "_QA_STATE_FILE", qa_state)

    test_log = QuickLog(path=tmp_path / "quick_log.json")
    await test_log.append({"type": "TOOL", "name": "nmap", "ts": "2026-01-01T00:00:00+00:00"})
    monkeypatch.setattr(core.quick_log, "quick_log", test_log)

    mock_graph = MagicMock()
    daemon = QADaemon()
    monkeypatch.setattr(daemon, "_get_graph", lambda: mock_graph)

    new_action = {"type": "TOOL", "name": "nuclei", "ts": "2099-12-31T23:59:59+00:00"}

    async def mock_to_thread(fn, *args, **kwargs):
        await test_log.append(new_action)
        return {"alerts": []}

    with patch("asyncio.to_thread", new=mock_to_thread):
        await daemon._cycle()

    data = json.loads(qa_state.read_text())
    assert len(data["history"]) == 1
    smith_actions = data["history"][0]["smith_actions"]
    assert any(a.get("name") == "nuclei" for a in smith_actions)


@pytest.mark.asyncio
async def test_cycle_caps_history_at_20(tmp_path, monkeypatch):
    session_file = tmp_path / "session.json"
    session_file.write_text(json.dumps({"status": "running"}))
    monkeypatch.setattr(core.qa_agent, "_SESSION_FILE", session_file)

    qa_state = tmp_path / "qa_state.json"
    existing_history = [
        {"ts": f"2026-01-{i:02d}T00:00:00+00:00", "summary_sent": "s", "alerts": [], "smith_actions": []}
        for i in range(1, 21)
    ]
    qa_state.write_text(json.dumps({"ts": "2026-01-20T00:00:00+00:00", "alerts": [], "history": existing_history}))
    monkeypatch.setattr(core.qa_agent, "_QA_STATE_FILE", qa_state)

    test_log = QuickLog(path=tmp_path / "quick_log.json")
    await test_log.append({"type": "TOOL", "name": "nmap", "ts": "2026-01-01T00:00:00+00:00"})
    monkeypatch.setattr(core.quick_log, "quick_log", test_log)

    mock_graph = MagicMock()
    daemon = QADaemon()
    monkeypatch.setattr(daemon, "_get_graph", lambda: mock_graph)

    with patch("asyncio.to_thread", new=AsyncMock(return_value={"alerts": []})):
        await daemon._cycle()

    data = json.loads(qa_state.read_text())
    assert len(data["history"]) == 20


@pytest.mark.asyncio
async def test_cycle_handles_corrupt_qa_state_gracefully(tmp_path, monkeypatch):
    session_file = tmp_path / "session.json"
    session_file.write_text(json.dumps({"status": "running"}))
    monkeypatch.setattr(core.qa_agent, "_SESSION_FILE", session_file)

    qa_state = tmp_path / "qa_state.json"
    qa_state.write_text("not valid json {{{")
    monkeypatch.setattr(core.qa_agent, "_QA_STATE_FILE", qa_state)

    test_log = QuickLog(path=tmp_path / "quick_log.json")
    await test_log.append({"type": "TOOL", "name": "nmap", "ts": "2026-01-01T00:00:00+00:00"})
    monkeypatch.setattr(core.quick_log, "quick_log", test_log)

    mock_graph = MagicMock()
    daemon = QADaemon()
    monkeypatch.setattr(daemon, "_get_graph", lambda: mock_graph)

    with patch("asyncio.to_thread", new=AsyncMock(return_value={"alerts": []})):
        await daemon._cycle()

    data = json.loads(qa_state.read_text())
    assert len(data["history"]) == 1


@pytest.mark.asyncio
async def test_cycle_handles_malformed_llm_json(tmp_path, monkeypatch):
    session_file = tmp_path / "session.json"
    session_file.write_text(json.dumps({"status": "running"}))
    monkeypatch.setattr(core.qa_agent, "_SESSION_FILE", session_file)

    qa_state = tmp_path / "qa_state.json"
    monkeypatch.setattr(core.qa_agent, "_QA_STATE_FILE", qa_state)

    test_log = QuickLog(path=tmp_path / "quick_log.json")
    await test_log.append({"type": "TOOL", "name": "nmap", "ts": "2026-01-01T00:00:00+00:00"})
    monkeypatch.setattr(core.quick_log, "quick_log", test_log)

    mock_graph = MagicMock()
    daemon = QADaemon()
    monkeypatch.setattr(daemon, "_get_graph", lambda: mock_graph)

    with patch("asyncio.to_thread", new=AsyncMock(return_value={"alerts": []})):
        await daemon._cycle()

    data = json.loads(qa_state.read_text())
    assert data["alerts"] == []


@pytest.mark.asyncio
async def test_cycle_handles_alerts_not_a_list(tmp_path, monkeypatch):
    session_file = tmp_path / "session.json"
    session_file.write_text(json.dumps({"status": "running"}))
    monkeypatch.setattr(core.qa_agent, "_SESSION_FILE", session_file)

    qa_state = tmp_path / "qa_state.json"
    monkeypatch.setattr(core.qa_agent, "_QA_STATE_FILE", qa_state)

    test_log = QuickLog(path=tmp_path / "quick_log.json")
    await test_log.append({"type": "TOOL", "name": "nmap", "ts": "2026-01-01T00:00:00+00:00"})
    monkeypatch.setattr(core.quick_log, "quick_log", test_log)

    mock_graph = MagicMock()
    daemon = QADaemon()
    monkeypatch.setattr(daemon, "_get_graph", lambda: mock_graph)

    with patch("asyncio.to_thread", new=AsyncMock(return_value={"alerts": "not-a-list"})):
        await daemon._cycle()

    data = json.loads(qa_state.read_text())
    assert data["alerts"] == "not-a-list"
