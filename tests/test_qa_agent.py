"""
Tests for core.qa_agent — session check and QADaemon cycle logic.
"""
import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

import core.qa_agent
import core.quick_log
from core.qa_agent import (
    _session_is_running, _read_qa_state, _build_context_summary,
    _sanitize_history, _init_llm, _build_graph, QADaemon,
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
    # Seed a previous cycle so prev_cycle_ts is set and read_since() can capture
    # actions that happen during the LLM call (the scenario under test).
    qa_state.write_text(json.dumps({
        "ts": "2025-12-31T00:00:00+00:00",
        "alerts": [],
        "history": [{"ts": "2025-12-31T00:00:00+00:00", "summary_sent": "prev", "alerts": [], "smith_actions": []}],
    }))
    monkeypatch.setattr(core.qa_agent, "_QA_STATE_FILE", qa_state)

    test_log = QuickLog(path=tmp_path / "quick_log.json")
    await test_log.append({"type": "TOOL", "name": "nmap", "ts": "2026-01-01T00:00:00+00:00"})
    monkeypatch.setattr(core.quick_log, "quick_log", test_log)

    mock_graph = MagicMock()
    daemon = QADaemon()
    monkeypatch.setattr(daemon, "_get_graph", lambda: mock_graph)

    new_action = {"type": "TOOL", "name": "nuclei", "ts": "2099-12-31T23:59:59+00:00"}

    import asyncio as _real_asyncio
    _real_to_thread = _real_asyncio.to_thread  # capture before patch replaces it

    async def mock_to_thread(fn, *args, **kwargs):
        if isinstance(fn, MagicMock):  # intercept graph.invoke only
            await test_log.append(new_action)
            return {"alerts": []}
        return await _real_to_thread(fn, *args, **kwargs)

    with patch("asyncio.to_thread", new=mock_to_thread):
        await daemon._cycle()

    data = json.loads(qa_state.read_text())
    assert len(data["history"]) == 2
    smith_actions = data["history"][-1]["smith_actions"]
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


@pytest.mark.asyncio
async def test_cycle_skips_write_when_alerts_unchanged(tmp_path, monkeypatch):
    session_file = tmp_path / "session.json"
    session_file.write_text(json.dumps({"status": "running"}))
    monkeypatch.setattr(core.qa_agent, "_SESSION_FILE", session_file)

    alert = {"urgency": "low", "message": "same alert"}
    qa_state = tmp_path / "qa_state.json"
    qa_state.write_text(json.dumps({
        "ts": "2026-01-01T00:00:00+00:00",
        "alerts": [alert],
        "history": [],
    }))
    monkeypatch.setattr(core.qa_agent, "_QA_STATE_FILE", qa_state)

    test_log = QuickLog(path=tmp_path / "quick_log.json")
    await test_log.append({"type": "TOOL", "name": "nmap", "ts": "2026-01-01T00:00:00+00:00"})
    monkeypatch.setattr(core.quick_log, "quick_log", test_log)

    mock_graph = MagicMock()
    daemon = QADaemon()
    monkeypatch.setattr(daemon, "_get_graph", lambda: mock_graph)

    mtime_before = qa_state.stat().st_mtime
    with patch("asyncio.to_thread", new=AsyncMock(return_value={"alerts": [alert]})):
        await daemon._cycle()

    # File must NOT have been rewritten (mtime unchanged)
    assert qa_state.stat().st_mtime == mtime_before


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
# _build_context_summary()
# ---------------------------------------------------------------------------

def test_build_context_summary_no_previous_alerts():
    result = _build_context_summary("summary text", [])
    assert result == "summary text"


def test_build_context_summary_with_previous_alerts():
    alerts = [{"urgency": "high", "message": "alert one"}, {"urgency": "medium", "message": "alert two"}]
    result = _build_context_summary("summary text", alerts)
    assert "Previously flagged (last cycle):" in result
    assert "[high] alert one" in result
    assert "[medium] alert two" in result


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
    import sys
    # Patch both langgraph and langchain_core as missing
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
        # Stop after second iteration
        raise asyncio.CancelledError()

    daemon = QADaemon()
    monkeypatch.setattr(daemon, "_cycle", fake_cycle)

    with patch("asyncio.sleep", new=AsyncMock()):
        try:
            await daemon.run(interval_s=0)
        except asyncio.CancelledError:
            pass

    assert call_count == 2
