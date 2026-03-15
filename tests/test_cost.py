"""
Tests for core.cost — token estimation and weighted cost tracking.
"""
import json
import pytest
import core.cost


def test_start_returns_uuid_string():
    call_id = core.cost.start("nmap")
    assert isinstance(call_id, str)
    assert len(call_id) == 36  # UUID4 format


def test_start_adds_running_entry():
    core.cost.start("httpx")
    summary = core.cost.get_summary()
    running = [c for c in summary["breakdown"] if c["status"] == "running"]
    assert len(running) == 1
    assert running[0]["tool"] == "httpx"


def test_finish_updates_status_to_done():
    call_id = core.cost.start("nuclei")
    core.cost.finish(call_id, "output text")
    summary = core.cost.get_summary()
    done = [c for c in summary["breakdown"] if c["id"] == call_id]
    assert done[0]["status"] == "done"


def test_finish_records_char_count():
    call_id = core.cost.start("nmap")
    output = "x" * 400
    core.cost.finish(call_id, output)
    summary = core.cost.get_summary()
    entry = next(c for c in summary["breakdown"] if c["id"] == call_id)
    assert entry["chars"] == 400


def test_finish_minimum_one_token_for_empty_output():
    call_id = core.cost.start("nmap")
    core.cost.finish(call_id, "")
    summary = core.cost.get_summary()
    entry = next(c for c in summary["breakdown"] if c["id"] == call_id)
    assert entry["tokens"] == 1


def test_finish_token_count_is_chars_div_4():
    call_id = core.cost.start("nmap")
    core.cost.finish(call_id, "x" * 400)
    summary = core.cost.get_summary()
    entry = next(c for c in summary["breakdown"] if c["id"] == call_id)
    assert entry["tokens"] == 100  # 400 / 4


def test_summary_counts_running_and_done():
    id1 = core.cost.start("tool_a")
    id2 = core.cost.start("tool_b")
    core.cost.finish(id1, "result")
    summary = core.cost.get_summary()
    assert summary["tool_calls_total"] == 2
    assert summary["tool_calls_done"] == 1
    assert summary["tool_calls_running"] == 1


def test_weighted_tokens_single_call():
    """Single call: weight = tokens * 1 (n-0 where n=1)."""
    call_id = core.cost.start("nmap")
    core.cost.finish(call_id, "x" * 400)  # 100 tokens
    summary = core.cost.get_summary()
    assert summary["total_weighted_tokens"] == 100  # 100 * (1 - 0) = 100


def test_weighted_tokens_two_calls():
    """
    Two calls: first call is re-read twice (weight 2), second once (weight 1).
    total_weighted = 100 * 2 + 100 * 1 = 300
    """
    id1 = core.cost.start("tool_a")
    core.cost.finish(id1, "x" * 400)   # 100 tokens
    id2 = core.cost.start("tool_b")
    core.cost.finish(id2, "x" * 400)   # 100 tokens
    summary = core.cost.get_summary()
    assert summary["total_weighted_tokens"] == 300


def test_est_cost_usd_is_correct():
    """est_cost_usd = weighted_tokens / 1_000_000 * 3.00"""
    call_id = core.cost.start("nmap")
    core.cost.finish(call_id, "x" * 1_000_000)  # 250_000 tokens
    summary = core.cost.get_summary()
    expected = round(250_000 / 1_000_000 * 3.00, 6)
    assert summary["est_cost_usd"] == expected


def test_flush_writes_valid_json(tmp_path, monkeypatch):
    monkeypatch.setattr(core.cost, "_COST_FILE", tmp_path / "cost.json")
    call_id = core.cost.start("nmap")
    core.cost.finish(call_id, "output")
    data = json.loads((tmp_path / "cost.json").read_text())
    assert "breakdown" in data
    assert data["tool_calls_total"] == 1


def test_get_summary_includes_model_info():
    summary = core.cost.get_summary()
    assert summary["model"] == "claude-sonnet-4-6"
    assert summary["input_price_per_M"] == 3.00


def test_finish_unknown_id_is_noop():
    """Finishing a non-existent call_id should not raise."""
    core.cost.start("nmap")
    core.cost.finish("nonexistent-id-xxxx", "output")
    summary = core.cost.get_summary()
    assert summary["tool_calls_done"] == 0


def test_multiple_tools_total_raw_tokens():
    id1 = core.cost.start("a")
    id2 = core.cost.start("b")
    core.cost.finish(id1, "x" * 40)   # 10 tokens
    core.cost.finish(id2, "x" * 80)   # 20 tokens
    summary = core.cost.get_summary()
    assert summary["total_output_tokens"] == 30
