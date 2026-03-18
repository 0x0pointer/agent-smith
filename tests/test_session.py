"""
Tests for core.session — scan lifecycle, presets, and hard limit enforcement.
"""
import time
import pytest
import core.session


# ---------------------------------------------------------------------------
# start()
# ---------------------------------------------------------------------------

def test_start_returns_dict_with_target():
    sess = core.session.start("example.com")
    assert sess["target"] == "example.com"


def test_start_defaults_to_standard_depth():
    sess = core.session.start("example.com")
    assert sess["depth"] == "standard"


def test_start_sets_status_running():
    sess = core.session.start("example.com")
    assert sess["status"] == "running"


def test_start_applies_preset_limits():
    sess = core.session.start("example.com", depth="recon")
    assert sess["limits"]["max_cost_usd"] == pytest.approx(0.10)
    assert sess["limits"]["max_time_minutes"] == 15
    assert sess["limits"]["max_tool_calls"] == 10


def test_start_thorough_preset():
    sess = core.session.start("example.com", depth="thorough")
    assert sess["limits"]["max_cost_usd"] == pytest.approx(2.00)
    assert sess["limits"]["max_tool_calls"] == 0  # unlimited


def test_start_custom_limits_override_preset():
    sess = core.session.start(
        "example.com", depth="recon",
        max_cost_usd=5.0, max_time_minutes=999, max_tool_calls=100
    )
    assert sess["limits"]["max_cost_usd"] == pytest.approx(5.0)
    assert sess["limits"]["max_time_minutes"] == 999
    assert sess["limits"]["max_tool_calls"] == 100


def test_start_scope_defaults_to_target():
    sess = core.session.start("example.com")
    assert "example.com" in sess["scope"]


def test_start_custom_scope():
    sess = core.session.start("example.com", scope=["api.example.com"])
    assert sess["scope"] == ["api.example.com"]


def test_start_out_of_scope_empty_by_default():
    sess = core.session.start("example.com")
    assert sess["out_of_scope"] == []


def test_start_persists_to_get():
    core.session.start("example.com")
    assert core.session.get() is not None
    assert core.session.get()["target"] == "example.com"


def test_start_writes_session_file(tmp_path, monkeypatch):
    import json
    monkeypatch.setattr(core.session, "_SESSION_FILE", tmp_path / "session.json")
    core.session.start("example.com")
    data = json.loads((tmp_path / "session.json").read_text())
    assert data["target"] == "example.com"


def test_start_unknown_depth_falls_back_to_standard():
    sess = core.session.start("example.com", depth="nonexistent")
    assert sess["limits"]["max_tool_calls"] == 25


# ---------------------------------------------------------------------------
# get()
# ---------------------------------------------------------------------------

def test_get_returns_none_before_start():
    assert core.session.get() is None


# ---------------------------------------------------------------------------
# check_limits()
# ---------------------------------------------------------------------------

def _fake_cost(usd=0.0, calls=0):
    return {"est_cost_usd": usd, "tool_calls_total": calls}


def test_check_limits_none_when_within_budget():
    core.session.start("example.com", depth="recon")
    assert core.session.check_limits(_fake_cost(usd=0.05, calls=5)) is None


def test_check_limits_returns_none_before_session_start():
    assert core.session.check_limits(_fake_cost()) is None


def test_check_limits_cost_exceeded_returns_stop_message():
    core.session.start("example.com", depth="recon")
    msg = core.session.check_limits(_fake_cost(usd=0.11))
    assert msg is not None
    assert "COST LIMIT" in msg


def test_check_limits_call_count_exceeded():
    core.session.start("example.com", depth="recon")
    msg = core.session.check_limits(_fake_cost(calls=10))
    assert msg is not None
    assert "CALL LIMIT" in msg


def test_check_limits_sets_status_limit_reached():
    core.session.start("example.com", depth="recon")
    core.session.check_limits(_fake_cost(usd=0.99))
    assert core.session.get()["status"] == "limit_reached"


def test_check_limits_no_further_checks_after_limit():
    """After limit is reached the session is no longer 'running', so subsequent
    calls to check_limits should return None."""
    core.session.start("example.com", depth="recon")
    core.session.check_limits(_fake_cost(usd=0.99))
    second_check = core.session.check_limits(_fake_cost(usd=0.99))
    assert second_check is None


# ---------------------------------------------------------------------------
# complete()
# ---------------------------------------------------------------------------

def test_complete_sets_status_complete():
    core.session.start("example.com")
    core.session.complete("all done")
    assert core.session.get()["status"] == "complete"


def test_complete_stores_notes():
    core.session.start("example.com")
    core.session.complete("found 3 vulns")
    assert core.session.get()["notes"] == "found 3 vulns"


def test_complete_sets_finished_timestamp():
    core.session.start("example.com")
    core.session.complete()
    assert core.session.get()["finished"] is not None


def test_complete_returns_empty_dict_when_no_session():
    result = core.session.complete()
    assert result == {}


# ---------------------------------------------------------------------------
# remaining()
# ---------------------------------------------------------------------------

def test_remaining_returns_empty_when_no_session():
    assert core.session.remaining(_fake_cost()) == {}


def test_remaining_calls_remaining_decrements():
    core.session.start("example.com", depth="recon", max_tool_calls=10)
    r = core.session.remaining(_fake_cost(calls=3))
    assert r["calls_remaining"] == 7


def test_remaining_cost_remaining():
    core.session.start("example.com", depth="recon", max_cost_usd=0.10)
    r = core.session.remaining(_fake_cost(usd=0.04))
    assert abs(r["cost_remaining_usd"] - 0.06) < 0.001


def test_remaining_never_goes_negative():
    core.session.start("example.com", depth="recon", max_tool_calls=5)
    r = core.session.remaining(_fake_cost(calls=100))
    assert r["calls_remaining"] == 0


# ---------------------------------------------------------------------------
# Unlimited tool calls (max_tool_calls=0)
# ---------------------------------------------------------------------------

def test_check_limits_unlimited_calls_never_triggers():
    core.session.start("example.com", depth="thorough")
    msg = core.session.check_limits(_fake_cost(calls=999))
    assert msg is None  # cost/time still within budget


def test_remaining_unlimited_calls_returns_minus_one():
    core.session.start("example.com", depth="thorough")
    r = core.session.remaining(_fake_cost(calls=50))
    assert r["calls_remaining"] == -1
    assert r["calls_pct"] == 0


# ---------------------------------------------------------------------------
# Counter reset on new session
# ---------------------------------------------------------------------------

def test_start_resets_cost_tracker():
    """Starting a new session should zero out cost tracker counters."""
    import core.cost as cost_tracker
    # Simulate a previous session's calls
    cid = cost_tracker.start("nmap")
    cost_tracker.finish(cid, "x" * 4000)
    assert cost_tracker.get_summary()["tool_calls_total"] == 1

    # Starting a new session should reset
    core.session.start("new-target.com")
    assert cost_tracker.get_summary()["tool_calls_total"] == 0
    assert cost_tracker.get_summary()["est_cost_usd"] == 0
