"""
Targeted test for the new terminal-status branch in
mcp_server.session_tools._do_recovery — when the scan reached complete /
incomplete_with_unresolved_blockers / limit_reached, recovery returns a
SCAN_COMPLETED brief instead of "no_session, start a new one".
"""
import json
import pytest

import core.session as scan_session
from mcp_server.session_tools import _do_recovery


@pytest.fixture(autouse=True)
def _sandbox(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
    scan_session._current = None
    yield
    scan_session._current = None


@pytest.mark.parametrize("terminal", [
    "complete",
    "incomplete_with_unresolved_blockers",
    "limit_reached",
])
def test_returns_scan_completed_for_terminal_status(terminal):
    scan_session.start("http://x.test")
    scan_session._current["status"] = terminal
    scan_session._current["finished"] = "2026-06-07T00:00:00+00:00"
    scan_session._current["notes"] = "human note"
    out = _do_recovery()
    parsed = json.loads(out)
    assert parsed["status"] == "SCAN_COMPLETED"
    assert parsed["scan_status"] == terminal
    assert parsed["target"] == "http://x.test"
    assert parsed["finished"] == "2026-06-07T00:00:00+00:00"
    assert parsed["notes"] == "human note"
    # Crucially: no EXECUTE_NOW for starting a new scan
    assert "EXECUTE_NOW" not in parsed


def test_returns_no_session_when_no_session_started():
    out = _do_recovery()
    parsed = json.loads(out)
    assert parsed["status"] == "no_session"
    assert "EXECUTE_NOW" in parsed


def test_returns_no_session_when_status_is_unfamiliar():
    scan_session.start("http://x.test")
    scan_session._current["status"] = "paused_unknown_state"
    out = _do_recovery()
    parsed = json.loads(out)
    # Non-running, non-terminal status currently falls back to the
    # no_session "start a new one" path.
    assert parsed["status"] == "no_session"
