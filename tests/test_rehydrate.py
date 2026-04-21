"""
Tests for mcp_server._app._rehydrate_tools — repopulates _session_tools_called
from session.json after an MCP process restart.
"""
import json
import pytest
from unittest.mock import mock_open, patch
import mcp_server._app as _app


def _patch_session_file(content: str | None):
    """Return a context-manager pair for patching the session file read."""
    if content is None:
        return (
            patch("os.path.isfile", return_value=False),
            None,
        )
    return (
        patch("os.path.isfile", return_value=True),
        patch("builtins.open", mock_open(read_data=content)),
    )


# ---------------------------------------------------------------------------
# _rehydrate_tools
# ---------------------------------------------------------------------------

def test_rehydrate_no_file_leaves_set_unchanged():
    """When session.json does not exist nothing is added."""
    with patch("os.path.isfile", return_value=False):
        _app._session_tools_called.clear()
        _app._rehydrate_tools()
    assert _app._session_tools_called == set()


def test_rehydrate_running_session_adds_tools():
    """Tools from a running session are added to _session_tools_called."""
    data = json.dumps({
        "status": "running",
        "tools_called": ["nmap", "httpx", "nuclei"],
    })
    with patch("os.path.isfile", return_value=True), \
         patch("builtins.open", mock_open(read_data=data)):
        _app._session_tools_called.clear()
        _app._rehydrate_tools()
    assert {"nmap", "httpx", "nuclei"} <= _app._session_tools_called


def test_rehydrate_completed_session_does_not_add_tools():
    """Completed sessions are ignored — only running sessions are rehydrated."""
    data = json.dumps({
        "status": "complete",
        "tools_called": ["nmap"],
    })
    with patch("os.path.isfile", return_value=True), \
         patch("builtins.open", mock_open(read_data=data)):
        _app._session_tools_called.clear()
        _app._rehydrate_tools()
    assert "nmap" not in _app._session_tools_called


def test_rehydrate_empty_tools_called_is_noop():
    """Running session with empty tools_called leaves set unchanged."""
    data = json.dumps({"status": "running", "tools_called": []})
    with patch("os.path.isfile", return_value=True), \
         patch("builtins.open", mock_open(read_data=data)):
        _app._session_tools_called.clear()
        _app._rehydrate_tools()
    assert _app._session_tools_called == set()


def test_rehydrate_corrupt_json_is_noop():
    """Corrupt JSON is silently ignored — existing set is unchanged."""
    with patch("os.path.isfile", return_value=True), \
         patch("builtins.open", mock_open(read_data="not json {{{")):
        _app._session_tools_called.clear()
        _app._rehydrate_tools()
    assert _app._session_tools_called == set()


def test_rehydrate_does_not_clear_existing_entries():
    """Pre-existing in-memory tools are not removed by rehydration."""
    data = json.dumps({"status": "running", "tools_called": ["nuclei"]})
    with patch("os.path.isfile", return_value=True), \
         patch("builtins.open", mock_open(read_data=data)):
        _app._session_tools_called.clear()
        _app._session_tools_called.add("ffuf")  # already tracked in-memory
        _app._rehydrate_tools()
    assert "ffuf" in _app._session_tools_called
    assert "nuclei" in _app._session_tools_called


def test_rehydrate_deduplicates_tools():
    """Tools already in the set are not duplicated (set semantics)."""
    data = json.dumps({"status": "running", "tools_called": ["nmap", "nmap", "httpx"]})
    with patch("os.path.isfile", return_value=True), \
         patch("builtins.open", mock_open(read_data=data)):
        _app._session_tools_called.clear()
        _app._session_tools_called.add("nmap")
        _app._rehydrate_tools()
    # set — no duplicates
    assert len([t for t in _app._session_tools_called if t == "nmap"]) == 1
    assert "httpx" in _app._session_tools_called
