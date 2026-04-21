"""
Tests for mcp_server.kali_tools — _record() call and session limit enforcement.
"""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import mcp_server._app as _app
from mcp_server.kali_tools import kali


def _make_session_running():
    """Return a minimal session dict that passes check_limits."""
    return {
        "status": "running",
        "limits": {"max_cost_usd": 100, "max_time_minutes": 120, "max_tool_calls": 0},
        "started": "2025-01-01T00:00:00+00:00",
    }


# ---------------------------------------------------------------------------
# _record("kali") is called on every successful invocation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_kali_records_tool_name():
    """kali() must call _record('kali') so the tool is tracked in session state."""
    _app._session_tools_called.clear()

    with patch("mcp_server.kali_tools.scan_session") as mock_session, \
         patch("mcp_server.kali_tools.cost_tracker") as mock_cost, \
         patch("mcp_server.kali_tools.log"), \
         patch("tools.kali_runner.exec_command", new_callable=AsyncMock, return_value="output"):

        mock_session.check_limits.return_value = None  # no limit hit
        mock_cost.start.return_value = "call-id"
        mock_cost.get_summary.return_value = {}

        await kali("id")

    assert "kali" in _app._session_tools_called


@pytest.mark.asyncio
async def test_kali_does_not_record_when_limit_hit():
    """_record is NOT called when check_limits returns a stop message."""
    _app._session_tools_called.clear()

    with patch("mcp_server.kali_tools.scan_session") as mock_session, \
         patch("mcp_server.kali_tools.cost_tracker") as mock_cost, \
         patch("mcp_server.kali_tools.log"):

        mock_session.check_limits.return_value = "LIMIT HIT: cost exceeded"
        mock_cost.get_summary.return_value = {}

        result = await kali("id")

    assert result == "LIMIT HIT: cost exceeded"
    assert "kali" not in _app._session_tools_called


# ---------------------------------------------------------------------------
# Output clipping
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_kali_clips_long_output():
    """Output longer than 8000 chars is clipped."""
    long_output = "x" * 20_000

    with patch("mcp_server.kali_tools.scan_session") as mock_session, \
         patch("mcp_server.kali_tools.cost_tracker") as mock_cost, \
         patch("mcp_server.kali_tools.log"), \
         patch("tools.kali_runner.exec_command", new_callable=AsyncMock, return_value=long_output):

        mock_session.check_limits.return_value = None
        mock_cost.start.return_value = "cid"
        mock_cost.get_summary.return_value = {}

        result = await kali("cat /etc/passwd")

    assert len(result) < len(long_output)
    assert "clipped" in result


@pytest.mark.asyncio
async def test_kali_returns_output_unchanged_when_short():
    """Short output is returned verbatim."""
    short_output = "uid=0(root) gid=0(root)\n"

    with patch("mcp_server.kali_tools.scan_session") as mock_session, \
         patch("mcp_server.kali_tools.cost_tracker") as mock_cost, \
         patch("mcp_server.kali_tools.log"), \
         patch("tools.kali_runner.exec_command", new_callable=AsyncMock, return_value=short_output):

        mock_session.check_limits.return_value = None
        mock_cost.start.return_value = "cid"
        mock_cost.get_summary.return_value = {}

        result = await kali("id")

    assert result == short_output
