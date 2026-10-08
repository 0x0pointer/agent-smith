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
async def test_kali_passes_output_to_wrap():
    """kali() passes raw output to wrap() and returns its result."""
    long_output = "x" * 20_000

    with patch("mcp_server.kali_tools.scan_session") as mock_session, \
         patch("mcp_server.kali_tools.cost_tracker") as mock_cost, \
         patch("mcp_server.kali_tools.log"), \
         patch("mcp_server.scan_engine.wrap", return_value="wrapped") as mock_wrap, \
         patch("tools.kali_runner.exec_command", new_callable=AsyncMock, return_value=long_output):

        mock_session.check_limits.return_value = None
        mock_cost.start.return_value = "cid"
        mock_cost.get_summary.return_value = {}

        result = await kali("cat /etc/passwd")

    mock_wrap.assert_called_once()
    assert result == "wrapped"


@pytest.mark.asyncio
async def test_kali_returns_output_unchanged_when_short():
    """Short output is passed through wrap() and returned."""
    short_output = "uid=0(root) gid=0(root)\n"

    with patch("mcp_server.kali_tools.scan_session") as mock_session, \
         patch("mcp_server.kali_tools.cost_tracker") as mock_cost, \
         patch("mcp_server.kali_tools.log"), \
         patch("mcp_server.scan_engine.wrap", side_effect=lambda tool, raw, ctx: raw), \
         patch("tools.kali_runner.exec_command", new_callable=AsyncMock, return_value=short_output):

        mock_session.check_limits.return_value = None
        mock_cost.start.return_value = "cid"
        mock_cost.get_summary.return_value = {}

        result = await kali("id")

    assert result == short_output


# ---------------------------------------------------------------------------
# #253 / #254 — files=, background=, job_id=
# ---------------------------------------------------------------------------

def _patched(**runner):
    from contextlib import ExitStack
    st = ExitStack()
    ms = st.enter_context(patch("mcp_server.kali_tools.scan_session"))
    mc = st.enter_context(patch("mcp_server.kali_tools.cost_tracker"))
    st.enter_context(patch("mcp_server.kali_tools.log"))
    ms.check_limits.return_value = None
    mc.get_summary.return_value = {}
    mc.start.return_value = "cid"
    for name, m in runner.items():
        st.enter_context(patch(f"tools.kali_runner.{name}", m))
    return st


@pytest.mark.asyncio
async def test_kali_background_returns_job_id():
    ex = AsyncMock(return_value="started job x")
    with _patched(exec_command=ex):
        out = await kali("python3 long.py", background=True)
    assert "job_id=" in out and "nohup" in ex.call_args.args[0]


@pytest.mark.asyncio
async def test_kali_poll_job_and_reject_bad_id():
    ex = AsyncMock(return_value="__JOB_STATUS__ running\n...")
    with _patched(exec_command=ex):
        assert "running" in await kali(job_id="abcdef123456")
        assert "invalid job_id" in await kali(job_id="../x; rm -rf /")


@pytest.mark.asyncio
async def test_kali_stages_files_before_command(monkeypatch, tmp_path):
    import mcp_server.scan_engine.artifacts as arts
    monkeypatch.setattr(arts, "_ARTIFACTS_DIR", tmp_path)
    aid = arts.store_artifact("transform", "PAYLOAD")
    put = AsyncMock(return_value=None)
    ex = AsyncMock(return_value="ok")
    with _patched(put_file=put, exec_command=ex), \
         patch("mcp_server.scan_engine.wrap", return_value="wrapped"):
        await kali("cat /tmp/a /tmp/b", files={"/tmp/a": aid, "/tmp/b": {"content": "X"}})
    assert [c.args for c in put.call_args_list] == [("/tmp/a", b"PAYLOAD"), ("/tmp/b", b"X")]
    ex.assert_awaited_once()


@pytest.mark.asyncio
async def test_kali_missing_file_artifact_aborts(monkeypatch, tmp_path):
    import mcp_server.scan_engine.artifacts as arts
    monkeypatch.setattr(arts, "_ARTIFACTS_DIR", tmp_path)
    ex = AsyncMock(return_value="ok")
    with _patched(exec_command=ex):
        out = await kali("cat /tmp/a", files={"/tmp/a": "nope_1_2"})
    assert "Error staging files" in out and not ex.called


@pytest.mark.asyncio
async def test_kali_whole_command_timeout_note_not_lead():
    ex = AsyncMock(return_value="[partial — command timed out]\nsome")
    with _patched(exec_command=ex), patch("mcp_server.scan_engine.wrap", side_effect=lambda k, raw, ctx: raw):
        out = await kali("python3 batch.py", timeout=900)
    assert "exceeded timeout=900s" in out and "TIMEOUT SIGNAL" not in out
