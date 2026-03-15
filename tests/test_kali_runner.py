"""
Tests for tools.kali_runner — host rewrite and exec_command behaviour.

Container lifecycle (ensure_running / stop) require Docker, so they are tested
only for their pure logic. The HTTP exec path is mocked via aiohttp.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import tools.kali_runner as kr


# ---------------------------------------------------------------------------
# _host_rewrite (pure function — no mocking needed)
# ---------------------------------------------------------------------------

def test_host_rewrite_replaces_localhost():
    result = kr._host_rewrite("curl http://localhost:3000/api")
    assert "localhost" not in result
    assert "host.docker.internal" in result


def test_host_rewrite_replaces_127_0_0_1():
    result = kr._host_rewrite("curl http://127.0.0.1:8080/login")
    assert "127.0.0.1" not in result
    assert "host.docker.internal" in result


def test_host_rewrite_leaves_other_hosts_unchanged():
    cmd = "curl http://192.168.1.10/path"
    assert kr._host_rewrite(cmd) == cmd


def test_host_rewrite_handles_both_in_same_command():
    cmd = "curl http://localhost/a && wget http://127.0.0.1/b"
    result = kr._host_rewrite(cmd)
    assert "localhost" not in result
    assert "127.0.0.1" not in result


def test_host_rewrite_empty_string():
    assert kr._host_rewrite("") == ""


# ---------------------------------------------------------------------------
# exec_command — mocked ensure_running + aiohttp
# ---------------------------------------------------------------------------

def _mock_resp(stdout="output", stderr="", timed_out=False):
    resp = AsyncMock()
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    resp.status = 200
    resp.json = AsyncMock(return_value={
        "stdout": stdout,
        "stderr": stderr,
        "timed_out": timed_out,
    })
    return resp


def _mock_session(resp):
    session = MagicMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    post_ctx = AsyncMock()
    post_ctx.__aenter__ = AsyncMock(return_value=resp)
    post_ctx.__aexit__ = AsyncMock(return_value=False)
    session.post = MagicMock(return_value=post_ctx)
    return session


@pytest.mark.asyncio
async def test_exec_command_returns_stdout():
    resp = _mock_resp(stdout="uid=0(root)")
    session = _mock_session(resp)
    import aiohttp
    with patch.object(kr, "ensure_running", AsyncMock(return_value=(True, "running"))), \
         patch.object(aiohttp, "ClientSession", return_value=session):
        result = await kr.exec_command("id")
    assert "uid=0(root)" in result


@pytest.mark.asyncio
async def test_exec_command_combines_stdout_and_stderr():
    resp = _mock_resp(stdout="out", stderr="err")
    session = _mock_session(resp)
    import aiohttp
    with patch.object(kr, "ensure_running", AsyncMock(return_value=(True, "running"))), \
         patch.object(aiohttp, "ClientSession", return_value=session):
        result = await kr.exec_command("cmd")
    assert "out" in result
    assert "err" in result


@pytest.mark.asyncio
async def test_exec_command_timed_out_prefixes_output():
    resp = _mock_resp(stdout="partial", timed_out=True)
    session = _mock_session(resp)
    import aiohttp
    with patch.object(kr, "ensure_running", AsyncMock(return_value=(True, "running"))), \
         patch.object(aiohttp, "ClientSession", return_value=session):
        result = await kr.exec_command("slow-command")
    assert "partial" in result.lower() or "timed out" in result.lower()


@pytest.mark.asyncio
async def test_exec_command_returns_error_when_ensure_running_fails():
    with patch.object(kr, "ensure_running", AsyncMock(return_value=(False, "image not found"))):
        result = await kr.exec_command("id")
    assert "image not found" in result


@pytest.mark.asyncio
async def test_exec_command_no_output_returns_no_output_string():
    resp = _mock_resp(stdout="", stderr="")
    session = _mock_session(resp)
    import aiohttp
    with patch.object(kr, "ensure_running", AsyncMock(return_value=(True, "running"))), \
         patch.object(aiohttp, "ClientSession", return_value=session):
        result = await kr.exec_command("true")
    assert result == "[no output]"


@pytest.mark.asyncio
async def test_exec_command_rewrites_localhost_before_sending():
    resp = _mock_resp(stdout="ok")
    session = _mock_session(resp)
    import aiohttp
    with patch.object(kr, "ensure_running", AsyncMock(return_value=(True, "running"))), \
         patch.object(aiohttp, "ClientSession", return_value=session):
        await kr.exec_command("curl http://localhost:3000")
    # Verify the posted command had the rewritten host
    posted_json = session.post.call_args[1]["json"]
    assert "localhost" not in posted_json["command"]
    assert "host.docker.internal" in posted_json["command"]


@pytest.mark.asyncio
async def test_exec_command_handles_aiohttp_exception():
    import aiohttp
    with patch.object(kr, "ensure_running", AsyncMock(return_value=(True, "running"))), \
         patch.object(aiohttp, "ClientSession", side_effect=Exception("conn refused")):
        result = await kr.exec_command("id")
    assert "Error" in result or "conn refused" in result
