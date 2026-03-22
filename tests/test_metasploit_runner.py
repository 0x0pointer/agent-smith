"""
Tests for tools.metasploit_runner — container lifecycle and command execution.

All tests mock asyncio.create_subprocess_exec so no Docker daemon is needed.
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from tools.metasploit_runner import ensure_running, stop, exec_command, container_running, image_exists, _host_rewrite


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_proc(stdout: bytes = b"", stderr: bytes = b"", returncode: int = 0):
    proc = MagicMock()
    proc.returncode = returncode
    proc.communicate = AsyncMock(return_value=(stdout, stderr))
    proc.wait = AsyncMock(return_value=returncode)
    proc.kill = MagicMock()
    return proc


# ---------------------------------------------------------------------------
# _host_rewrite tests
# ---------------------------------------------------------------------------

def test_host_rewrite_replaces_localhost():
    assert "host.docker.internal" in _host_rewrite("curl http://localhost:8080")


def test_host_rewrite_replaces_127():
    assert "host.docker.internal" in _host_rewrite("curl http://127.0.0.1:8080")


def test_host_rewrite_leaves_other_hosts():
    assert _host_rewrite("curl http://example.com") == "curl http://example.com"


# ---------------------------------------------------------------------------
# image_exists tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_image_exists_returns_true():
    proc = _make_proc(returncode=0)
    with patch("tools.metasploit_runner.asyncio.create_subprocess_exec", return_value=proc):
        assert await image_exists() is True


@pytest.mark.asyncio
async def test_image_exists_returns_false():
    proc = _make_proc(returncode=1)
    with patch("tools.metasploit_runner.asyncio.create_subprocess_exec", return_value=proc):
        assert await image_exists() is False


# ---------------------------------------------------------------------------
# container_running tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_container_running_true():
    proc = _make_proc(stdout=b"true")
    with patch("tools.metasploit_runner.asyncio.create_subprocess_exec", return_value=proc):
        assert await container_running() is True


@pytest.mark.asyncio
async def test_container_running_false():
    proc = _make_proc(stdout=b"false")
    with patch("tools.metasploit_runner.asyncio.create_subprocess_exec", return_value=proc):
        assert await container_running() is False


@pytest.mark.asyncio
async def test_container_running_empty():
    proc = _make_proc(stdout=b"")
    with patch("tools.metasploit_runner.asyncio.create_subprocess_exec", return_value=proc):
        assert await container_running() is False


# ---------------------------------------------------------------------------
# stop tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_stop_success():
    proc = _make_proc(returncode=0)
    with patch("tools.metasploit_runner.asyncio.create_subprocess_exec", return_value=proc):
        result = await stop()
    assert "stopped" in result.lower()


@pytest.mark.asyncio
async def test_stop_failure():
    proc = _make_proc(returncode=1, stderr=b"no such container")
    with patch("tools.metasploit_runner.asyncio.create_subprocess_exec", return_value=proc):
        result = await stop()
    assert "no such container" in result


# ---------------------------------------------------------------------------
# ensure_running tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ensure_running_already_running():
    with patch("tools.metasploit_runner.container_running", new_callable=AsyncMock, return_value=True):
        ok, msg = await ensure_running()
    assert ok is True
    assert "already running" in msg


@pytest.mark.asyncio
async def test_ensure_running_image_missing():
    with patch("tools.metasploit_runner.container_running", new_callable=AsyncMock, return_value=False), \
         patch("tools.metasploit_runner.image_exists", new_callable=AsyncMock, return_value=False):
        ok, msg = await ensure_running()
    assert ok is False
    assert "not found" in msg


@pytest.mark.asyncio
async def test_ensure_running_docker_run_fails():
    run_proc = _make_proc(returncode=1, stderr=b"port already in use")
    with patch("tools.metasploit_runner.container_running", new_callable=AsyncMock, return_value=False), \
         patch("tools.metasploit_runner.image_exists", new_callable=AsyncMock, return_value=True), \
         patch("tools.metasploit_runner.asyncio.create_subprocess_exec", return_value=run_proc):
        ok, msg = await ensure_running()
    assert ok is False
    assert "port already in use" in msg


# ---------------------------------------------------------------------------
# exec_command tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_exec_command_returns_output():
    with patch("tools.metasploit_runner.ensure_running", new_callable=AsyncMock, return_value=(True, "started")):
        mock_session = MagicMock()
        mock_resp = AsyncMock()
        mock_resp.json = AsyncMock(return_value={"stdout": "uid=0(root)", "stderr": "", "timed_out": False})
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)
        mock_session.post = MagicMock(return_value=mock_resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await exec_command("whoami")
    assert "uid=0(root)" in result


@pytest.mark.asyncio
async def test_exec_command_returns_error_when_not_running():
    with patch("tools.metasploit_runner.ensure_running", new_callable=AsyncMock, return_value=(False, "image not found")):
        result = await exec_command("whoami")
    assert "image not found" in result


@pytest.mark.asyncio
async def test_exec_command_timed_out_prefix():
    with patch("tools.metasploit_runner.ensure_running", new_callable=AsyncMock, return_value=(True, "started")):
        mock_session = MagicMock()
        mock_resp = AsyncMock()
        mock_resp.json = AsyncMock(return_value={"stdout": "partial output", "stderr": "", "timed_out": True})
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)
        mock_session.post = MagicMock(return_value=mock_resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await exec_command("long-running-command")
    assert "timed out" in result.lower()
    assert "partial output" in result


@pytest.mark.asyncio
async def test_exec_command_no_output():
    with patch("tools.metasploit_runner.ensure_running", new_callable=AsyncMock, return_value=(True, "started")):
        mock_session = MagicMock()
        mock_resp = AsyncMock()
        mock_resp.json = AsyncMock(return_value={"stdout": "", "stderr": "", "timed_out": False})
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)
        mock_session.post = MagicMock(return_value=mock_resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await exec_command("true")
    assert result == "[no output]"


@pytest.mark.asyncio
async def test_exec_command_api_error():
    with patch("tools.metasploit_runner.ensure_running", new_callable=AsyncMock, return_value=(True, "started")):
        with patch("aiohttp.ClientSession", side_effect=ConnectionError("refused")):
            result = await exec_command("whoami")
    assert "Error" in result
    assert "ConnectionError" in result
