"""
Tests for tools.docker_runner.run_container.

All tests mock asyncio.create_subprocess_exec so no Docker daemon is needed.
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from tools.docker_runner import run_container


def _make_proc(stdout: bytes = b"", stderr: bytes = b"", returncode: int = 0):
    """Return a mock Process whose communicate() returns (stdout, stderr)."""
    proc = MagicMock()
    proc.returncode = returncode
    proc.communicate = AsyncMock(return_value=(stdout, stderr))
    proc.kill = MagicMock()
    return proc


@pytest.mark.asyncio
async def test_returns_stdout_string():
    proc = _make_proc(stdout=b"open port 80")
    with patch("tools.docker_runner.asyncio.create_subprocess_exec", return_value=proc):
        stdout, _, _ = await run_container("nmap:latest", ["--help"])
    assert stdout == "open port 80"


@pytest.mark.asyncio
async def test_returns_stderr_string():
    proc = _make_proc(stderr=b"warning: something")
    with patch("tools.docker_runner.asyncio.create_subprocess_exec", return_value=proc):
        _, stderr, _ = await run_container("nmap:latest", [])
    assert stderr == "warning: something"


@pytest.mark.asyncio
async def test_returns_exit_code():
    proc = _make_proc(returncode=1)
    with patch("tools.docker_runner.asyncio.create_subprocess_exec", return_value=proc):
        _, _, code = await run_container("nmap:latest", [])
    assert code == 1


@pytest.mark.asyncio
async def test_exit_code_none_coerced_to_zero():
    proc = _make_proc()
    proc.returncode = None
    with patch("tools.docker_runner.asyncio.create_subprocess_exec", return_value=proc):
        _, _, code = await run_container("nmap:latest", [])
    assert code == 0


@pytest.mark.asyncio
async def test_docker_command_includes_rm_flag():
    proc = _make_proc()
    with patch("tools.docker_runner.asyncio.create_subprocess_exec", return_value=proc) as mock_exec:
        await run_container("nmap:latest", [])
    cmd = mock_exec.call_args[0]
    assert "--rm" in cmd


@pytest.mark.asyncio
async def test_docker_command_includes_memory_limit():
    proc = _make_proc()
    with patch("tools.docker_runner.asyncio.create_subprocess_exec", return_value=proc) as mock_exec:
        await run_container("nmap:latest", [])
    cmd = mock_exec.call_args[0]
    assert "--memory=2g" in cmd


@pytest.mark.asyncio
async def test_docker_command_includes_cpu_limit():
    proc = _make_proc()
    with patch("tools.docker_runner.asyncio.create_subprocess_exec", return_value=proc) as mock_exec:
        await run_container("nmap:latest", [])
    cmd = mock_exec.call_args[0]
    assert "--cpus=1.5" in cmd


@pytest.mark.asyncio
async def test_mount_path_added_as_volume(tmp_path):
    proc = _make_proc()
    with patch("tools.docker_runner.asyncio.create_subprocess_exec", return_value=proc) as mock_exec:
        await run_container("nmap:latest", [], mount_path=str(tmp_path))
    cmd = mock_exec.call_args[0]
    assert "-v" in cmd


@pytest.mark.asyncio
async def test_env_vars_injected():
    proc = _make_proc()
    with patch("tools.docker_runner.asyncio.create_subprocess_exec", return_value=proc) as mock_exec:
        await run_container("nmap:latest", [], env_vars={"FOO": "bar"})
    cmd = mock_exec.call_args[0]
    assert "-e" in cmd
    assert "FOO=bar" in cmd


@pytest.mark.asyncio
async def test_timeout_raises_and_kills_process():
    proc = MagicMock()
    proc.kill = MagicMock()
    proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError)

    async def fake_wait_for(coro, timeout):
        raise asyncio.TimeoutError

    with patch("tools.docker_runner.asyncio.create_subprocess_exec", return_value=proc), \
         patch("tools.docker_runner.asyncio.wait_for", side_effect=fake_wait_for):
        with pytest.raises(asyncio.TimeoutError):
            await run_container("nmap:latest", [], timeout=1)

    proc.kill.assert_called_once()


@pytest.mark.asyncio
async def test_extra_volumes_added_as_mounts(tmp_path):
    proc = _make_proc()
    extra = [(str(tmp_path), "/extra:ro")]
    with patch("tools.docker_runner.asyncio.create_subprocess_exec", return_value=proc) as mock_exec:
        await run_container("nmap:latest", [], extra_volumes=extra)
    cmd = mock_exec.call_args[0]
    assert "-v" in cmd
    assert any("/extra:ro" in str(a) for a in cmd)


@pytest.mark.asyncio
async def test_timeout_communicates_after_kill():
    """After TimeoutError, proc.communicate() must be awaited to reap the process."""
    communicate_calls = []

    async def _communicate():
        communicate_calls.append(True)
        return b"", b""

    proc = MagicMock()
    proc.kill = MagicMock()
    proc.communicate = _communicate

    async def fake_wait_for(coro, timeout):
        raise asyncio.TimeoutError

    with patch("tools.docker_runner.asyncio.create_subprocess_exec", return_value=proc), \
         patch("tools.docker_runner.asyncio.wait_for", side_effect=fake_wait_for):
        with pytest.raises(asyncio.TimeoutError):
            await run_container("nmap:latest", [], timeout=1)

    assert len(communicate_calls) == 1


@pytest.mark.asyncio
async def test_output_bytes_decoded_with_replace():
    """Invalid UTF-8 bytes should be replaced, not raise."""
    proc = _make_proc(stdout=b"\xff\xfe raw bytes")
    with patch("tools.docker_runner.asyncio.create_subprocess_exec", return_value=proc):
        stdout, _, _ = await run_container("nmap:latest", [])
    assert isinstance(stdout, str)
