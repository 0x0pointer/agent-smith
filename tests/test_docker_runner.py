"""
Tests for tools.docker_runner.run_container and _ensure_image.

All tests mock asyncio.create_subprocess_exec so no Docker daemon is needed.
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from tools.docker_runner import _ensure_image, run_container
import tools.docker_runner as _dr


@pytest.fixture(autouse=True)
def _skip_image_pull():
    """Bypass _ensure_image so run_container tests don't need a Docker daemon."""
    with patch("tools.docker_runner._ensure_image", new_callable=AsyncMock):
        yield


@pytest.fixture(autouse=True)
def _clear_pulled_cache():
    """Reset the pulled-images cache between tests."""
    _dr._pulled_images.clear()
    yield
    _dr._pulled_images.clear()


# ---------------------------------------------------------------------------
# _ensure_image tests
# ---------------------------------------------------------------------------

def _make_inspect_proc(returncode: int = 0):
    """Mock process for docker image inspect."""
    proc = MagicMock()
    proc.returncode = returncode
    proc.wait = AsyncMock(return_value=returncode)
    return proc


def _make_pull_proc(returncode: int = 0, stdout: bytes = b"", stderr: bytes = b""):
    """Mock process for docker pull."""
    proc = MagicMock()
    proc.returncode = returncode
    proc.communicate = AsyncMock(return_value=(stdout, stderr))
    return proc


@pytest.mark.asyncio
async def test_ensure_image_skips_when_cached(_skip_image_pull):
    """If image is already in the cache, no subprocess should be spawned."""
    # Override the autouse _skip_image_pull — call the real function
    _dr._pulled_images.add("cached:latest")
    with patch("tools.docker_runner.asyncio.create_subprocess_exec") as mock_exec:
        await _ensure_image("cached:latest")
    mock_exec.assert_not_called()


@pytest.mark.asyncio
async def test_ensure_image_local_hit(_skip_image_pull):
    """docker image inspect succeeds → image added to cache, no pull."""
    inspect_proc = _make_inspect_proc(returncode=0)
    with patch("tools.docker_runner.asyncio.create_subprocess_exec", return_value=inspect_proc):
        await _ensure_image("local:latest")
    assert "local:latest" in _dr._pulled_images


@pytest.mark.asyncio
async def test_ensure_image_pull_success(_skip_image_pull):
    """docker image inspect fails, docker pull succeeds → image cached."""
    inspect_proc = _make_inspect_proc(returncode=1)
    pull_proc = _make_pull_proc(returncode=0)

    call_count = 0

    async def _side_effect(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return inspect_proc if call_count == 1 else pull_proc

    with patch("tools.docker_runner.asyncio.create_subprocess_exec", side_effect=_side_effect):
        await _ensure_image("remote:latest")
    assert "remote:latest" in _dr._pulled_images


@pytest.mark.asyncio
async def test_ensure_image_pull_failure_raises(_skip_image_pull):
    """docker image inspect fails, docker pull fails → RuntimeError."""
    inspect_proc = _make_inspect_proc(returncode=1)
    pull_proc = _make_pull_proc(returncode=1, stderr=b"denied: access forbidden")

    call_count = 0

    async def _side_effect(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return inspect_proc if call_count == 1 else pull_proc

    with patch("tools.docker_runner.asyncio.create_subprocess_exec", side_effect=_side_effect):
        with pytest.raises(RuntimeError, match="denied: access forbidden"):
            await _ensure_image("private:latest")
    assert "private:latest" not in _dr._pulled_images


@pytest.mark.asyncio
async def test_ensure_image_pull_failure_falls_back_to_stdout(_skip_image_pull):
    """When stderr is empty, error message falls back to stdout."""
    inspect_proc = _make_inspect_proc(returncode=1)
    pull_proc = _make_pull_proc(returncode=1, stdout=b"not found", stderr=b"")

    call_count = 0

    async def _side_effect(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return inspect_proc if call_count == 1 else pull_proc

    with patch("tools.docker_runner.asyncio.create_subprocess_exec", side_effect=_side_effect):
        with pytest.raises(RuntimeError, match="not found"):
            await _ensure_image("missing:latest")


# ---------------------------------------------------------------------------
# run_container tests
# ---------------------------------------------------------------------------

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
