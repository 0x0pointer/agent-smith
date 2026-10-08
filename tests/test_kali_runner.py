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
# _force_bash (pure function — no mocking needed)
# ---------------------------------------------------------------------------

def test_force_bash_wraps_simple_command():
    result = kr._force_bash("id")
    assert result.startswith("bash -c ")
    # shlex.quote wraps single-word args in single quotes only if necessary
    assert "id" in result


def test_force_bash_preserves_bashisms():
    # `[[ ]]` is the canonical bashism dash does not support
    cmd = '[[ "a" == "a" ]] && echo ok'
    result = kr._force_bash(cmd)
    assert result.startswith("bash -c ")
    # The inner command survives intact once shell-unquoted
    import shlex
    tokens = shlex.split(result)
    assert tokens[:2] == ["bash", "-c"]
    assert tokens[2] == cmd


def test_force_bash_preserves_single_quotes():
    cmd = "echo 'hello world'"
    result = kr._force_bash(cmd)
    import shlex
    tokens = shlex.split(result)
    assert tokens[:2] == ["bash", "-c"]
    assert tokens[2] == cmd


def test_force_bash_preserves_double_quotes_and_vars():
    cmd = 'echo "$HOME"'
    result = kr._force_bash(cmd)
    import shlex
    tokens = shlex.split(result)
    assert tokens[:2] == ["bash", "-c"]
    assert tokens[2] == cmd


def test_force_bash_preserves_pipes_and_redirects():
    cmd = "ls -la | grep foo > /tmp/out.txt 2>&1"
    result = kr._force_bash(cmd)
    import shlex
    tokens = shlex.split(result)
    assert tokens[:2] == ["bash", "-c"]
    assert tokens[2] == cmd


def test_force_bash_preserves_backslashes():
    cmd = r"grep -E 'foo\s+bar' /etc/passwd"
    result = kr._force_bash(cmd)
    import shlex
    tokens = shlex.split(result)
    assert tokens[:2] == ["bash", "-c"]
    assert tokens[2] == cmd


def test_force_bash_double_wrapping_is_idempotent_in_effect():
    # Already-wrapped commands get double-wrapped, which is harmless —
    # the outer bash invokes the inner bash with the same argument list.
    cmd = "bash -c 'echo inner'"
    result = kr._force_bash(cmd)
    assert result.startswith("bash -c ")
    import shlex
    tokens = shlex.split(result)
    assert tokens[:2] == ["bash", "-c"]
    assert tokens[2] == cmd


def test_force_bash_empty_string_unchanged():
    # No point wrapping an empty command.
    assert kr._force_bash("") == ""


def test_force_bash_whitespace_only_unchanged():
    assert kr._force_bash("   ") == "   "


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


@pytest.mark.asyncio
async def test_exec_command_wraps_in_bash_c_before_sending():
    """The posted command must start with `bash -c ` so bashisms survive
    dash (/bin/sh on Kali) when kali-server-mcp executes it."""
    resp = _mock_resp(stdout="ok")
    session = _mock_session(resp)
    import aiohttp
    with patch.object(kr, "ensure_running", AsyncMock(return_value=(True, "running"))), \
         patch.object(aiohttp, "ClientSession", return_value=session):
        await kr.exec_command('[[ "a" == "a" ]] && echo ok')
    posted_json = session.post.call_args[1]["json"]
    assert posted_json["command"].startswith("bash -c ")
    # The inner (bashism) command must be fully preserved
    import shlex
    tokens = shlex.split(posted_json["command"])
    assert tokens[:2] == ["bash", "-c"]
    assert tokens[2] == '[[ "a" == "a" ]] && echo ok'


@pytest.mark.asyncio
async def test_exec_command_bash_wrap_composes_with_host_rewrite():
    """Host rewrite runs before bash wrap, so the final posted command
    contains host.docker.internal (not localhost) inside the bash -c."""
    resp = _mock_resp(stdout="ok")
    session = _mock_session(resp)
    import aiohttp
    with patch.object(kr, "ensure_running", AsyncMock(return_value=(True, "running"))), \
         patch.object(aiohttp, "ClientSession", return_value=session):
        await kr.exec_command("curl http://localhost:3000")
    posted_json = session.post.call_args[1]["json"]
    posted = posted_json["command"]
    assert posted.startswith("bash -c ")
    assert "localhost" not in posted
    assert "host.docker.internal" in posted


# ---------------------------------------------------------------------------
# #253 / #254 — file delivery, background jobs, artifacts mount
# ---------------------------------------------------------------------------

def test_background_command_detaches_and_records_rc():
    cmd = kr.background_command("python3 run.py 'a b'", "abc12345")
    assert "nohup setsid sh -c" in cmd and cmd.rstrip().endswith("echo started job abc12345")
    assert "/tmp/smith-jobs/abc12345.log" in cmd and "/tmp/smith-jobs/abc12345.rc" in cmd


def test_poll_command_reports_status_and_tail():
    cmd = kr.poll_command("abc12345", tail_bytes=100)
    assert "__JOB_STATUS__ done" in cmd and "__JOB_STATUS__ running" in cmd
    assert "tail -c 100 /tmp/smith-jobs/abc12345.log" in cmd


@pytest.mark.asyncio
async def test_put_file_rejects_relative_path():
    assert "must be absolute" in await kr.put_file("tmp/x", b"x")


@pytest.mark.asyncio
async def test_put_file_pipes_stdin():
    proc = MagicMock()
    proc.communicate = AsyncMock(return_value=(b"", b""))
    proc.returncode = 0
    with patch.object(kr, "ensure_running", AsyncMock(return_value=(True, "running"))), \
         patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)) as cse:
        assert await kr.put_file("/tmp/p dir/x.txt", b"DATA") is None
    argv = cse.call_args.args
    assert argv[1:4] == ("exec", "-i", kr.KALI_CONTAINER)
    assert "'/tmp/p dir/x.txt'" in argv[-1]
    proc.communicate.assert_awaited_once_with(b"DATA")


def test_guard_honours_timeout_and_kills_group():
    import importlib.util
    import pathlib
    import time
    spec = importlib.util.spec_from_file_location(
        "kali_api_guard", pathlib.Path(kr.__file__).parent / "kali" / "api_guard.py")
    g = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(g)
    r = g.run_command("echo hi", 5)
    assert r["stdout"].strip() == "hi" and r["return_code"] == 0 and not r["timed_out"]
    t0 = time.time()
    r = g.run_command("echo start; sleep 30 & sleep 30", 1)
    assert r["timed_out"] and "start" in r["stdout"] and time.time() - t0 < 15
    assert g._clamp_timeout(10**9) == g.MAX_COMMAND_TIMEOUT and g._clamp_timeout("x") == 180
