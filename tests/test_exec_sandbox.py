"""
Tests for the exec_sandbox scan handler (Docker mocked — no real container run).
Verifies the fail-soft contract and artifact-backed success path.
"""
import pytest
from unittest.mock import AsyncMock, patch

from mcp_server.scan_tools import _handle_exec_sandbox


@pytest.mark.asyncio
async def test_no_codebase_returns_guidance(monkeypatch):
    monkeypatch.delenv("PENTEST_TARGET_PATH", raising=False)
    res = await _handle_exec_sandbox("", "", {})
    assert "No codebase" in res


@pytest.mark.asyncio
async def test_success_returns_artifact(tmp_path):
    with patch("tools.sandbox_runner.run_in_sandbox", new=AsyncMock(return_value={
        "ok": True, "timed_out": False, "exit_code": 1,
        "output": "Traceback (most recent call last):\nValueError: boom", "image": "python:3.11-slim",
    })), patch("mcp_server.scan_engine.artifacts.store_artifact", return_value="exec_sandbox_abc"):
        res = await _handle_exec_sandbox(str(tmp_path), "", {"cmd": "python repro.py"})
    assert "artifact_id=exec_sandbox_abc" in res
    assert "exit_code=1" in res
    assert "Traceback" in res


@pytest.mark.asyncio
async def test_fail_soft_on_runner_error(tmp_path):
    with patch("tools.sandbox_runner.run_in_sandbox", new=AsyncMock(return_value={
        "ok": False, "error": "could not pull image 'python:3.11-slim'",
    })):
        res = await _handle_exec_sandbox(str(tmp_path), "", {"cmd": "python repro.py"})
    assert "could not run" in res and "fall back to static evidence" in res
