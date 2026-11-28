"""The platform (`smith start`) owns its dashboard.

A scan started from the platform runs its own tool server. When the agent asked
that server for the dashboard (the pentester skill does, at the start of every
scan) it replaced the platform with a copy running in the scan's environment:
the one scan was listed twice (again as the repo-root scan) and stopping it took
the platform down.
"""
from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import core.api_server as api_server
from control_plane import orchestrator


@pytest.fixture
def pid_file(tmp_path, monkeypatch):
    path = tmp_path / "dashboard.pid"
    monkeypatch.setattr(api_server, "_PID_FILE", path)
    return path


def _no_run(monkeypatch):
    monkeypatch.delenv("SMITH_RUN_ID", raising=False)
    monkeypatch.delenv("SMITH_SINGLE_RUN", raising=False)


@pytest.mark.asyncio
async def test_a_platform_scans_tool_server_never_restarts_the_dashboard(monkeypatch, pid_file):
    monkeypatch.setenv("SMITH_RUN_ID", "run-abc")
    monkeypatch.delenv("SMITH_SINGLE_RUN", raising=False)
    pid_file.write_text(str(os.getpid()))          # the plain pid `smith start` records
    monkeypatch.setattr(api_server, "_port_healthy", lambda port: True)
    spawn = AsyncMock()

    with patch("asyncio.create_subprocess_exec", spawn), patch("psutil.Process") as process:
        url = await api_server.serve(7777)

    assert url == "http://localhost:7777"
    spawn.assert_not_called()
    process.assert_not_called()                    # nothing was terminated
    assert pid_file.read_text() == str(os.getpid())


@pytest.mark.asyncio
async def test_a_platform_scan_says_so_when_the_platform_is_down(monkeypatch, pid_file):
    monkeypatch.setenv("SMITH_RUN_ID", "run-abc")
    monkeypatch.delenv("SMITH_SINGLE_RUN", raising=False)
    monkeypatch.setattr(api_server, "_port_healthy", lambda port: False)
    spawn = AsyncMock()

    with patch("asyncio.create_subprocess_exec", spawn):
        message = await api_server.serve(7777)

    assert "smith start" in message and not message.startswith("http")
    spawn.assert_not_called()
    assert not pid_file.exists()


@pytest.mark.asyncio
async def test_nobody_replaces_a_running_platform_dashboard(monkeypatch, pid_file):
    """Another client (the shared tool server) asking for the dashboard reuses the platform."""
    _no_run(monkeypatch)
    pid_file.write_text(str(os.getpid()))
    monkeypatch.setattr(api_server, "_platform_on_port", lambda port: True)
    monkeypatch.setattr(api_server, "_port_healthy", lambda port: True)
    spawn = AsyncMock()

    with patch("asyncio.create_subprocess_exec", spawn), patch("psutil.Process") as process:
        url = await api_server.serve(7777)

    assert url == "http://localhost:7777"
    spawn.assert_not_called()
    process.assert_not_called()


@pytest.mark.asyncio
async def test_a_dashboard_is_still_started_when_there_is_no_platform(monkeypatch, pid_file):
    _no_run(monkeypatch)
    monkeypatch.setattr(api_server, "_platform_on_port", lambda port: False)
    started = []
    monkeypatch.setattr(api_server, "_port_healthy", lambda port: bool(started))

    async def _spawn(*args, **kwargs):
        started.append(args)
        return MagicMock(pid=4242)

    with patch("asyncio.create_subprocess_exec", side_effect=_spawn), \
            patch("asyncio.sleep", new_callable=AsyncMock):
        url = await api_server.serve(7777)

    assert url == "http://localhost:7777"
    assert len(started) == 1
    assert pid_file.read_text().startswith("4242:")


def test_healthz_says_whether_this_dashboard_is_the_platform(monkeypatch):
    client = TestClient(api_server.app)

    monkeypatch.setenv("SMITH_DATABASE_URL", "sqlite:///somewhere.db")
    assert client.get("/healthz").json() == {"ok": True, "platform": True}

    monkeypatch.delenv("SMITH_DATABASE_URL")
    assert client.get("/healthz").json() == {"ok": True, "platform": False}


def test_platform_on_port_is_false_when_nothing_answers():
    assert api_server._platform_on_port(19999) is False


def test_smith_reads_the_dashboard_pid_in_both_recorded_forms(tmp_path):
    path = tmp_path / "dashboard.pid"

    path.write_text("4242")
    assert orchestrator._read_pid_file(path) == 4242

    path.write_text("4242:1795819832.772549")      # written by core.api_server.serve
    assert orchestrator._read_pid_file(path) == 4242

    path.write_text("not a pid")
    assert orchestrator._read_pid_file(path) is None
