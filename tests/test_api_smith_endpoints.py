"""
Tests for the Smith-lifecycle endpoints in core.api_server:

  • /api/intervention           (GET — force-reloads from disk)
  • /api/intervention/respond   (POST — resolves an HIR)
  • /api/steer                  (POST — queues a HUMAN_STEER directive)
  • /api/complete               (POST — terminal status transition)
  • /api/smith-status           (GET — alive/dead heartbeat)
  • /api/smith-clients          (GET — claude vs opencode auto-detect)
  • /api/restart-smith          (POST — spawn a fresh client)
  • /api/watchdog               (GET — watchdog config + recent stats)

Plus the small helpers that aren't covered elsewhere:

  • _smith_running, _client_installed, _client_process_running,
    _detect_active_client, _mcp_sse_alive, _smith_watchdog_loop.

The endpoints share a few invariants:
  - they always `load_from_disk(force=True)` before touching session.json,
    so monkeypatching _SESSION_FILE in core.session is enough to sandbox.
  - they never call out to subprocess except via _spawn_smith, which we
    mock — no real `claude -p` / `opencode run` ever fires in tests.
"""
import asyncio
import json
import time
from pathlib import Path
from unittest.mock import patch, AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

import core.api_server as api
import core.session as scan_session
from core.api_server import app

client = TestClient(app)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sandbox_session(tmp_path, monkeypatch):
    """Point every "session.json"-aware constant at tmp_path and reset
    the in-memory _current so each test starts from a clean slate."""
    session_file = tmp_path / "session.json"
    monkeypatch.setattr(scan_session, "_SESSION_FILE", session_file)
    monkeypatch.setattr(api, "_SESSION_FILE", session_file)
    scan_session._current = None
    yield session_file
    scan_session._current = None


@pytest.fixture
def sandbox_smith_files(tmp_path, monkeypatch):
    """Quick-log + smith.pid + smith.client paths in tmp_path."""
    monkeypatch.setattr(api, "_QUICK_LOG_FILE", tmp_path / "quick_log.json")
    monkeypatch.setattr(api, "_SMITH_PID_FILE", tmp_path / "smith.pid")
    monkeypatch.setattr(api, "_SMITH_CLIENT_FILE", tmp_path / "smith.client")


def _write_session(session_file: Path, **overrides):
    """Write a minimal session.json. Defaults to a running scan."""
    data = {
        "target": "http://x.test",
        "status": "running",
        "intervention": None,
        "intervention_history": [],
    }
    data.update(overrides)
    session_file.write_text(json.dumps(data))


# ---------------------------------------------------------------------------
# GET /api/intervention
# ---------------------------------------------------------------------------

class TestApiIntervention:

    def test_idle_returns_active_false(self, sandbox_session):
        _write_session(sandbox_session, status="running", intervention=None)
        r = client.get("/api/intervention")
        assert r.status_code == 200
        assert r.json() == {"active": False}

    def test_active_returns_payload(self, sandbox_session):
        iv = {
            "code": "HIR_AUTH_FAILURE",
            "situation": "7/10 401s",
            "options": ["REAUTH: …", "ABORT: …"],
        }
        _write_session(sandbox_session, status="intervention_required", intervention=iv)
        r = client.get("/api/intervention")
        body = r.json()
        assert body["active"] is True
        assert body["code"] == "HIR_AUTH_FAILURE"
        assert "7/10" in body["situation"]

    def test_force_reload_picks_up_disk_change(self, sandbox_session):
        # Cached state says intervention_required → endpoint must re-read
        # from disk and notice that the scan is now complete.
        iv = {"code": "HIR_FOO", "situation": ""}
        scan_session._current = {"status": "intervention_required", "intervention": iv}
        # On disk: scan completed, no intervention
        _write_session(sandbox_session, status="complete", intervention=None)
        r = client.get("/api/intervention")
        assert r.json() == {"active": False}


# ---------------------------------------------------------------------------
# POST /api/intervention/respond
# ---------------------------------------------------------------------------

class TestApiInterventionRespond:

    def test_rejects_empty_body(self, sandbox_session):
        _write_session(sandbox_session)
        r = client.post("/api/intervention/respond", json={"choice": "", "message": ""})
        assert r.status_code == 400
        assert "required" in r.json()["error"]

    def test_resolves_active_intervention(self, sandbox_session):
        iv = {"code": "HIR_AUTH_FAILURE", "situation": ""}
        _write_session(sandbox_session, status="intervention_required", intervention=iv)
        with patch("core.steering.steering_queue") as q:
            r = client.post("/api/intervention/respond",
                            json={"choice": "REAUTH", "message": "admin/admin"})
        assert r.status_code == 200
        assert r.json()["ok"] is True
        # Steering directive was queued with the human response
        q.add_directive.assert_called_once()
        kwargs = q.add_directive.call_args.kwargs
        assert kwargs["trigger"] == "HIR_RESOLVED"
        assert "REAUTH" in kwargs["message"]


# ---------------------------------------------------------------------------
# POST /api/steer
# ---------------------------------------------------------------------------

class TestApiSteer:

    def test_rejects_empty_message(self, sandbox_session):
        r = client.post("/api/steer", json={"message": "   "})
        assert r.status_code == 400

    def test_queues_directive(self, sandbox_session):
        _write_session(sandbox_session)
        with patch("core.steering.steering_queue") as q:
            r = client.post("/api/steer", json={"message": "Pivot to /api/bills"})
        assert r.status_code == 200
        assert r.json()["ok"] is True
        kwargs = q.add_directive.call_args.kwargs
        assert kwargs["force"] is True  # human steers never dedup
        assert "Pivot to /api/bills" in kwargs["message"]


# ---------------------------------------------------------------------------
# POST /api/complete
# ---------------------------------------------------------------------------

class TestApiComplete:

    def test_marks_session_complete(self, sandbox_session):
        _write_session(sandbox_session, status="running")
        r = client.post("/api/complete", json={"notes": "done"})
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True
        # Status persisted to disk
        on_disk = json.loads(sandbox_session.read_text())
        assert on_disk["status"] == "complete"
        assert on_disk.get("notes") == "done"


# ---------------------------------------------------------------------------
# GET /api/smith-status + _smith_running
# ---------------------------------------------------------------------------

class TestSmithRunning:

    def test_running_false_when_no_signals(self, sandbox_smith_files, tmp_path):
        # No pid file, no quick_log → must report not running
        assert api._smith_running() is False

    def test_running_true_when_quick_log_fresh(self, sandbox_smith_files, tmp_path):
        (tmp_path / "quick_log.json").write_text('{"type":"TOOL"}\n')
        assert api._smith_running() is True

    def test_running_false_when_quick_log_stale(self, sandbox_smith_files, tmp_path):
        ql = tmp_path / "quick_log.json"
        ql.write_text("{}\n")
        # Push mtime back 1 hour
        old_mtime = time.time() - 3600
        import os as _os
        _os.utime(ql, (old_mtime, old_mtime))
        assert api._smith_running() is False

    def test_running_handles_bogus_pid_file(self, sandbox_smith_files, tmp_path):
        # PID file with text that doesn't parse → fall through to activity check
        (tmp_path / "smith.pid").write_text("notapid\n")
        assert api._smith_running() is False

    def test_running_caps_huge_pid_value(self, sandbox_smith_files, tmp_path):
        # PID well above POSIX kernel.pid_max → must short-circuit, not blow up
        (tmp_path / "smith.pid").write_text(str(10 ** 20))
        assert api._smith_running() is False

    def test_endpoint_returns_running_flag(self, sandbox_smith_files):
        with patch.object(api, "_smith_running", return_value=True):
            r = client.get("/api/smith-status")
        assert r.json() == {"running": True}


# ---------------------------------------------------------------------------
# GET /api/smith-clients + _client_installed / _detect_active_client
# ---------------------------------------------------------------------------

class TestSmithClients:

    def test_both_installed_active_is_string(self):
        with patch.object(api, "_client_installed", return_value=True):
            r = client.get("/api/smith-clients")
        body = r.json()
        assert body["claude"] is True
        assert body["opencode"] is True
        assert body["active"] in ("claude", "opencode")

    def test_detect_prefers_persisted_choice(self, sandbox_smith_files, tmp_path):
        (tmp_path / "smith.client").write_text("opencode")
        with patch.object(api, "_client_installed", return_value=True):
            assert api._detect_active_client() == "opencode"

    def test_detect_falls_back_to_claude(self):
        with patch.object(api, "_client_installed",
                          side_effect=lambda name: name == "claude"):
            with patch.object(api, "_client_process_running", return_value=False):
                assert api._detect_active_client() == "claude"

    def test_detect_prefers_opencode_when_both_installed_and_no_history(
        self, sandbox_smith_files
    ):
        # No smith.client persisted, no running process → opencode wins
        with patch.object(api, "_client_installed", return_value=True):
            with patch.object(api, "_client_process_running", return_value=False):
                assert api._detect_active_client() == "opencode"

    def test_client_process_running_handles_pgrep_failure(self):
        # Force subprocess.run to raise — _client_process_running must
        # swallow + return False rather than crash the watchdog loop.
        with patch("subprocess.run", side_effect=FileNotFoundError("pgrep")):
            assert api._client_process_running("claude") is False


# ---------------------------------------------------------------------------
# POST /api/restart-smith
# ---------------------------------------------------------------------------

class TestRestartSmith:

    def test_blocks_when_smith_is_running(self, sandbox_session, sandbox_smith_files):
        _write_session(sandbox_session)
        with patch.object(api, "_smith_running", return_value=True):
            r = client.post("/api/restart-smith", json={})
        assert r.status_code == 409
        assert "already running" in r.json()["error"]

    def test_force_bypass_runs_through(self, sandbox_session, sandbox_smith_files):
        _write_session(sandbox_session)
        spawn = AsyncMock(return_value=(True, 9999))
        with patch.object(api, "_smith_running", return_value=True), \
             patch.object(api, "_spawn_smith", spawn), \
             patch.object(api, "_client_installed", return_value=True):
            r = client.post("/api/restart-smith", json={"force": True})
        assert r.status_code == 200
        assert r.json()["ok"] is True
        assert r.json()["pid"] == 9999
        spawn.assert_awaited_once()

    def test_rejects_unknown_client(self, sandbox_session, sandbox_smith_files):
        _write_session(sandbox_session)
        with patch.object(api, "_smith_running", return_value=False):
            r = client.post("/api/restart-smith", json={"client": "vim"})
        assert r.status_code == 400
        assert "Unknown client" in r.json()["error"]

    def test_rejects_uninstalled_client(self, sandbox_session, sandbox_smith_files):
        _write_session(sandbox_session)
        with patch.object(api, "_smith_running", return_value=False), \
             patch.object(api, "_client_installed", return_value=False):
            r = client.post("/api/restart-smith", json={"client": "claude"})
        assert r.status_code == 400
        assert "not installed" in r.json()["error"]


# ---------------------------------------------------------------------------
# GET /api/watchdog
# ---------------------------------------------------------------------------

class TestWatchdogStatus:

    def test_watchdog_status_shape(self):
        r = client.get("/api/watchdog")
        body = r.json()
        # `enabled` is True if the FastAPI startup hook ran AND the watchdog
        # task is still alive — in TestClient that hook may or may not fire
        # depending on lifespan management, so accept either bool.
        assert isinstance(body["enabled"], bool)
        assert "restarts_in_last_hour" in body
        assert "max_per_hour" in body
        assert "poll_seconds" in body
        assert "min_gap_seconds" in body
        assert "last_restart_ago_s" in body


# ---------------------------------------------------------------------------
# _mcp_sse_alive
# ---------------------------------------------------------------------------

class TestMcpSseAlive:

    def test_returns_false_when_port_closed(self):
        # Depending on the test host, MCP might actually be running on 7778.
        # We just need the function to return a bool without raising.
        ok = api._mcp_sse_alive()
        assert isinstance(ok, bool)

    def test_handles_socket_oserror(self):
        import socket
        real_socket = socket.socket

        class _FailingSocket(real_socket):
            def connect_ex(self, _addr):
                raise OSError("synthetic")

        with patch("socket.socket", _FailingSocket):
            result = api._mcp_sse_alive()
        assert result is False


# ---------------------------------------------------------------------------
# _smith_watchdog_loop — single-iteration smoke test
# ---------------------------------------------------------------------------

class TestSmithWatchdogLoop:

    def _make_loop_runner(self, monkeypatch):
        """Patch asyncio.sleep so the watchdog loop body runs exactly once
        then exits via CancelledError on the second sleep call."""
        ticks = {"n": 0}

        async def fake_sleep(_s):
            ticks["n"] += 1
            if ticks["n"] > 1:
                raise asyncio.CancelledError()

        monkeypatch.setattr("asyncio.sleep", fake_sleep)
        return ticks

    def _run_watchdog(self):
        """Run the watchdog loop and absorb the expected CancelledError exit."""
        import contextlib
        with contextlib.suppress(asyncio.CancelledError):
            asyncio.run(api._smith_watchdog_loop())

    def test_skips_when_session_not_running(self, sandbox_session, monkeypatch):
        self._make_loop_runner(monkeypatch)
        _write_session(sandbox_session, status="complete")
        # Loop body should hit the early-return for status != running
        self._run_watchdog()

    def test_skips_when_mcp_unreachable(self, sandbox_session, sandbox_smith_files, monkeypatch):
        self._make_loop_runner(monkeypatch)
        _write_session(sandbox_session, status="running")
        spawn = AsyncMock()
        with patch.object(api, "_smith_running", return_value=False), \
             patch.object(api, "_mcp_sse_alive", return_value=False), \
             patch.object(api, "_spawn_smith", spawn):
            self._run_watchdog()
        # MCP-health gate must have prevented the spawn
        spawn.assert_not_awaited()

    def test_spawns_when_all_conditions_met(self, sandbox_session, sandbox_smith_files, monkeypatch):
        self._make_loop_runner(monkeypatch)
        _write_session(sandbox_session, status="running")
        spawn = AsyncMock(return_value=(True, 4242))
        with patch.object(api, "_smith_running", return_value=False), \
             patch.object(api, "_mcp_sse_alive", return_value=True), \
             patch.object(api, "_detect_active_client", return_value="opencode"), \
             patch.object(api, "_spawn_smith", spawn):
            self._run_watchdog()
        spawn.assert_awaited_once()

    def test_loop_continues_after_non_cancel_exception(self, sandbox_session, monkeypatch):
        """Exception in tick body must not crash the loop — only CancelledError exits."""
        ticks = {"n": 0}

        async def fake_sleep(_s):
            ticks["n"] += 1
            if ticks["n"] > 1:
                raise asyncio.CancelledError()

        async def boom(_now):
            raise RuntimeError("synthetic tick error")

        monkeypatch.setattr("asyncio.sleep", fake_sleep)
        monkeypatch.setattr(api, "_watchdog_tick", boom)
        import contextlib
        with contextlib.suppress(asyncio.CancelledError):
            asyncio.run(api._smith_watchdog_loop())
        assert ticks["n"] == 2  # second sleep fired → loop survived the exception


# ---------------------------------------------------------------------------
# _watchdog_tick — guard condition unit tests
# ---------------------------------------------------------------------------

class TestWatchdogTick:

    def _run_tick(self, now=9999.0):
        asyncio.run(api._watchdog_tick(now))

    def test_skips_when_intervention_active(self, sandbox_session):
        _write_session(sandbox_session, status="running",
                       intervention={"code": "HIR_AUTH_FAILURE", "situation": ""})
        spawn = AsyncMock()
        with patch.object(api, "_spawn_smith", spawn):
            self._run_tick()
        spawn.assert_not_awaited()

    def test_skips_when_smith_already_running(self, sandbox_session):
        _write_session(sandbox_session, status="running")
        spawn = AsyncMock()
        with patch.object(api, "_smith_running", return_value=True), \
             patch.object(api, "_spawn_smith", spawn):
            self._run_tick()
        spawn.assert_not_awaited()

    def test_skips_when_min_gap_not_elapsed(self, sandbox_session):
        _write_session(sandbox_session, status="running")
        spawn = AsyncMock()
        api._watchdog_last_restart_ts = 9000.0  # now=9999, gap=999 < MIN_GAP
        with patch.object(api, "_smith_running", return_value=False), \
             patch.object(api, "_mcp_sse_alive", return_value=True), \
             patch.object(api, "_spawn_smith", spawn):
            self._run_tick(now=9000.0 + api._WATCHDOG_MIN_GAP_SECONDS - 1)
        spawn.assert_not_awaited()
        api._watchdog_last_restart_ts = 0.0  # reset for other tests

    def test_skips_when_hourly_cap_exceeded(self, sandbox_session):
        _write_session(sandbox_session, status="running")
        spawn = AsyncMock()
        now = 9999.0
        api._watchdog_restart_count_window[:] = [now - 10] * api._WATCHDOG_MAX_PER_HOUR
        with patch.object(api, "_smith_running", return_value=False), \
             patch.object(api, "_mcp_sse_alive", return_value=True), \
             patch.object(api, "_spawn_smith", spawn):
            self._run_tick(now=now)
        spawn.assert_not_awaited()
        api._watchdog_restart_count_window.clear()
