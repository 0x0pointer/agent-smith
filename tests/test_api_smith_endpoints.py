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
    """Quick-log + smith.pid + smith.client + session paths in tmp_path."""
    monkeypatch.setattr(api, "_QUICK_LOG_FILE", tmp_path / "quick_log.json")
    monkeypatch.setattr(api, "_SMITH_PID_FILE", tmp_path / "smith.pid")
    monkeypatch.setattr(api, "_SMITH_CLIENT_FILE", tmp_path / "smith.client")
    monkeypatch.setattr(api, "_SESSION_FILE", tmp_path / "session.json")


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

    def test_running_true_via_session_fallback_when_quick_log_missing(
        self, sandbox_smith_files, tmp_path
    ):
        # quick_log absent + session running + started < 2 h ago → True
        from datetime import datetime, timezone, timedelta
        import json as _json
        session_file = tmp_path / "session.json"
        session_file.write_text(_json.dumps({
            "status": "running",
            "finished": None,
            "started": (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(),
        }))
        monkeypatch_session = patch.object(api, "_SESSION_FILE", session_file)
        with monkeypatch_session:
            assert api._smith_running() is True

    def test_running_false_via_session_fallback_when_session_old(
        self, sandbox_smith_files, tmp_path
    ):
        # quick_log absent + session running but started > 2 h ago → False
        from datetime import datetime, timezone, timedelta
        import json as _json
        session_file = tmp_path / "session.json"
        session_file.write_text(_json.dumps({
            "status": "running",
            "finished": None,
            "started": (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat(),
        }))
        with patch.object(api, "_SESSION_FILE", session_file):
            assert api._smith_running() is False


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

    def test_detect_prefers_claude_when_both_installed_and_no_history(
        self, sandbox_smith_files
    ):
        # No smith.client persisted, no running process → claude is the default fallback
        with patch.object(api, "_client_installed", return_value=True):
            with patch.object(api, "_client_process_running", return_value=False):
                assert api._detect_active_client() == "claude"

    def test_client_process_running_finds_match_in_name(self):
        import psutil
        fake = MagicMock()
        fake.info = {"name": "claude", "cmdline": ["claude", "--foo"]}
        with patch.object(psutil, "process_iter", return_value=[fake]):
            assert api._client_process_running("claude") is True

    def test_client_process_running_finds_match_in_cmdline(self):
        """opencode runs as 'node /path/to/opencode' — name is 'node' but the
        cmdline contains 'opencode'. Must match either way."""
        import psutil
        fake = MagicMock()
        fake.info = {"name": "node", "cmdline": ["node", "/Users/u/.opencode/bin/opencode", "run"]}
        with patch.object(psutil, "process_iter", return_value=[fake]):
            assert api._client_process_running("opencode") is True

    def test_client_process_running_returns_false_when_no_match(self):
        import psutil
        fake = MagicMock()
        fake.info = {"name": "bash", "cmdline": ["bash", "-l"]}
        with patch.object(psutil, "process_iter", return_value=[fake]):
            assert api._client_process_running("claude") is False

    def test_client_process_running_handles_iter_failure(self):
        """psutil.process_iter raising → swallow and return False so the
        watchdog loop doesn't blow up on transient errors."""
        import psutil
        with patch.object(psutil, "process_iter",
                          side_effect=psutil.AccessDenied(pid=0)):
            assert api._client_process_running("claude") is False

    def test_client_installed_codex_true_when_on_path(self):
        with patch("shutil.which", return_value="/usr/local/bin/codex"):
            assert api._client_installed("codex") is True

    def test_client_installed_codex_false_when_absent(self):
        with patch("shutil.which", return_value=None):
            assert api._client_installed("codex") is False

    def test_client_installed_claude_true_when_on_path(self):
        with patch("shutil.which", return_value="/usr/local/bin/claude"), \
             patch("os.path.exists", return_value=False):
            assert api._client_installed("claude") is True

    def test_client_installed_opencode_false_when_absent(self):
        with patch("shutil.which", return_value=None), \
             patch("os.path.exists", return_value=False):
            assert api._client_installed("opencode") is False

    def test_client_installed_unknown_returns_false(self):
        assert api._client_installed("vim") is False

    def test_detect_reads_client_from_session_json(self, sandbox_smith_files, tmp_path):
        # Step 1: client stored in session.json at scan start takes priority
        import json as _json
        session_file = tmp_path / "session.json"
        session_file.write_text(_json.dumps({"client": "opencode"}))
        with patch.object(api, "_SESSION_FILE", session_file), \
             patch.object(api, "_client_installed", return_value=True):
            assert api._detect_active_client() == "opencode"


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
# _spawn_smith unit tests
# ---------------------------------------------------------------------------

class TestSpawnSmith:
    """Unit tests for _spawn_smith — the core spawn logic.

    Every external side-effect is mocked so no real subprocess fires.
    The key invariant: the function must succeed (return True, pid) even
    when the logs/ directory already exists — that was the bug fixed by
    switching from run_in_executor(None, mkdir, True, True) to a lambda
    that passes parents=True, exist_ok=True by keyword.
    """

    @pytest.fixture
    def spawn_env(self, tmp_path, monkeypatch):
        """Sandbox all file paths and mock every external call."""
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()  # pre-create so exist_ok=True is actually exercised

        monkeypatch.setattr(api, "_SMITH_PID_FILE", logs_dir / "smith.pid")
        monkeypatch.setattr(api, "_SMITH_CLIENT_FILE", logs_dir / "smith.client")
        monkeypatch.setattr(api, "_REPO_ROOT", tmp_path)

        # Steering queue — return no active directives
        steering_mock = MagicMock()
        steering_mock.get_active.return_value = []
        steering_module = MagicMock()
        steering_module.steering_queue = steering_mock

        # Session — no active scan, so no intervention to resolve
        session_mock = MagicMock()
        session_mock.get.return_value = {}

        return {
            "tmp_path": tmp_path,
            "logs_dir": logs_dir,
            "steering_module": steering_module,
            "session_mock": session_mock,
        }

    def test_succeeds_when_logs_dir_already_exists(self, spawn_env):
        """mkdir must not raise FileExistsError when logs/ is present."""
        env = spawn_env
        fake_proc = MagicMock()
        fake_proc.pid = 12321

        with patch.dict("sys.modules", {"core.steering": env["steering_module"]}), \
             patch("core.session.load_from_disk"), \
             patch("core.session.get", return_value={}), \
             patch("os.path.exists", return_value=True), \
             patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=fake_proc)), \
             patch("shutil.which", return_value="/usr/bin/claude"):
            ok, result = asyncio.get_event_loop().run_until_complete(
                api._spawn_smith("claude", source="test")
            )

        assert ok is True
        assert result == 12321

    def test_returns_error_when_binary_missing(self, spawn_env):
        """Returns (False, 'binary not found') when the client binary is absent."""
        env = spawn_env

        with patch.dict("sys.modules", {"core.steering": env["steering_module"]}), \
             patch("core.session.load_from_disk"), \
             patch("core.session.get", return_value={}), \
             patch("shutil.which", return_value=None):
            ok, result = asyncio.get_event_loop().run_until_complete(
                api._spawn_smith("claude", source="test")
            )

        assert ok is False
        assert "not found" in result

    def test_no_hardcoded_homebrew_fallback(self, spawn_env):
        """The old code fell back to /opt/homebrew/bin/claude when shutil.which
        returned None; that broke on Linux/Windows. Verify we now fail cleanly
        instead of trying a non-existent path."""
        env = spawn_env

        # shutil.which returns None — must NOT silently substitute homebrew path
        with patch.dict("sys.modules", {"core.steering": env["steering_module"]}), \
             patch("core.session.load_from_disk"), \
             patch("core.session.get", return_value={}), \
             patch("shutil.which", return_value=None), \
             patch("asyncio.create_subprocess_exec") as spawn:
            ok, result = asyncio.get_event_loop().run_until_complete(
                api._spawn_smith("claude", source="test")
            )

        assert ok is False
        # subprocess should NEVER be called when the binary is missing
        spawn.assert_not_called()

    def test_posix_uses_start_new_session(self, spawn_env):
        """On macOS/Linux _spawn_smith must pass start_new_session=True to
        detach the child from the dashboard's process group."""
        env = spawn_env
        fake_proc = MagicMock(); fake_proc.pid = 11111
        spawn_calls: list = []

        async def _record_spawn(*args, **kw):
            spawn_calls.append(kw)
            return fake_proc

        with patch.dict("sys.modules", {"core.steering": env["steering_module"]}), \
             patch("core.session.load_from_disk"), \
             patch("core.session.get", return_value={}), \
             patch("shutil.which", return_value="/usr/local/bin/opencode"), \
             patch("sys.platform", "linux"), \
             patch("asyncio.create_subprocess_exec", side_effect=_record_spawn):
            ok, _ = asyncio.get_event_loop().run_until_complete(
                api._spawn_smith("opencode", source="test")
            )

        assert ok is True
        assert spawn_calls[0].get("start_new_session") is True
        assert "creationflags" not in spawn_calls[0]

    def test_windows_uses_create_new_process_group(self, spawn_env):
        """On Windows _spawn_smith must use CREATE_NEW_PROCESS_GROUP instead
        of start_new_session (the latter raises ValueError on Windows
        asyncio's ProactorEventLoop)."""
        env = spawn_env
        fake_proc = MagicMock(); fake_proc.pid = 22222
        spawn_calls: list = []

        async def _record_spawn(*args, **kw):
            spawn_calls.append(kw)
            return fake_proc

        with patch.dict("sys.modules", {"core.steering": env["steering_module"]}), \
             patch("core.session.load_from_disk"), \
             patch("core.session.get", return_value={}), \
             patch("shutil.which", return_value="C:\\opencode\\opencode.exe"), \
             patch("sys.platform", "win32"), \
             patch("asyncio.create_subprocess_exec", side_effect=_record_spawn):
            ok, _ = asyncio.get_event_loop().run_until_complete(
                api._spawn_smith("opencode", source="test")
            )

        assert ok is True
        # On Windows: creationflags must be set, start_new_session must NOT be.
        # Use the documented Win32 constant value (0x00000200) since
        # subprocess.CREATE_NEW_PROCESS_GROUP only exists on Windows builds
        # of CPython — the api_server.py code also falls back to the same
        # literal so cross-platform CI works.
        assert "start_new_session" not in spawn_calls[0]
        import subprocess as _sp
        expected = getattr(_sp, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
        assert spawn_calls[0].get("creationflags") == expected

    def test_opencode_spawn_uses_dangerously_skip_permissions(self, spawn_env):
        """Background-spawned opencode has no controlling TTY, so any permission
        prompt either hangs forever or exits the process. The auto-restart
        loop is non-functional for opencode without this flag — same reason
        the claude branch already passes its own --dangerously-skip-permissions.
        Pin the flag here so a refactor doesn't silently lose it."""
        env = spawn_env
        fake_proc = MagicMock(); fake_proc.pid = 33333
        captured_args: list = []

        async def _record_spawn(*args, **kw):
            captured_args.append(list(args))
            return fake_proc

        with patch.dict("sys.modules", {"core.steering": env["steering_module"]}), \
             patch("core.session.load_from_disk"), \
             patch("core.session.get", return_value={}), \
             patch("shutil.which", return_value="/usr/local/bin/opencode"), \
             patch("asyncio.create_subprocess_exec", side_effect=_record_spawn):
            ok, _ = asyncio.get_event_loop().run_until_complete(
                api._spawn_smith("opencode", source="test")
            )

        assert ok is True
        argv = captured_args[0]
        assert argv[0] == "/usr/local/bin/opencode"
        assert "run" in argv
        assert "--dangerously-skip-permissions" in argv, (
            "opencode background spawn must include --dangerously-skip-permissions "
            "or the watchdog loop is non-functional (detached child has no TTY)"
        )
        # The prompt comes after the flag; the flag must precede the prompt
        # so opencode parses it as a flag, not as part of the message.
        flag_idx   = argv.index("--dangerously-skip-permissions")
        prompt_idx = len(argv) - 1
        assert flag_idx < prompt_idx, "flag must come before the message argument"

    def test_claude_spawn_keeps_dangerously_skip_permissions(self, spawn_env):
        """Sanity: don't accidentally break claude when touching the spawn path."""
        env = spawn_env
        fake_proc = MagicMock(); fake_proc.pid = 44444
        captured_args: list = []

        async def _record_spawn(*args, **kw):
            captured_args.append(list(args))
            return fake_proc

        with patch.dict("sys.modules", {"core.steering": env["steering_module"]}), \
             patch("core.session.load_from_disk"), \
             patch("core.session.get", return_value={}), \
             patch("shutil.which", return_value="/opt/homebrew/bin/claude"), \
             patch("asyncio.create_subprocess_exec", side_effect=_record_spawn):
            ok, _ = asyncio.get_event_loop().run_until_complete(
                api._spawn_smith("claude", source="test")
            )

        assert ok is True
        argv = captured_args[0]
        assert "--dangerously-skip-permissions" in argv


# ---------------------------------------------------------------------------
# _pid_alive — cross-platform liveness probe
# ---------------------------------------------------------------------------

class TestPidAlive:

    def test_alive_returns_true_for_running_process(self):
        import os as _os
        with patch("psutil.pid_exists", return_value=True):
            assert api._pid_alive(_os.getpid()) is True

    def test_alive_returns_false_for_dead_process(self):
        with patch("psutil.pid_exists", return_value=False):
            assert api._pid_alive(9999999) is False

    def test_alive_returns_false_when_psutil_missing(self):
        """If psutil import fails (shouldn't happen given it's a dep) we
        must return False rather than crash the watchdog."""
        import builtins
        real_import = builtins.__import__

        def _no_psutil(name, *a, **kw):
            if name == "psutil":
                raise ImportError("psutil unavailable")
            return real_import(name, *a, **kw)

        with patch("builtins.__import__", side_effect=_no_psutil):
            assert api._pid_alive(1) is False


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


# ---------------------------------------------------------------------------
# Watchdog → notifier wiring
#
# The user wants out-of-band alerts (Telegram/Slack/Discord) when the
# watchdog observes a stuck-scan state, not just dashboard logs. Three
# distinct conditions each get their own code so the BaseNotifier 30-min
# dedup suppresses repeats per condition rather than across conditions.
# ---------------------------------------------------------------------------

class TestWatchdogNotifies:

    def setup_method(self):
        # Module-level state leaks between watchdog tests if we don't reset
        # it. _watchdog_last_restart_ts in particular would otherwise trip
        # the MIN_GAP guard and bail before the cap / spawn paths we're
        # actually asserting on here.
        api._watchdog_last_restart_ts = 0.0
        api._watchdog_restart_count_window.clear()

    def teardown_method(self):
        api._watchdog_last_restart_ts = 0.0
        api._watchdog_restart_count_window.clear()

    def _run_tick(self, now=9999.0):
        asyncio.run(api._watchdog_tick(now))

    def test_notifies_when_smith_stopped_with_scan_running(self, sandbox_session):
        """The case the operator asked for: scan still running but Smith died."""
        _write_session(sandbox_session, status="running")
        sent: list[dict] = []

        def _capture(title, body, **kw):
            sent.append({"title": title, "body": body, **kw})

        with patch.object(api, "_smith_running", return_value=False), \
             patch.object(api, "_mcp_sse_alive", return_value=True), \
             patch.object(api, "_spawn_smith", AsyncMock(return_value=(True, 12345))), \
             patch("core.notifiers.notify", _capture):
            self._run_tick()

        # First notify must be the smith-stopped one — it fires before the
        # MCP / gap / cap guards so the most actionable case is never silent.
        assert sent, "watchdog should have notified"
        first = sent[0]
        assert first["code"] == "WATCHDOG_SMITH_STOPPED"
        assert first["urgency"] == "high"
        assert "scan" in first["body"].lower()

    def test_notifies_when_mcp_is_down(self, sandbox_session):
        """If MCP is unreachable, watchdog can't restart — operator needs to know."""
        _write_session(sandbox_session, status="running")
        sent: list[dict] = []

        def _capture(title, body, **kw):
            sent.append({"title": title, "body": body, **kw})

        with patch.object(api, "_smith_running", return_value=False), \
             patch.object(api, "_mcp_sse_alive", return_value=False), \
             patch.object(api, "_spawn_smith", AsyncMock()) as spawn, \
             patch("core.notifiers.notify", _capture):
            self._run_tick()

        # Both the generic "smith stopped" and the MCP-down notice should fire,
        # since the MCP guard suppresses the restart but the underlying
        # condition (smith dead while scan running) is still true.
        codes = [s["code"] for s in sent]
        assert "WATCHDOG_SMITH_STOPPED" in codes
        assert "WATCHDOG_MCP_DOWN" in codes
        # No restart attempted while MCP is dead.
        spawn.assert_not_awaited()

    def test_notifies_when_respawn_cap_reached(self, sandbox_session):
        """Watchdog gave up after too many restarts — escalate via notifier."""
        _write_session(sandbox_session, status="running")
        sent: list[dict] = []

        def _capture(title, body, **kw):
            sent.append({"title": title, "body": body, **kw})

        now = 9999.0
        api._watchdog_restart_count_window[:] = [now - 10] * api._WATCHDOG_MAX_PER_HOUR
        with patch.object(api, "_smith_running", return_value=False), \
             patch.object(api, "_mcp_sse_alive", return_value=True), \
             patch.object(api, "_spawn_smith", AsyncMock()) as spawn, \
             patch("core.notifiers.notify", _capture):
            self._run_tick(now=now)

        codes = [s["code"] for s in sent]
        assert "WATCHDOG_RESPAWN_CAP" in codes
        # The cap-hit notification carries the actual count and the cap
        # so the operator can tell at a glance what gave up.
        cap_msg = next(s for s in sent if s["code"] == "WATCHDOG_RESPAWN_CAP")
        assert str(api._WATCHDOG_MAX_PER_HOUR) in cap_msg["body"]
        spawn.assert_not_awaited()
        api._watchdog_restart_count_window.clear()

    def test_no_notify_when_scan_not_running(self, sandbox_session):
        """No active scan → no out-of-band noise, even if Smith is dead."""
        _write_session(sandbox_session, status="complete")
        sent: list[dict] = []

        def _capture(title, body, **kw):
            sent.append(title)

        with patch.object(api, "_smith_running", return_value=False), \
             patch("core.notifiers.notify", _capture):
            self._run_tick()

        assert sent == []

    def test_no_notify_when_intervention_active(self, sandbox_session):
        """When an HIR is active the operator already saw an alert for IT —
        we don't pile a watchdog ping on top of an unresolved intervention."""
        _write_session(sandbox_session, status="running",
                       intervention={"code": "HIR_AUTH_FAILURE", "situation": "."})
        sent: list[dict] = []

        def _capture(title, body, **kw):
            sent.append(title)

        with patch.object(api, "_smith_running", return_value=False), \
             patch("core.notifiers.notify", _capture):
            self._run_tick()

        assert sent == []

    def test_notify_failure_does_not_break_watchdog(self, sandbox_session):
        """A broken notifier must never short-circuit the restart logic.

        This is the never-raise contract that BaseNotifier already enforces,
        but the watchdog has its own try/except wrappers — verify they hold
        even when notify() itself blows up before delivery scheduling."""
        _write_session(sandbox_session, status="running")

        def _explode(*a, **kw):
            raise RuntimeError("notifier registry is on fire")

        spawn = AsyncMock(return_value=(True, 12345))
        with patch.object(api, "_smith_running", return_value=False), \
             patch.object(api, "_mcp_sse_alive", return_value=True), \
             patch.object(api, "_spawn_smith", spawn), \
             patch("core.notifiers.notify", _explode):
            # Must not raise.
            self._run_tick()

        # And the restart still happened despite the notify explosion.
        spawn.assert_awaited_once()
