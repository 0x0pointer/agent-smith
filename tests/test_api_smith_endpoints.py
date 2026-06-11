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
    """Quick-log + smith.pid + smith.client + session paths in tmp_path.

    Also stubs ``psutil.process_iter`` to return an empty list by default
    so the process-scan fallback signal in ``_smith_running()`` can't
    false-positive on whatever the host is running while tests execute
    (the user observed transient failures from their own opencode/claude
    diagnostic processes matching the SMITH_PROC needles during a full
    suite run). Tests that specifically exercise the process-scan path
    override this patch with their own ``patch.object(psutil, ...)``."""
    monkeypatch.setattr(api, "_QUICK_LOG_FILE", tmp_path / "quick_log.json")
    monkeypatch.setattr(api, "_SMITH_PID_FILE", tmp_path / "smith.pid")
    monkeypatch.setattr(api, "_SMITH_CLIENT_FILE", tmp_path / "smith.client")
    monkeypatch.setattr(api, "_SESSION_FILE", tmp_path / "session.json")
    import psutil
    monkeypatch.setattr(psutil, "process_iter", lambda *_a, **_kw: iter([]))


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

    def test_wipes_stale_smith_pointers_on_complete(self, sandbox_session, tmp_path, monkeypatch):
        """Mirror Clear All's cleanup: pressing Complete should remove the
        scan-tied operational files so the dashboard immediately reflects
        "smith: stopped" instead of waiting 5 min for the activity signal
        to age out from a stale quick_log mtime. The user-reported sequence
        was: kill Smith → click Complete → dashboard kept showing "smith
        running" because quick_log was 60s old (still within the 300s window)
        and smith.pid still pointed at the dead PID."""
        _write_session(sandbox_session, status="running")

        # Sandbox the operational-pointer files
        smith_pid_file    = tmp_path / "smith.pid"
        smith_client_file = tmp_path / "smith.client"
        quick_log_file    = tmp_path / "quick_log.json"
        smith_pid_file.write_text("99337\n")
        smith_client_file.write_text("opencode\n")
        quick_log_file.write_text('{"type":"tool_result"}\n')
        monkeypatch.setattr(api, "_SMITH_PID_FILE",   smith_pid_file)
        monkeypatch.setattr(api, "_SMITH_CLIENT_FILE", smith_client_file)
        monkeypatch.setattr(api, "_QUICK_LOG_FILE",   quick_log_file)

        r = client.post("/api/complete", json={"notes": "ok"})
        assert r.status_code == 200
        assert r.json()["ok"] is True
        assert not smith_pid_file.exists(), \
            "smith.pid (stale dead PID) should be removed by Complete"
        assert not smith_client_file.exists(), \
            "smith.client (stale client identifier) should be removed by Complete"
        assert not quick_log_file.exists(), \
            "quick_log.json (heartbeat) should be removed so dashboard immediately shows smith stopped"

    def test_deliverables_preserved_on_complete(self, sandbox_session, tmp_path, monkeypatch):
        """The Clear All button is for fresh-slate cleanup; Complete is for
        wrapping up a scan whose findings the operator wants to export.
        Findings, coverage, artifacts, pocs, and pentest.log must NOT be
        touched — those are the report you'd export from."""
        _write_session(sandbox_session, status="running")

        # Drop dummy deliverable files; Complete must leave them alone
        findings_file = tmp_path / "findings.json"
        coverage_file = tmp_path / "coverage_matrix.json"
        artifacts_dir = tmp_path / "artifacts"
        pocs_dir      = tmp_path / "pocs"
        pentest_log   = tmp_path / "logs" / "pentest.log"
        for d in (artifacts_dir, pocs_dir, pentest_log.parent):
            d.mkdir(parents=True, exist_ok=True)
        findings_file.write_text(json.dumps({"findings": [{"id": "F1"}]}))
        coverage_file.write_text(json.dumps({"endpoints": [{"id": "ep1"}]}))
        (artifacts_dir / "a.txt").write_text("evidence")
        (pocs_dir / "p.http").write_text("POST /x HTTP/1.1")
        pentest_log.write_text("[scan log line]\n")

        r = client.post("/api/complete", json={"notes": "done"})
        assert r.status_code == 200
        # Deliverables intact
        assert findings_file.exists() and findings_file.read_text() != ""
        assert coverage_file.exists()
        assert (artifacts_dir / "a.txt").exists()
        assert (pocs_dir / "p.http").exists()
        assert pentest_log.exists() and "[scan log line]" in pentest_log.read_text()


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

    def test_idle_window_tolerates_thinking_mode_pauses(self, sandbox_smith_files, tmp_path):
        """Qwen3.6-A3B thinking-mode regularly spends 2-3 min between tool calls.
        The 60s threshold previously fired false positives during those pauses;
        300s catches real Smith deaths within 5 min while tolerating long
        internal reasoning blocks."""
        ql = tmp_path / "quick_log.json"
        ql.write_text("{}\n")
        # Push mtime back 4 minutes — well past the old 60s threshold, well
        # under the new 300s threshold.
        import os as _os
        old_mtime = time.time() - 240
        _os.utime(ql, (old_mtime, old_mtime))
        # No PID file, no process scan needed — activity signal alone should
        # decide this case. Patch process_iter to confirm we don't fall to it.
        import psutil
        with patch.object(psutil, "process_iter", return_value=[]):
            assert api._smith_running() is True

    def test_running_true_via_process_scan_when_other_signals_fail(
        self, sandbox_smith_files, tmp_path
    ):
        """Third signal: when smith.pid is stale + quick_log is missing + no
        recent session.started, scanning psutil for a live opencode/claude
        process catches the manual-relaunch case (operator killed dashboard
        spawn, restarted opencode in a terminal, scan continues)."""
        # smith.pid file points at a clearly-dead PID
        (tmp_path / "smith.pid").write_text("99999999\n")
        # quick_log absent → session fallback would normally fire but skip that
        # by also leaving session.json absent so we ISOLATE the process-scan path
        import psutil
        fake = MagicMock()
        fake.info = {"cmdline": ["node", "/Users/u/.opencode/bin/opencode", "run", "scan"]}
        with patch.object(psutil, "pid_exists", return_value=False), \
             patch.object(psutil, "process_iter", return_value=[fake]):
            assert api._smith_running() is True

    def test_running_false_when_process_scan_finds_no_smith_clients(
        self, sandbox_smith_files, tmp_path
    ):
        """Process-scan must not false-positive on unrelated processes like
        the MCP server itself, vLLM, or random terminals."""
        import psutil
        unrelated = [
            MagicMock(info={"cmdline": ["python3", "-m", "mcp_server"]}),
            MagicMock(info={"cmdline": ["vllm", "serve", "--model", "Qwen/x"]}),
            MagicMock(info={"cmdline": ["zsh"]}),
            MagicMock(info={"cmdline": ["/usr/bin/firefox"]}),
        ]
        with patch.object(psutil, "pid_exists", return_value=False), \
             patch.object(psutil, "process_iter", return_value=unrelated):
            assert api._smith_running() is False

    def test_process_scan_matches_dashboard_spawned_claude(
        self, sandbox_smith_files, tmp_path
    ):
        """Dashboard-spawned claude has --dangerously-skip-permissions in cmdline."""
        import psutil
        fake = MagicMock()
        fake.info = {"cmdline": ["/opt/homebrew/bin/claude",
                                  "--dangerously-skip-permissions",
                                  "-p", "Recover the scan ..."]}
        with patch.object(psutil, "pid_exists", return_value=False), \
             patch.object(psutil, "process_iter", return_value=[fake]):
            assert api._smith_running() is True

    def test_process_scan_matches_node_wrapped_opencode(
        self, sandbox_smith_files, tmp_path
    ):
        """When opencode is invoked via `node /path/to/.opencode/bin/opencode`,
        process name is 'node' but cmdline contains the .opencode anchor.
        This is the case the user actually hit — pgrep showed nothing for
        'opencode' literally even though Smith was alive under node."""
        import psutil
        fake = MagicMock()
        fake.info = {"cmdline": ["node", "/Users/gibson/.opencode/bin/opencode",
                                  "run", "--dangerously-skip-permissions", "scan target"]}
        with patch.object(psutil, "pid_exists", return_value=False), \
             patch.object(psutil, "process_iter", return_value=[fake]):
            assert api._smith_running() is True


# ---------------------------------------------------------------------------
# _smith_hung_pid / _kill_hung_smith — hang detection + cleanup
#
# The bug these tests pin down: before the hang-detection layer, a Smith
# process that locked up (process alive, no MCP heartbeat) kept
# _signal_pid_file_alive() and _signal_process_scan_finds_client()
# returning True, which OR'd through _smith_running() and made the
# watchdog believe Smith was healthy. The dashboard showed "smith
# running" for 9+ hours on a frozen opencode while no Telegram alert
# fired and no restart happened. _smith_hung_pid() is the explicit
# probe that says "process exists but quick_log is stale" — exactly the
# alive-but-stuck condition the OR'd _smith_running() can't see.
# ---------------------------------------------------------------------------

class TestSmithHungDetection:

    def test_hung_pid_is_none_when_quick_log_fresh(
        self, sandbox_smith_files, tmp_path,
    ):
        """Fresh quick_log → Smith is progressing; hung-PID probe MUST
        short-circuit to None even if a pid file points at a live PID.
        Otherwise we'd kill a perfectly healthy process mid-tool-call."""
        (tmp_path / "quick_log.json").write_text("{}\n")
        (tmp_path / "smith.pid").write_text("12345\n")
        import psutil
        with patch.object(psutil, "pid_exists", return_value=True):
            assert api._smith_hung_pid() is None

    def test_hung_pid_is_none_in_startup_grace(
        self, sandbox_smith_files, tmp_path,
    ):
        """Session started < 2 h ago + quick_log absent → startup grace.
        We must not declare hang during the spawn → first-tool-call gap."""
        from datetime import datetime, timezone, timedelta
        (tmp_path / "session.json").write_text(json.dumps({
            "status": "running",
            "finished": None,
            "started": (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat(),
        }))
        (tmp_path / "smith.pid").write_text("12345\n")
        import psutil
        with patch.object(psutil, "pid_exists", return_value=True):
            assert api._smith_hung_pid() is None

    def test_hung_pid_returns_live_pid_when_quick_log_stale(
        self, sandbox_smith_files, tmp_path,
    ):
        """The actual bug — pid alive + quick_log stale + session old →
        hang. This is the 9-hour opencode-hung case from the user's report."""
        from datetime import datetime, timezone, timedelta
        ql = tmp_path / "quick_log.json"
        ql.write_text("{}\n")
        import os as _os
        old_mtime = time.time() - 9 * 3600
        _os.utime(ql, (old_mtime, old_mtime))
        (tmp_path / "smith.pid").write_text("32746\n")
        (tmp_path / "session.json").write_text(json.dumps({
            "status": "running",
            "finished": None,
            "started": (datetime.now(timezone.utc) - timedelta(hours=10)).isoformat(),
        }))
        import psutil
        with patch.object(psutil, "pid_exists", return_value=True):
            assert api._smith_hung_pid() == 32746

    def test_hung_pid_falls_through_to_process_scan(
        self, sandbox_smith_files, tmp_path,
    ):
        """Pid file missing, quick_log stale, but a live opencode process
        exists → probe must walk process_iter to find the PID to kill.
        Without this fallback, manually-launched terminal smiths that hang
        can never be auto-recovered."""
        from datetime import datetime, timezone, timedelta
        ql = tmp_path / "quick_log.json"
        ql.write_text("{}\n")
        import os as _os
        old_mtime = time.time() - 9 * 3600
        _os.utime(ql, (old_mtime, old_mtime))
        (tmp_path / "session.json").write_text(json.dumps({
            "status": "running",
            "finished": None,
            "started": (datetime.now(timezone.utc) - timedelta(hours=10)).isoformat(),
        }))
        import psutil
        fake = MagicMock()
        fake.info = {"cmdline": ["node", "/Users/u/.opencode/bin/opencode", "run", "x"],
                     "pid": 99001}
        fake.pid = 99001
        with patch.object(psutil, "pid_exists", return_value=False), \
             patch.object(psutil, "process_iter", return_value=[fake]):
            assert api._smith_hung_pid() == 99001

    def test_hung_pid_returns_none_when_no_process_anywhere(
        self, sandbox_smith_files, tmp_path,
    ):
        """Quick_log stale + session old + NO live process anywhere →
        Smith is genuinely stopped (not hung). Probe returns None so the
        watchdog falls through to the plain "stopped → respawn" path
        rather than try to terminate a phantom PID."""
        from datetime import datetime, timezone, timedelta
        ql = tmp_path / "quick_log.json"
        ql.write_text("{}\n")
        import os as _os
        old_mtime = time.time() - 9 * 3600
        _os.utime(ql, (old_mtime, old_mtime))
        (tmp_path / "session.json").write_text(json.dumps({
            "status": "running",
            "finished": None,
            "started": (datetime.now(timezone.utc) - timedelta(hours=10)).isoformat(),
        }))
        import psutil
        with patch.object(psutil, "pid_exists", return_value=False):
            assert api._smith_hung_pid() is None


class TestKillHungSmith:

    def test_kill_terminates_then_cleans_pointers(
        self, sandbox_smith_files, tmp_path,
    ):
        """SIGTERM path: process responds to terminate within timeout →
        success, and we wipe smith.pid / smith.client so the next
        _smith_running() call doesn't keep reading the freshly-dead PID
        as alive (signal #1's psutil.pid_exists has a brief race window
        before the kernel reclaims)."""
        (tmp_path / "smith.pid").write_text("32746\n")
        (tmp_path / "smith.client").write_text("opencode\n")
        import psutil
        proc = MagicMock()
        proc.wait.return_value = None  # responds to SIGTERM
        with patch.object(psutil, "Process", return_value=proc):
            assert api._kill_hung_smith(32746) is True
        proc.terminate.assert_called_once()
        proc.kill.assert_not_called()
        assert not (tmp_path / "smith.pid").exists()
        assert not (tmp_path / "smith.client").exists()

    def test_kill_escalates_to_sigkill_on_sigterm_timeout(
        self, sandbox_smith_files, tmp_path,
    ):
        """SIGTERM ignored → escalate to SIGKILL. Critical because an
        opencode stuck in a tight Node.js loop won't observe SIGTERM in
        time, and we MUST guarantee the process is gone before the
        watchdog respawns or two MCP clients race on quick_log."""
        (tmp_path / "smith.pid").write_text("32746\n")
        import psutil
        proc = MagicMock()
        # First .wait() (after terminate) times out → escalate
        # Second .wait() (after kill) returns cleanly
        proc.wait.side_effect = [psutil.TimeoutExpired(5), None]
        with patch.object(psutil, "Process", return_value=proc):
            assert api._kill_hung_smith(32746) is True
        proc.terminate.assert_called_once()
        proc.kill.assert_called_once()

    def test_kill_returns_true_when_process_already_gone(
        self, sandbox_smith_files, tmp_path,
    ):
        """Race: process exits between hung-detection and kill attempt.
        psutil.Process raises NoSuchProcess → that's success from our
        POV (the goal was "process not alive"). Pointers still cleaned."""
        (tmp_path / "smith.pid").write_text("32746\n")
        (tmp_path / "smith.client").write_text("opencode\n")
        import psutil
        with patch.object(psutil, "Process", side_effect=psutil.NoSuchProcess(32746)):
            assert api._kill_hung_smith(32746) is True
        assert not (tmp_path / "smith.pid").exists()
        assert not (tmp_path / "smith.client").exists()

    def test_kill_handles_permission_denied_without_crashing(
        self, sandbox_smith_files, tmp_path,
    ):
        """psutil.AccessDenied during terminate → we can't kill the
        process. Returns False (so watchdog knows it didn't recover),
        BUT pointers still get wiped because the pid file is misleading
        either way — leaving it pointing at an un-killable PID would
        keep _signal_pid_file_alive() returning True forever and re-
        trigger hung detection on every tick."""
        (tmp_path / "smith.pid").write_text("32746\n")
        import psutil
        proc = MagicMock()
        proc.terminate.side_effect = psutil.AccessDenied(32746)
        with patch.object(psutil, "Process", return_value=proc):
            assert api._kill_hung_smith(32746) is False
        assert not (tmp_path / "smith.pid").exists()


class TestWatchdogHungIntegration:

    @pytest.fixture(autouse=True)
    def _reset_watchdog_globals(self, monkeypatch):
        """The watchdog tracks last-restart-ts + recent-restart-count in
        module globals so the min-gap and per-hour caps survive across
        watchdog ticks. Tests that successfully drive _spawn_smith mutate
        those globals and bleed into the next test in test_spawns_when_*
        (the min-gap suppression then kicks in and asserts fail). Snapshot
        + restore both globals per-test so each starts from a clean slate."""
        monkeypatch.setattr(api, "_watchdog_last_restart_ts", 0.0)
        monkeypatch.setattr(api, "_watchdog_restart_count_window", [])

    def _stale_log(self, tmp_path, age_seconds: int) -> None:
        import os as _os
        ql = tmp_path / "quick_log.json"
        ql.write_text("{}\n")
        t = time.time() - age_seconds
        _os.utime(ql, (t, t))

    @pytest.mark.asyncio
    async def test_watchdog_kills_hung_smith_then_respawns(
        self, sandbox_smith_files, tmp_path,
    ):
        """End-to-end: scan running + hung process → watchdog (a) fires
        WATCHDOG_SMITH_HUNG, (b) calls _kill_hung_smith, (c) falls
        through to _spawn_smith (not early-return)."""
        from datetime import datetime, timezone, timedelta
        _write_session(tmp_path / "session.json", status="running")
        # Make session "old" so we're past startup grace
        sd = json.loads((tmp_path / "session.json").read_text())
        sd["started"] = (datetime.now(timezone.utc) - timedelta(hours=10)).isoformat()
        sd["finished"] = None
        (tmp_path / "session.json").write_text(json.dumps(sd))
        (tmp_path / "smith.pid").write_text("32746\n")
        self._stale_log(tmp_path, 9 * 3600)

        import psutil
        proc = MagicMock(); proc.wait.return_value = None
        with patch.object(psutil, "pid_exists", return_value=True), \
             patch.object(psutil, "Process", return_value=proc), \
             patch.object(api, "_mcp_sse_alive", return_value=True), \
             patch.object(api, "_spawn_smith",
                          new_callable=AsyncMock,
                          return_value=(True, 99999)) as mock_spawn, \
             patch("core.notifiers.notify") as mock_notify:
            await api._watchdog_tick(time.time())

        proc.terminate.assert_called_once()
        mock_spawn.assert_awaited_once()
        codes_fired = [c.kwargs.get("code") for c in mock_notify.call_args_list]
        assert "WATCHDOG_SMITH_HUNG" in codes_fired

    @pytest.mark.asyncio
    async def test_watchdog_returns_early_when_smith_fresh_and_not_hung(
        self, sandbox_smith_files, tmp_path,
    ):
        """Negative case: quick_log fresh → hung probe returns None →
        _smith_running True → watchdog returns early as before, no
        spawn, no kill, no notification."""
        _write_session(tmp_path / "session.json", status="running")
        (tmp_path / "quick_log.json").write_text("{}\n")  # fresh

        import psutil
        with patch.object(psutil, "pid_exists", return_value=False), \
             patch.object(api, "_spawn_smith",
                          new_callable=AsyncMock) as mock_spawn, \
             patch("core.notifiers.notify") as mock_notify:
            await api._watchdog_tick(time.time())

        mock_spawn.assert_not_called()
        mock_notify.assert_not_called()


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
        # Step 2: top-level client field in session.json (back-compat / legacy
        # sessions before the smith_proc field was added).
        import json as _json
        session_file = tmp_path / "session.json"
        session_file.write_text(_json.dumps({"client": "opencode"}))
        with patch.object(api, "_SESSION_FILE", session_file), \
             patch.object(api, "_client_installed", return_value=True):
            assert api._detect_active_client() == "opencode"

    def test_detect_prefers_scan_locked_smith_proc_client(self, sandbox_smith_files, tmp_path):
        """The scan-lock at session.start() writes smith_proc.client. This
        must take precedence over EVERY other signal so a watchdog restart
        can never drift to a different CLI than the one the operator started
        the scan in."""
        import json as _json
        session_file = tmp_path / "session.json"
        # Even with logs/smith.client saying "claude" AND a running claude
        # process detected, the scan-lock on opencode must win.
        session_file.write_text(_json.dumps({
            "smith_proc": {"pid": 1234, "client": "opencode",
                            "source": "interactive_mcp"},
        }))
        (tmp_path / "smith.client").write_text("claude")   # drift signal
        with patch.object(api, "_SESSION_FILE", session_file), \
             patch.object(api, "_client_installed", return_value=True), \
             patch.object(api, "_client_process_running",
                           side_effect=lambda n: n == "claude"):
            assert api._detect_active_client() == "opencode"

    def test_detect_falls_through_when_scan_locked_client_not_installed(
        self, sandbox_smith_files, tmp_path
    ):
        """If smith_proc.client says opencode but opencode isn't on PATH,
        skip the lock and use the next signal. Prevents a "scan locked to
        client that no longer exists" deadlock."""
        import json as _json
        session_file = tmp_path / "session.json"
        session_file.write_text(_json.dumps({
            "smith_proc": {"pid": 1234, "client": "opencode",
                            "source": "interactive_mcp"},
        }))
        (tmp_path / "smith.client").write_text("claude")
        with patch.object(api, "_SESSION_FILE", session_file), \
             patch.object(api, "_client_installed",
                           side_effect=lambda n: n == "claude"):
            assert api._detect_active_client() == "claude"

    def test_detect_ignores_smith_proc_with_unknown_client(
        self, sandbox_smith_files, tmp_path
    ):
        """A malformed smith_proc.client (typo, future client name we don't
        support) shouldn't deadlock detection — fall through to the legacy
        signals."""
        import json as _json
        session_file = tmp_path / "session.json"
        session_file.write_text(_json.dumps({
            "smith_proc": {"pid": 1234, "client": "klaude",  # typo
                            "source": "interactive_mcp"},
        }))
        (tmp_path / "smith.client").write_text("claude")
        with patch.object(api, "_SESSION_FILE", session_file), \
             patch.object(api, "_client_installed", return_value=True):
            assert api._detect_active_client() == "claude"

    def test_restart_endpoint_client_param_overrides_scan_lock(
        self, sandbox_session, sandbox_smith_files
    ):
        """The Restart Smith button accepts {"client": "..."} which must
        override the scan-lock — operators sometimes need to switch CLI
        mid-scan (e.g. Anthropic credits exhausted → switch to local opencode).
        The scan-lock is for AUTO-restarts; explicit operator input wins."""
        _write_session(sandbox_session, status="running",
                        smith_proc={"pid": 9999, "client": "claude",
                                     "source": "interactive_mcp"})
        with patch.object(api, "_smith_running", return_value=False), \
             patch.object(api, "_client_installed", return_value=True), \
             patch.object(api, "_spawn_smith",
                           new_callable=AsyncMock,
                           return_value=(True, 12345)) as spawn:
            r = client.post("/api/restart-smith", json={"client": "opencode"})
        assert r.status_code == 200
        # spawn was called with the *override*, not the scan-locked "claude"
        called_client = spawn.await_args.args[0]
        assert called_client == "opencode"


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

    def test_spawn_persists_scan_lock_for_watchdog(self, spawn_env):
        """Every successful _spawn_smith must call set_smith_proc() so the
        watchdog's _detect_active_client() sees the scan-locked client on its
        next tick. Without this lock, the watchdog would have to guess via
        logs/smith.client (a global file that drifts across scans)."""
        env = spawn_env
        fake_proc = MagicMock(); fake_proc.pid = 55555
        set_calls: list = []

        async def _record_spawn(*args, **kw):
            return fake_proc

        def _record_set(pid, client, source):
            set_calls.append({"pid": pid, "client": client, "source": source})

        with patch.dict("sys.modules", {"core.steering": env["steering_module"]}), \
             patch("core.session.load_from_disk"), \
             patch("core.session.get", return_value={}), \
             patch("core.session.set_smith_proc", side_effect=_record_set), \
             patch("shutil.which", return_value="/usr/local/bin/opencode"), \
             patch("asyncio.create_subprocess_exec", side_effect=_record_spawn):
            ok, pid = asyncio.get_event_loop().run_until_complete(
                api._spawn_smith("opencode", source="watchdog")
            )

        assert ok is True
        assert len(set_calls) == 1
        assert set_calls[0]["pid"] == 55555
        assert set_calls[0]["client"] == "opencode"
        # source tag distinguishes watchdog from api in audit
        assert set_calls[0]["source"] == "watchdog_spawn"

    def test_spawn_lock_failure_does_not_break_spawn(self, spawn_env):
        """set_smith_proc raising must not turn a successful spawn into a
        failure — the smith.client file write above it is the operational
        backup. Diagnostic only."""
        env = spawn_env
        fake_proc = MagicMock(); fake_proc.pid = 66666

        async def _spawn(*a, **kw): return fake_proc

        with patch.dict("sys.modules", {"core.steering": env["steering_module"]}), \
             patch("core.session.load_from_disk"), \
             patch("core.session.get", return_value={}), \
             patch("core.session.set_smith_proc",
                    side_effect=RuntimeError("disk full")), \
             patch("shutil.which", return_value="/usr/local/bin/opencode"), \
             patch("asyncio.create_subprocess_exec", side_effect=_spawn):
            ok, pid = asyncio.get_event_loop().run_until_complete(
                api._spawn_smith("opencode", source="api")
            )

        assert ok is True
        assert pid == 66666


# ---------------------------------------------------------------------------
# session.set_smith_proc / get_scan_client
# ---------------------------------------------------------------------------

class TestSetSmithProc:
    """The scan-lock writer in core/session.py. Watchdog reads what this
    persists, so it's load-bearing for the "don't drift between CLIs"
    guarantee."""

    @pytest.fixture
    def fresh_session(self, tmp_path, monkeypatch):
        from core import session as scan_session
        monkeypatch.setattr(scan_session, "_REPO_ROOT", tmp_path)
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        scan_session._current = None
        scan_session._last_local_write_mtime = 0.0
        scan_session._last_pid_refresh_attempt = 0.0
        yield tmp_path
        scan_session._current = None
        scan_session._last_local_write_mtime = 0.0
        scan_session._last_pid_refresh_attempt = 0.0

    def test_set_smith_proc_writes_all_fields(self, fresh_session):
        from core import session as scan_session
        scan_session.start(target="http://x.test", depth="quick")
        scan_session.set_smith_proc(pid=4321, client="opencode",
                                     source="dashboard_spawn")
        on_disk = json.loads((fresh_session / "session.json").read_text())
        sp = on_disk["smith_proc"]
        assert sp["pid"] == 4321
        assert sp["client"] == "opencode"
        assert sp["source"] == "dashboard_spawn"
        assert "captured_at" in sp

    def test_set_smith_proc_overwrites_previous_lock(self, fresh_session):
        """Each spawn re-pins; the latest source-tagged value wins. Allows
        the operator to override via Restart Smith button + the scan-lock
        to update on the next spawn."""
        from core import session as scan_session
        scan_session.start(target="http://x.test", depth="quick")
        scan_session.set_smith_proc(pid=1, client="claude",
                                     source="interactive_mcp")
        scan_session.set_smith_proc(pid=2, client="opencode",
                                     source="api_restart")
        on_disk = json.loads((fresh_session / "session.json").read_text())
        assert on_disk["smith_proc"]["client"] == "opencode"
        assert on_disk["smith_proc"]["source"] == "api_restart"

    def test_set_smith_proc_noop_when_no_session(self, fresh_session):
        """No session in memory → silent no-op. Won't crash mid-spawn if
        someone called set_smith_proc out of sequence."""
        from core import session as scan_session
        scan_session._current = None
        scan_session.set_smith_proc(pid=1, client="claude", source="x")
        assert not (fresh_session / "session.json").exists()

    def test_get_scan_client_reads_smith_proc(self, fresh_session):
        from core import session as scan_session
        scan_session.start(target="http://x.test", depth="quick")
        scan_session.set_smith_proc(pid=1, client="opencode",
                                     source="interactive_mcp")
        assert scan_session.get_scan_client() == "opencode"

    def test_get_scan_client_returns_none_for_unknown(self, fresh_session):
        from core import session as scan_session
        scan_session._current = {"smith_proc": {"client": "klaude"}}
        assert scan_session.get_scan_client() is None


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
