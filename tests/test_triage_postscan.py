"""
Tests for the post-scan triage flow + cross-platform MCP SSE self-heal.

Covers the new code in this PR that was previously untested (the bulk of the
new-code coverage gap):

  • POST /api/triage          — now allowed on a STOPPED scan; (re)spawns Smith,
                                wording branches terminal vs running.
  • POST /api/triage-cancel   — clears the in-flight pass + directives.
  • GET  /api/session         — triage self-heal (clears flag at 0 pending,
                                advances the stall clock otherwise).
  • GET  /api/adjudication-log
  • smith._ensure_mcp_sse_alive — watchdog self-heal for the SSE daemon.

Patterns mirror test_api_smith_endpoints.py: TestClient(app), a tmp_path
session sandbox, and every subprocess / steering side-effect mocked.
"""
import json
import time
from unittest.mock import patch, AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

import core.api_server as api
from core.api_server import app
from core.api_server import smith as smith_mod
import core.session as scan_session

client = TestClient(app)


@pytest.fixture
def sandbox_session(tmp_path, monkeypatch):
    session_file = tmp_path / "session.json"
    monkeypatch.setattr(scan_session, "_SESSION_FILE", session_file)
    monkeypatch.setattr(api, "_SESSION_FILE", session_file)
    scan_session._current = None
    yield session_file
    scan_session._current = None


def _write_session(session_file, **overrides):
    data = {"target": "http://x.test", "status": "running", "intervention": None}
    data.update(overrides)
    session_file.write_text(json.dumps(data))


# ---------------------------------------------------------------------------
# POST /api/triage
# ---------------------------------------------------------------------------

class TestApiTriage:

    def test_nothing_to_triage_when_no_pending(self, sandbox_session):
        _write_session(sandbox_session, status="complete")
        with patch("core.adjunction.pending_findings", return_value=[]):
            r = client.post("/api/triage", json={})
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True
        assert body["status"] == "nothing_to_triage"

    def test_409_when_no_scan_to_triage(self, sandbox_session):
        # Pending findings exist but the session has no target → nothing to triage.
        sandbox_session.write_text(json.dumps({"status": "complete"}))  # no target
        with patch("core.adjunction.pending_findings", return_value=[{"id": "F1"}]):
            r = client.post("/api/triage", json={})
        assert r.status_code == 409
        assert "no scan" in r.json()["error"]

    def test_terminal_scan_triggers_triage_and_spawns_smith(self, sandbox_session):
        _write_session(sandbox_session, status="complete")
        q = MagicMock()
        with patch("core.adjunction.pending_findings", return_value=[{"id": "F1"}]), \
             patch("core.adjunction.directive.build_adjudication_directive",
                   return_value="ADJUDICATE F1"), \
             patch("core.adjunction.log.log_directive"), \
             patch("core.steering.steering_queue", q), \
             patch.object(api, "_ERR_REQUEST_FAILED", "err"), \
             patch("core.api_server.routes._wake_smith_if_idle",
                   new=AsyncMock(return_value=True)):
            r = client.post("/api/triage", json={})
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "triaging"
        assert body["smith_spawned"] is True
        # Directive queued, and on a STOPPED scan the wording says STOP afterwards.
        q.add_directive.assert_called_once()
        msg = q.add_directive.call_args.kwargs["message"]
        assert "STOPPED scan" in msg and "STOP" in msg
        assert "resume normal testing" not in msg
        # Flag persisted on the (terminal) session — the bug we fixed.
        on_disk = json.loads(sandbox_session.read_text())
        assert on_disk.get("triage_requested") is True

    def test_returns_500_on_unexpected_error(self, sandbox_session):
        _write_session(sandbox_session, status="complete")
        with patch("core.adjunction.pending_findings", return_value=[{"id": "F1"}]), \
             patch("core.session.set_triage_requested", side_effect=RuntimeError("boom")):
            r = client.post("/api/triage", json={})
        assert r.status_code == 500
        assert r.json()["ok"] is False

    def test_running_scan_keeps_resume_wording(self, sandbox_session):
        _write_session(sandbox_session, status="running")
        q = MagicMock()
        with patch("core.adjunction.pending_findings", return_value=[{"id": "F1"}]), \
             patch("core.adjunction.directive.build_adjudication_directive",
                   return_value="ADJUDICATE F1"), \
             patch("core.adjunction.log.log_directive"), \
             patch("core.steering.steering_queue", q), \
             patch("core.api_server.routes._wake_smith_if_idle",
                   new=AsyncMock(return_value=False)):
            r = client.post("/api/triage", json={})
        assert r.status_code == 200
        msg = q.add_directive.call_args.kwargs["message"]
        assert "resume normal testing" in msg


# ---------------------------------------------------------------------------
# POST /api/triage-cancel
# ---------------------------------------------------------------------------

class TestApiTriageCancel:

    def test_clears_flag_and_counts_removed_directives(self, sandbox_session):
        _write_session(sandbox_session, status="complete", triage_requested=True)
        q = MagicMock()
        q.cancel_by_trigger.side_effect = [2, 1]  # TRIAGE_ADJUDICATION, FORCE_COMPLETE_*
        with patch("core.steering.steering_queue", q):
            r = client.post("/api/triage-cancel")
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True
        assert body["removed_directives"] == 3
        on_disk = json.loads(sandbox_session.read_text())
        assert not on_disk.get("triage_requested")

    def test_returns_500_on_unexpected_error(self, sandbox_session):
        _write_session(sandbox_session, status="complete", triage_requested=True)
        with patch("core.session.set_triage_requested", side_effect=RuntimeError("boom")):
            r = client.post("/api/triage-cancel")
        assert r.status_code == 500
        assert r.json()["ok"] is False


# ---------------------------------------------------------------------------
# GET /api/session — triage self-heal
# ---------------------------------------------------------------------------

class TestApiSessionTriageSelfHeal:

    def test_clears_flag_when_no_pending(self, sandbox_session):
        _write_session(sandbox_session, status="complete", triage_requested=True)
        q = MagicMock()
        with patch("core.adjunction.pending_findings", return_value=[]), \
             patch("core.steering.steering_queue", q):
            r = client.get("/api/session")
        assert r.status_code == 200
        # pending hit 0 → flag self-heals off and the directive is cancelled.
        on_disk = json.loads(sandbox_session.read_text())
        assert not on_disk.get("triage_requested")
        q.cancel_by_trigger.assert_called_once()

    def test_exposes_pending_count_and_idle_clock_while_in_flight(self, sandbox_session):
        _write_session(sandbox_session, status="complete", triage_requested=True)
        with patch("core.adjunction.pending_findings", return_value=[{"id": "F1"}, {"id": "F2"}]):
            r = client.get("/api/session")
        body = r.json()
        assert body["pending_adjudication"] == 2
        assert "triage_idle_s" in body


# ---------------------------------------------------------------------------
# _wake_smith_if_idle — (re)spawn a fresh Smith for the triage pass
# ---------------------------------------------------------------------------

class TestWakeSmithIfIdle:

    @pytest.mark.asyncio
    async def test_abstains_when_smith_already_alive(self):
        from core.api_server.routes import _wake_smith_if_idle
        with patch.object(api, "_signal_pid_file_alive", return_value=True), \
             patch.object(api, "_spawn_smith", new_callable=AsyncMock) as spawn:
            assert await _wake_smith_if_idle() is False
        spawn.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_spawns_when_idle_and_client_installed(self):
        from core.api_server.routes import _wake_smith_if_idle
        with patch.object(api, "_signal_pid_file_alive", return_value=False), \
             patch.object(api, "_signal_process_scan_finds_client", return_value=False), \
             patch.object(api, "_detect_active_client", return_value="claude"), \
             patch.object(api, "_client_installed", return_value=True), \
             patch.object(api, "_spawn_smith",
                          new=AsyncMock(return_value=(True, 4242))) as spawn:
            assert await _wake_smith_if_idle() is True
        spawn.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_false_on_spawn_error(self):
        from core.api_server.routes import _wake_smith_if_idle
        with patch.object(api, "_signal_pid_file_alive", side_effect=RuntimeError("boom")):
            assert await _wake_smith_if_idle() is False


# ---------------------------------------------------------------------------
# GET /api/adjudication-log
# ---------------------------------------------------------------------------

class TestApiAdjudicationLog:

    def test_returns_log_entries(self, sandbox_session):
        with patch("core.adjunction.log.read_all", return_value=[{"finding_id": "F1"}]):
            r = client.get("/api/adjudication-log")
        assert r.status_code == 200
        assert r.json() == [{"finding_id": "F1"}]

    def test_returns_empty_list_on_error(self, sandbox_session):
        with patch("core.adjunction.log.read_all", side_effect=RuntimeError("boom")):
            r = client.get("/api/adjudication-log")
        assert r.status_code == 200
        assert r.json() == []


# ---------------------------------------------------------------------------
# smith._ensure_mcp_sse_alive — cross-platform SSE self-heal
# ---------------------------------------------------------------------------

class TestEnsureMcpSseAlive:

    @pytest.fixture(autouse=True)
    def _reset_throttle(self, monkeypatch):
        # The restart throttle is a module global; reset so each test starts clean.
        monkeypatch.setattr(smith_mod, "_mcp_sse_last_restart_ts", 0.0)

    @pytest.mark.asyncio
    async def test_noop_when_alive(self):
        with patch.object(smith_mod, "_mcp_sse_alive", return_value=True), \
             patch("asyncio.create_subprocess_exec") as spawn:
            await api._ensure_mcp_sse_alive(time.time())
        spawn.assert_not_called()

    @pytest.mark.asyncio
    async def test_throttled_when_recently_restarted(self, monkeypatch):
        now = 1000.0
        monkeypatch.setattr(smith_mod, "_mcp_sse_last_restart_ts", now - 5)  # 5s ago < 30s gap
        with patch.object(smith_mod, "_mcp_sse_alive", return_value=False), \
             patch("asyncio.create_subprocess_exec") as spawn:
            await api._ensure_mcp_sse_alive(now)
        spawn.assert_not_called()

    @pytest.mark.asyncio
    async def test_restarts_daemon_when_down(self, tmp_path, monkeypatch):
        # Provide a real launcher path so launcher.exists() is True.
        (tmp_path / "installers").mkdir()
        (tmp_path / "installers" / "start-mcp-server.sh").write_text("#!/bin/sh\n")
        monkeypatch.setattr(api, "_REPO_ROOT", tmp_path)
        # Down on the pre-check, up after the restart.
        alive_seq = iter([False, True])
        proc = MagicMock()
        proc.wait = AsyncMock(return_value=0)
        with patch.object(smith_mod, "_mcp_sse_alive", side_effect=lambda: next(alive_seq)), \
             patch("asyncio.create_subprocess_exec",
                   new=AsyncMock(return_value=proc)) as spawn, \
             patch("core.notifiers.notify"):
            await api._ensure_mcp_sse_alive(time.time())
        spawn.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_no_restart_when_launcher_missing(self, tmp_path, monkeypatch):
        monkeypatch.setattr(api, "_REPO_ROOT", tmp_path)  # no installers/ dir
        with patch.object(smith_mod, "_mcp_sse_alive", return_value=False), \
             patch("asyncio.create_subprocess_exec") as spawn:
            await api._ensure_mcp_sse_alive(time.time())
        spawn.assert_not_called()
