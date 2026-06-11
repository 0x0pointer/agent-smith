"""
Tests for changes added on this branch:

  • core.session.load_from_disk(force=True)
  • core.session.resolve_intervention terminal-status guard
  • core.coverage._validate_finding_link
  • core.coverage._validate_auth_response
  • mcp_server.session_tools._do_recovery terminal-status branch
"""
import asyncio
import json
from pathlib import Path
from unittest.mock import patch

import pytest

import core.session as scan_session
from core import coverage as cov


# ---------------------------------------------------------------------------
# core.session.load_from_disk(force=...)
# ---------------------------------------------------------------------------

class TestLoadFromDisk:

    def test_default_does_not_overwrite_loaded_state(self, tmp_path, monkeypatch):
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        scan_session._current = {"status": "running", "marker": "in-memory"}
        (tmp_path / "session.json").write_text('{"status": "complete", "marker": "on-disk"}')
        scan_session.load_from_disk()
        assert scan_session._current["marker"] == "in-memory"

    def test_force_true_always_reloads(self, tmp_path, monkeypatch):
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        scan_session._current = {"status": "running", "marker": "in-memory"}
        (tmp_path / "session.json").write_text('{"status": "complete", "marker": "on-disk"}')
        scan_session.load_from_disk(force=True)
        assert scan_session._current["marker"] == "on-disk"
        scan_session._current = None

    def test_force_with_no_file_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "missing.json")
        scan_session._current = None
        result = scan_session.load_from_disk(force=True)
        assert result is None

    def test_force_swallows_corrupt_json(self, tmp_path, monkeypatch):
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        scan_session._current = {"status": "running", "marker": "in-memory"}
        (tmp_path / "session.json").write_text("not json {{{ broken")
        # No exception even with corrupt data — _current stays as-was.
        scan_session.load_from_disk(force=True)
        assert scan_session._current["marker"] == "in-memory"
        scan_session._current = None

    def test_force_drops_cache_when_disk_deleted_after_local_write(
        self, tmp_path, monkeypatch,
    ):
        """User's reported bug: dashboard's Clear All deletes session.json,
        but the MCP server's _current cache (and prior _last_local_write_mtime
        from when *this* process flushed during the prior scan) stays
        populated. Without deletion detection, the MCP server's next
        session(action='start') reads the cached intervention_required and
        blocks the fresh scan with 'SCAN PAUSED'.

        force=True must mirror disk reality: if file is gone AND we know
        we previously wrote to it (_last_local_write_mtime > 0), drop the
        cache to None to match.
        """
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        # Simulate a prior flush: _current populated, _last_local_write_mtime
        # bumped to "we wrote at time T".
        scan_session._current = {
            "status": "intervention_required",
            "intervention": {"code": "HIR_FORCE_COMPLETE"},
        }
        monkeypatch.setattr(scan_session, "_last_local_write_mtime", 1000.0)
        # Dashboard wipes the file (Clear All). MCP cache is stale.
        # → force-load should now reflect "no session".
        result = scan_session.load_from_disk(force=True)
        assert result is None
        assert scan_session._current is None

    def test_force_preserves_stub_when_disk_never_existed(
        self, tmp_path, monkeypatch,
    ):
        """Test-stub guard: a test that monkeypatches _current without
        ever flushing has _last_local_write_mtime == 0. In that case the
        file's absence is "fresh process, no session yet", not "external
        deletion". Cache must NOT be cleared, or 12 prior unit tests
        (status_reporter, TestResolveInterventionTerminalGuard, ...) break.
        """
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "missing.json")
        scan_session._current = {"status": "running", "marker": "test-stub"}
        # _last_local_write_mtime stays at the fixture's 0.0
        result = scan_session.load_from_disk(force=True)
        assert result == {"status": "running", "marker": "test-stub"}
        assert scan_session._current["marker"] == "test-stub"


# ---------------------------------------------------------------------------
# core.session.resolve_intervention — terminal status guard
# ---------------------------------------------------------------------------

class TestResolveInterventionTerminalGuard:

    @pytest.mark.parametrize("terminal", [
        "complete",
        "incomplete_with_unresolved_blockers",
        "limit_reached",
    ])
    def test_keeps_terminal_status(self, tmp_path, monkeypatch, terminal):
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        scan_session._current = {
            "status": terminal,
            "intervention": {"code": "HIR_TEST", "situation": ""},
            "intervention_history": [],
        }
        scan_session.resolve_intervention("CONTINUE", "human OK")
        assert scan_session._current["status"] == terminal
        # Intervention dict still cleared
        assert scan_session._current["intervention"] is None
        scan_session._current = None

    def test_returns_to_running_from_non_terminal(self, tmp_path, monkeypatch):
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        scan_session._current = {
            "status": "intervention_required",
            "intervention": {"code": "HIR_TEST", "situation": ""},
            "intervention_history": [],
        }
        scan_session.resolve_intervention("REAUTH", "")
        assert scan_session._current["status"] == "running"
        scan_session._current = None

    def test_noop_when_no_current_session(self):
        scan_session._current = None
        result = scan_session.resolve_intervention("X", "")
        assert result == {}


# ---------------------------------------------------------------------------
# core.coverage._validate_finding_link
# ---------------------------------------------------------------------------

class TestValidateFindingLink:

    @pytest.mark.parametrize("status", [
        "tested_clean", "not_applicable", "skipped", "in_progress", "pending",
    ])
    def test_non_vulnerable_passes(self, status):
        assert cov._validate_finding_link(status, None) == ""

    def test_vulnerable_without_finding_id_rejects(self):
        msg = cov._validate_finding_link("vulnerable", None)
        assert "REJECTED" in msg
        assert "report(action=" in msg

    def test_vulnerable_with_blank_finding_id_rejects(self):
        msg = cov._validate_finding_link("vulnerable", "   ")
        assert "REJECTED" in msg

    def test_vulnerable_with_real_id_passes(self):
        assert cov._validate_finding_link("vulnerable", "finding-123") == ""


# ---------------------------------------------------------------------------
# core.coverage._validate_auth_response
# ---------------------------------------------------------------------------

class TestValidateAuthResponse:

    def _seed_artifact(self, tmp_path, monkeypatch, artifact_id: str, status: int):
        monkeypatch.setattr(cov, "_ARTIFACTS_DIR", tmp_path)
        (tmp_path / f"{artifact_id}.txt").write_text(json.dumps({
            "status": status, "body": "", "headers": {},
        }))

    def test_passes_when_status_not_tested_clean(self, tmp_path, monkeypatch):
        self._seed_artifact(tmp_path, monkeypatch, "http_request_x", 401)
        cell = {"id": "c1", "injection_type": "sqli"}
        assert cov._validate_auth_response("http_request_x", "vulnerable", cell) == ""

    def test_passes_when_cell_is_none(self, tmp_path, monkeypatch):
        self._seed_artifact(tmp_path, monkeypatch, "http_request_x", 401)
        assert cov._validate_auth_response("http_request_x", "tested_clean", None) == ""

    def test_passes_for_non_injection_cell_types(self, tmp_path, monkeypatch):
        self._seed_artifact(tmp_path, monkeypatch, "http_request_x", 401)
        # cors / jwt / rate_limit / security_headers cells legitimately use 401
        for inj in ("cors", "jwt", "rate_limit", "security_headers", "auth"):
            cell = {"id": "c", "injection_type": inj}
            assert cov._validate_auth_response("http_request_x", "tested_clean", cell) == ""

    def test_rejects_sqli_clean_on_401(self, tmp_path, monkeypatch):
        self._seed_artifact(tmp_path, monkeypatch, "http_request_x", 401)
        cell = {"id": "c1", "injection_type": "sqli"}
        msg = cov._validate_auth_response("http_request_x", "tested_clean", cell)
        assert "REJECTED" in msg
        assert "HTTP 401" in msg

    def test_rejects_xss_clean_on_403(self, tmp_path, monkeypatch):
        self._seed_artifact(tmp_path, monkeypatch, "http_request_x", 403)
        cell = {"id": "c1", "injection_type": "xss"}
        msg = cov._validate_auth_response("http_request_x", "tested_clean", cell)
        assert "REJECTED" in msg
        assert "HTTP 403" in msg

    def test_passes_when_artifact_shows_200(self, tmp_path, monkeypatch):
        self._seed_artifact(tmp_path, monkeypatch, "http_request_x", 200)
        cell = {"id": "c1", "injection_type": "sqli"}
        assert cov._validate_auth_response("http_request_x", "tested_clean", cell) == ""

    def test_passes_for_non_http_request_artifact(self, tmp_path, monkeypatch):
        # Only http_request_* artifacts are inspected.
        monkeypatch.setattr(cov, "_ARTIFACTS_DIR", tmp_path)
        (tmp_path / "kali_xyz.txt").write_text("nikto raw output")
        cell = {"id": "c1", "injection_type": "sqli"}
        assert cov._validate_auth_response("kali_xyz", "tested_clean", cell) == ""

    def test_handles_missing_artifact_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cov, "_ARTIFACTS_DIR", tmp_path)
        cell = {"id": "c1", "injection_type": "sqli"}
        # _validate_artifact handles the file existence check elsewhere;
        # this branch returns "" early.
        assert cov._validate_auth_response("http_request_missing", "tested_clean", cell) == ""

    def test_handles_corrupt_artifact_json(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cov, "_ARTIFACTS_DIR", tmp_path)
        (tmp_path / "http_request_corrupt.txt").write_text("not-json {{{")
        cell = {"id": "c1", "injection_type": "sqli"}
        assert cov._validate_auth_response("http_request_corrupt", "tested_clean", cell) == ""

    def test_caps_oversized_artifact(self, tmp_path, monkeypatch):
        # Artifact larger than 10 MB ceiling — must short-circuit cleanly.
        monkeypatch.setattr(cov, "_ARTIFACTS_DIR", tmp_path)
        f = tmp_path / "http_request_huge.txt"
        f.write_text("x" * (11 * 1024 * 1024))  # 11 MB
        cell = {"id": "c1", "injection_type": "sqli"}
        assert cov._validate_auth_response("http_request_huge", "tested_clean", cell) == ""


# ---------------------------------------------------------------------------
# update_cell + bulk_update + _validate_finding_link integration
# ---------------------------------------------------------------------------

class TestCoverageValidatorIntegration:
    """End-to-end check that the validator is actually wired into the
    update_cell + bulk_update paths."""

    def _make_artifact(self, tool: str = "sqlmap") -> str:
        import uuid
        artifact_id = f"{tool}-{uuid.uuid4().hex[:8]}"
        (cov._ARTIFACTS_DIR / f"{artifact_id}.txt").write_text("test output")
        return artifact_id

    @pytest.fixture(autouse=True)
    def _isolate_coverage(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cov, "COVERAGE_FILE", tmp_path / "coverage_matrix.json")
        monkeypatch.setattr(cov, "_ARTIFACTS_DIR", tmp_path / "artifacts")
        (tmp_path / "artifacts").mkdir()
        yield

    @pytest.mark.asyncio
    async def test_update_cell_rejects_vulnerable_without_finding_id(self):
        await cov.add_endpoint(
            path="/login", method="POST",
            params=[{"name": "user", "type": "body_form", "value_hint": ""}],
        )
        data = json.loads(cov.COVERAGE_FILE.read_text())
        sqli = next(c for c in data["matrix"] if c["injection_type"] == "sqli")
        result = await cov.update_cell(
            sqli["id"], "vulnerable",
            artifact_id=self._make_artifact(), notes="SQLi via user",
        )
        assert isinstance(result, str) and "REJECTED" in result
        # Cell state should not have been mutated to vulnerable
        data2 = json.loads(cov.COVERAGE_FILE.read_text())
        kept = next(c for c in data2["matrix"] if c["id"] == sqli["id"])
        assert kept["status"] != "vulnerable"

    @pytest.mark.asyncio
    async def test_bulk_update_rejects_vulnerable_without_finding_id(self):
        await cov.add_endpoint(
            path="/login", method="POST",
            params=[{"name": "user", "type": "body_form", "value_hint": ""}],
        )
        data = json.loads(cov.COVERAGE_FILE.read_text())
        sqli = next(c for c in data["matrix"] if c["injection_type"] == "sqli")
        await cov.update_cell(sqli["id"], "in_progress")
        result = await cov.bulk_update([{
            "cell_id": sqli["id"], "status": "vulnerable",
            "artifact_id": self._make_artifact(),
        }])
        assert result["rejected"] == 1
        assert any("REJECTED" in w for w in result["warnings"])
