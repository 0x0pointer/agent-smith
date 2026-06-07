"""
Tests for mcp_server.scan_engine.envelope pipeline changes:
  - Tiered context pressure warnings (P4)
  - Steering directive injection (P5.6)
  - Duplicate tool call warning (P5.7)
  - _build_quick_log_entry (P6)
"""
import json
import pytest
from unittest.mock import patch, MagicMock


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_envelope(summary="", warnings=None, session_state=None):
    from mcp_server.scan_engine.envelope import Envelope
    return Envelope(
        summary=summary,
        warnings=warnings or [],
        session_state=session_state or {},
    )


# ---------------------------------------------------------------------------
# _check_context_pressure — tiered warnings
# ---------------------------------------------------------------------------

class TestContextPressureTiers:

    def _run_pressure(self, pressure_value, tmp_path, monkeypatch):
        import mcp_server.scan_engine.envelope as env_mod
        import core.session as scan_session

        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        scan_session.start("https://example.com")

        env = _make_envelope(summary="some summary")

        with patch("core.session.get_context_pressure", return_value=pressure_value), \
             patch("core.session.charge_context"), \
             patch("mcp_server.scan_engine.envelope._maybe_write_recovery_snapshot"):
            from mcp_server.scan_engine.envelope import _check_context_pressure
            result = _check_context_pressure(env, env.to_json())
        return json.loads(result)

    def test_below_70_percent_no_warning(self, tmp_path, monkeypatch):
        result = self._run_pressure(0.5, tmp_path, monkeypatch)
        warnings = result.get("warnings", [])
        assert not any("CONTEXT_WARNING" in w for w in warnings)

    def test_above_70_advisory_warning(self, tmp_path, monkeypatch):
        result = self._run_pressure(0.75, tmp_path, monkeypatch)
        warnings = result.get("warnings", [])
        assert any("CONTEXT_WARNING" in w for w in warnings)
        assert not any("EXECUTE NOW" in w for w in warnings)

    def test_above_80_urgent_execute_now(self, tmp_path, monkeypatch):
        result = self._run_pressure(0.85, tmp_path, monkeypatch)
        warnings = result.get("warnings", [])
        assert any("EXECUTE NOW" in w for w in warnings)

    def test_above_90_auto_injects_recovery_brief(self, tmp_path, monkeypatch):
        import mcp_server.scan_engine.envelope as env_mod
        import core.session as scan_session

        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        scan_session.start("https://example.com")

        env = _make_envelope(summary="some summary")

        fake_brief = {"status": "running", "EXECUTE_NOW": "scan(tool='httpx', ...)"}

        with patch("core.session.get_context_pressure", return_value=0.95), \
             patch("core.session.charge_context"), \
             patch("mcp_server.scan_engine.envelope._maybe_write_recovery_snapshot"), \
             patch("mcp_server.session_tools._do_recovery", return_value=json.dumps(fake_brief)):
            from mcp_server.scan_engine.envelope import _check_context_pressure
            result_str = _check_context_pressure(env, env.to_json())

        result = json.loads(result_str)
        assert "recovery_brief" in result.get("session_state", {})
        assert result["session_state"]["recovery_brief"]["EXECUTE_NOW"] == "scan(tool='httpx', ...)"


# ---------------------------------------------------------------------------
# _inject_steering_directives — P5.6
# ---------------------------------------------------------------------------

class TestSteeringInjection:

    def test_pending_high_directive_prepended_to_summary(self, tmp_path, monkeypatch):
        import core.steering as st_mod
        monkeypatch.setattr(st_mod, "_STEERING_FILE", tmp_path / "steering_queue.json")

        q = st_mod.SteeringQueue()
        q.add_directive(
            code=st_mod.CHAIN_REQUIRED,
            message="CHAIN NOW: /web-exploit — 2 critical findings confirmed.",
            priority="high",
            skill="web-exploit",
            trigger="SKILL_CHAIN_GAP",
        )

        env = _make_envelope(summary="original summary")
        from mcp_server.scan_engine.envelope import _inject_steering_directives
        _inject_steering_directives(env)

        assert "QA STEERING" in env.summary
        assert "CHAIN NOW" in env.summary
        assert "original summary" in env.summary  # original is preserved after the prepend

    def test_pending_medium_directive_goes_to_warnings_only(self, tmp_path, monkeypatch):
        import core.steering as st_mod
        monkeypatch.setattr(st_mod, "_STEERING_FILE", tmp_path / "steering_queue.json")

        q = st_mod.SteeringQueue()
        q.add_directive(
            code=st_mod.RESUME_TESTING,
            message="Resume testing — 5 pending cells.",
            priority="medium",
            trigger="COVERAGE_STALL",
        )

        env = _make_envelope(summary="original summary")
        from mcp_server.scan_engine.envelope import _inject_steering_directives
        _inject_steering_directives(env)

        # Medium: only in warnings, not prepended to summary
        assert "QA STEER" not in env.summary
        assert any("RESUME_TESTING" in w or "Resume testing" in w for w in env.warnings)

    def test_directive_marked_injected_after_surfacing(self, tmp_path, monkeypatch):
        import core.steering as st_mod
        monkeypatch.setattr(st_mod, "_STEERING_FILE", tmp_path / "steering_queue.json")

        q = st_mod.SteeringQueue()
        did = q.add_directive(
            code=st_mod.RESUME_REQUIRED,
            message="Stall detected.",
            priority="high",
            trigger="TOOL_INACTIVITY",
        )

        env = _make_envelope()
        from mcp_server.scan_engine.envelope import _inject_steering_directives
        _inject_steering_directives(env)

        directives = q._load()
        d = next(d for d in directives if d["id"] == did)
        assert d["status"] == "injected"

    def test_no_directives_no_change(self, tmp_path, monkeypatch):
        import core.steering as st_mod
        monkeypatch.setattr(st_mod, "_STEERING_FILE", tmp_path / "steering_queue.json")

        env = _make_envelope(summary="clean summary")
        from mcp_server.scan_engine.envelope import _inject_steering_directives
        _inject_steering_directives(env)

        assert env.summary == "clean summary"
        assert env.warnings == []


# ---------------------------------------------------------------------------
# _inject_duplicate_warning — P5.7
# ---------------------------------------------------------------------------

class TestDuplicateWarning:

    def test_duplicate_warning_injected_into_warnings(self, tmp_path, monkeypatch):
        import core.session as scan_session
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        scan_session.start("https://example.com")
        # Seed a tool invocation
        scan_session.add_tool_invocation("nmap", "example.com", "summary", "abc12345")

        env = _make_envelope()
        from mcp_server.scan_engine.envelope import _inject_duplicate_warning
        _inject_duplicate_warning(env, "nmap")

        assert any("DUPLICATE_TOOL_CALL" in w for w in env.warnings)
        assert any("nmap" in w for w in env.warnings)

    def test_no_invocations_no_warning(self, tmp_path, monkeypatch):
        import core.session as scan_session
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        scan_session.start("https://example.com")

        env = _make_envelope()
        from mcp_server.scan_engine.envelope import _inject_duplicate_warning
        _inject_duplicate_warning(env, "nmap")

        # No invocations yet — warning still injected (it's about current dup detection)
        # The warning is always injected when _inject_duplicate_warning is called;
        # actual dedup decision is made in wrap() before calling this function.
        # This test just confirms the warning format is correct.
        warnings_text = " ".join(env.warnings)
        assert "DUPLICATE_TOOL_CALL" in warnings_text


# ---------------------------------------------------------------------------
# _build_quick_log_entry — P6 quick log helper
# ---------------------------------------------------------------------------

from mcp_server.scan_engine.envelope import _build_quick_log_entry


def _mock_result(evidence=None, anomalies=None):
    r = MagicMock()
    r.evidence = evidence if evidence is not None else {}
    r.anomalies = anomalies if anomalies is not None else []
    return r


class TestBuildQuickLogEntry:

    def test_spider_returns_spider_type_with_endpoint_count(self):
        result = _build_quick_log_entry(
            "spider", "https://example.com",
            "Found 42 unique endpoints across the site", None
        )
        assert result["type"] == "SPIDER"
        assert result["target"] == "https://example.com"
        assert result["endpoints_found"] == 42

    def test_spider_no_match_returns_zero_endpoints(self):
        result = _build_quick_log_entry(
            "spider", "https://example.com",
            "No pages discovered at all", None
        )
        assert result["type"] == "SPIDER"
        assert result["endpoints_found"] == 0

    def test_non_spider_returns_tool_type_with_name_and_target(self):
        result = _build_quick_log_entry(
            "nmap", "192.168.1.1", "some summary", None
        )
        assert result["type"] == "TOOL"
        assert result["name"] == "nmap"
        assert result["target"] == "192.168.1.1"

    def test_http_request_status_code_extracted_from_evidence(self):
        r = _mock_result(evidence={"status": 200})
        result = _build_quick_log_entry("http_request", "https://example.com", "", r)
        assert result["status_code"] == 200

    def test_http_request_with_error_in_evidence_sets_error_true(self):
        r = _mock_result(evidence={"status": 200, "error": "connection refused"})
        result = _build_quick_log_entry("http_request", "https://example.com", "", r)
        assert result.get("error") is True

    def test_http_request_with_status_zero_sets_error_true(self):
        """status=0 means no HTTP response was received, so mark as tool error."""
        r = _mock_result(evidence={"status": 0})
        result = _build_quick_log_entry("http_request", "https://example.com", "", r)
        assert result.get("error") is True

    def test_non_http_tool_with_error_in_anomalies_does_not_set_error(self):
        r = _mock_result(evidence={}, anomalies=["connection error: timed out"])
        result = _build_quick_log_entry("nuclei", "https://example.com", "", r)
        assert result.get("error") is not True

    def test_result_none_does_not_crash(self):
        result = _build_quick_log_entry("nmap", "10.0.0.1", "scan done", None)
        assert result["type"] == "TOOL"
        assert "error" not in result


# ---------------------------------------------------------------------------
# _inject_steering_directives — exception path
# ---------------------------------------------------------------------------

class TestSteeringInjectionExceptionPath:

    def test_exception_in_steering_returns_false(self):
        """If steering_queue.get_pending() raises, function returns False without crashing."""
        env = _make_envelope(summary="original")
        from mcp_server.scan_engine.envelope import _inject_steering_directives
        with patch("core.steering.steering_queue") as mock_sq:
            mock_sq.get_pending.side_effect = RuntimeError("disk error")
            result = _inject_steering_directives(env)
        assert result is False
        assert env.summary == "original"  # unchanged


# ---------------------------------------------------------------------------
# _inject_qa_alerts_into_envelope — QA alert injection
# ---------------------------------------------------------------------------

class TestInjectQaAlerts:

    def _write_qa_state(self, path, alerts, ts="2025-01-01T12:00:00+00:00"):
        import json
        path.write_text(json.dumps({"ts": ts, "alerts": alerts}), encoding="utf-8")

    def test_no_qa_state_file_does_nothing(self, tmp_path, monkeypatch):
        import mcp_server.scan_engine.envelope as env_mod
        monkeypatch.setattr(env_mod, "_QA_STATE_FILE", tmp_path / "qa_state.json")
        monkeypatch.setattr(env_mod, "_last_qa_shown_ts", "")
        env = _make_envelope(summary="clean")
        from mcp_server.scan_engine.envelope import _inject_qa_alerts_into_envelope
        _inject_qa_alerts_into_envelope(env)
        assert env.summary == "clean"
        assert env.warnings == []

    def test_high_urgency_alert_injected_into_warnings_and_summary(self, tmp_path, monkeypatch):
        import mcp_server.scan_engine.envelope as env_mod
        qa_path = tmp_path / "qa_state.json"
        monkeypatch.setattr(env_mod, "_QA_STATE_FILE", qa_path)
        monkeypatch.setattr(env_mod, "_last_qa_shown_ts", "")
        self._write_qa_state(qa_path, [
            {"urgency": "high", "message": "Smith is skipping endpoints!"},
        ])
        env = _make_envelope(summary="original summary")
        from mcp_server.scan_engine.envelope import _inject_qa_alerts_into_envelope
        _inject_qa_alerts_into_envelope(env)
        assert any("[QA HIGH]" in w for w in env.warnings)
        assert "QA ALERT" in env.summary
        assert "Smith is skipping endpoints!" in env.summary

    def test_suppress_summary_prepend_omits_summary_prefix(self, tmp_path, monkeypatch):
        import mcp_server.scan_engine.envelope as env_mod
        qa_path = tmp_path / "qa_state.json"
        monkeypatch.setattr(env_mod, "_QA_STATE_FILE", qa_path)
        monkeypatch.setattr(env_mod, "_last_qa_shown_ts", "")
        self._write_qa_state(qa_path, [
            {"urgency": "high", "message": "Check auth flows!"},
        ])
        env = _make_envelope(summary="original summary")
        from mcp_server.scan_engine.envelope import _inject_qa_alerts_into_envelope
        _inject_qa_alerts_into_envelope(env, suppress_summary_prepend=True)
        assert any("[QA HIGH]" in w for w in env.warnings)
        assert "QA ALERT" not in env.summary

    def test_medium_urgency_alert_skipped(self, tmp_path, monkeypatch):
        import mcp_server.scan_engine.envelope as env_mod
        qa_path = tmp_path / "qa_state.json"
        monkeypatch.setattr(env_mod, "_QA_STATE_FILE", qa_path)
        monkeypatch.setattr(env_mod, "_last_qa_shown_ts", "")
        self._write_qa_state(qa_path, [
            {"urgency": "medium", "message": "Low priority advisory"},
        ])
        env = _make_envelope(summary="original")
        from mcp_server.scan_engine.envelope import _inject_qa_alerts_into_envelope
        _inject_qa_alerts_into_envelope(env)
        assert env.warnings == []
        assert "QA ALERT" not in env.summary

    def test_dedup_same_ts_does_not_reinject(self, tmp_path, monkeypatch):
        import mcp_server.scan_engine.envelope as env_mod
        qa_path = tmp_path / "qa_state.json"
        ts = "2025-06-01T10:00:00+00:00"
        monkeypatch.setattr(env_mod, "_QA_STATE_FILE", qa_path)
        monkeypatch.setattr(env_mod, "_last_qa_shown_ts", ts)
        self._write_qa_state(qa_path, [
            {"urgency": "high", "message": "Already shown!"},
        ], ts=ts)
        env = _make_envelope(summary="original")
        from mcp_server.scan_engine.envelope import _inject_qa_alerts_into_envelope
        _inject_qa_alerts_into_envelope(env)
        assert env.warnings == []

    def test_exception_in_qa_injection_does_not_propagate(self, tmp_path, monkeypatch):
        import mcp_server.scan_engine.envelope as env_mod
        qa_path = tmp_path / "qa_state.json"
        qa_path.write_text("not valid json{{{{", encoding="utf-8")
        monkeypatch.setattr(env_mod, "_QA_STATE_FILE", qa_path)
        monkeypatch.setattr(env_mod, "_last_qa_shown_ts", "")
        env = _make_envelope(summary="safe")
        from mcp_server.scan_engine.envelope import _inject_qa_alerts_into_envelope
        _inject_qa_alerts_into_envelope(env)  # must not raise
        assert env.summary == "safe"

    def test_multiple_high_alerts_all_injected(self, tmp_path, monkeypatch):
        import mcp_server.scan_engine.envelope as env_mod
        qa_path = tmp_path / "qa_state.json"
        monkeypatch.setattr(env_mod, "_QA_STATE_FILE", qa_path)
        monkeypatch.setattr(env_mod, "_last_qa_shown_ts", "")
        self._write_qa_state(qa_path, [
            {"urgency": "high", "message": "Alert one"},
            {"urgency": "high", "message": "Alert two"},
        ])
        env = _make_envelope(summary="s")
        from mcp_server.scan_engine.envelope import _inject_qa_alerts_into_envelope
        _inject_qa_alerts_into_envelope(env)
        assert sum(1 for w in env.warnings if "[QA HIGH]" in w) == 2
        assert "Alert one" in env.summary
        assert "Alert two" in env.summary
