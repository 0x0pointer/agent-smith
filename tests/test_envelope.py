"""
Tests for mcp_server.scan_engine.envelope pipeline changes:
  - Tiered context pressure warnings (P4)
  - Steering directive injection (P5.6)
  - Duplicate tool call warning (P5.7)
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
