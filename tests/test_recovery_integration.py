"""
Integration tests for the context recovery flow.

These tests verify the full recovery pipeline:
  - session start + coverage + findings written to disk
  - session(action='recovery') returns correct in_progress_cells with notes
  - set_skill resume detection returns recovery brief inline
  - recovery brief finding count matches findings.json
"""
import asyncio
import json
import pytest
from unittest.mock import patch, AsyncMock


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_session(tmp_path, monkeypatch):
    """Redirect all disk state to tmp_path and start a running session."""
    import core.session as scan_session
    import core.coverage as cov_mod
    import core.findings as findings_mod

    monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
    monkeypatch.setattr(cov_mod, "COVERAGE_FILE", tmp_path / "coverage_matrix.json")
    monkeypatch.setattr(findings_mod, "FINDINGS_FILE", tmp_path / "findings.json")

    scan_session.start("https://example.com", depth="thorough", scope=["example.com"])
    return tmp_path


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------
# Test: recovery brief contains in_progress cells with notes
# ---------------------------------------------------------------------------

def test_recovery_brief_contains_in_progress_cells(tmp_session, monkeypatch):
    import core.coverage as cov_mod
    import core.session as scan_session

    monkeypatch.setattr(cov_mod, "COVERAGE_FILE", tmp_session / "coverage_matrix.json")

    # Register an endpoint (sync version via direct matrix manipulation)
    matrix_data = {
        "meta": {"total_cells": 2, "tested": 0, "vulnerable": 0, "addressed": 0},
        "endpoints": [{"id": "ep-1", "path": "/api/users", "method": "GET"}],
        "matrix": [
            {
                "id": "cell-001",
                "endpoint_id": "ep-1",
                "param": "id",
                "injection_type": "sqli",
                "status": "in_progress",
                "notes": "Union blocked. Trying blind time-based. 10s delay promising.",
                "finding_id": None,
            },
            {
                "id": "cell-002",
                "endpoint_id": "ep-1",
                "param": "name",
                "injection_type": "xss",
                "status": "pending",
                "notes": "",
                "finding_id": None,
            },
        ],
    }
    (tmp_session / "coverage_matrix.json").write_text(json.dumps(matrix_data))

    from mcp_server.session_tools import _do_recovery
    brief = json.loads(_do_recovery())

    # The in_progress cell drives EXECUTE_NOW and action_required
    execute_now = brief.get("EXECUTE_NOW", "")
    action_required = brief.get("action_required", [])
    assert "in_progress" in str(action_required).lower() or "cell-001" in execute_now or "sqli" in execute_now
    # Coverage should reflect the pending cells
    assert brief.get("coverage") is not None


# ---------------------------------------------------------------------------
# Test: recovery brief finding count matches findings.json
# ---------------------------------------------------------------------------

def test_recovery_brief_finding_count_matches_findings_json(tmp_session, monkeypatch):
    import core.findings as findings_mod
    import asyncio

    monkeypatch.setattr(findings_mod, "FINDINGS_FILE", tmp_session / "findings.json")
    monkeypatch.setattr(findings_mod, "_lock", asyncio.Lock())

    # Write 3 findings directly
    findings_data = {
        "meta": {"target": "https://example.com"},
        "findings": [
            {"id": "f-001", "title": "SQLi in /api/users", "severity": "critical",
             "status": "confirmed", "escalation_leads": [
                 {"lead": "Dump users table", "status": "pending"}
             ]},
            {"id": "f-002", "title": "XSS in search", "severity": "high",
             "status": "confirmed", "escalation_leads": []},
            {"id": "f-003", "title": "SSRF via callback", "severity": "high",
             "status": "confirmed", "escalation_leads": []},
        ],
        "diagrams": [],
    }
    (tmp_session / "findings.json").write_text(json.dumps(findings_data))

    from mcp_server.session_tools import _do_recovery
    brief = json.loads(_do_recovery())

    # findings count should reflect the 3 we wrote
    assert brief.get("findings", 0) == 3

    # pending_escalations should include the SQLi finding's lead
    escalations = brief.get("pending_escalations", [])
    assert any(e["finding_id"] == "f-001" for e in escalations)
    assert any("Dump users table" in e.get("pending_leads", []) for e in escalations)


# ---------------------------------------------------------------------------
# Test: set_skill resume detection returns recovery brief on second invocation
# ---------------------------------------------------------------------------

def test_set_skill_resume_detection(tmp_session, monkeypatch):
    import core.session as scan_session
    import core.steering as st_mod

    monkeypatch.setattr(st_mod, "_STEERING_FILE", tmp_session / "steering_queue.json")

    from mcp_server.session_tools import _do_set_skill

    # First invocation — not a resume
    result1 = _do_set_skill({"skill": "pentester", "reason": "starting pentest"})
    assert "RESUME DETECTED" not in result1

    # Second invocation of same skill — should trigger resume detection
    result2 = _do_set_skill({"skill": "pentester", "reason": "re-invoking after compaction"})
    assert "RESUME DETECTED" in result2
    # The recovery brief JSON should be embedded
    assert "EXECUTE_NOW" in result2 or "status" in result2


# ---------------------------------------------------------------------------
# Test: same-target session start appends recovery brief
# ---------------------------------------------------------------------------

def test_same_target_start_includes_recovery_state(tmp_session, monkeypatch):
    import core.session as scan_session
    import core.findings as findings_mod
    import core.coverage as cov_mod

    monkeypatch.setattr(findings_mod, "FINDINGS_FILE", tmp_session / "findings.json")
    monkeypatch.setattr(cov_mod, "COVERAGE_FILE", tmp_session / "coverage_matrix.json")

    # Write a coverage matrix so has_data is True
    cov_data = {
        "meta": {"total_cells": 1, "tested": 0, "addressed": 0},
        "endpoints": [{"id": "ep-1", "path": "/", "method": "GET"}],
        "matrix": [{"id": "c-1", "endpoint_id": "ep-1", "param": "q",
                     "injection_type": "sqli", "status": "pending", "notes": ""}],
    }
    (tmp_session / "coverage_matrix.json").write_text(json.dumps(cov_data))

    from mcp_server.session_tools import _do_start
    with patch("mcp_server.session_tools._do_recovery", return_value='{"status":"running","EXECUTE_NOW":"resume"}'):
        result = _do_start({
            "target": "https://example.com",  # same target
            "depth": "thorough",
        })

    assert "recovery" in result.lower() or "resume" in result.lower() or "RESUME" in result
