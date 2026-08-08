"""
Tests for core.status_reporter.

Covers:
  • should_emit() gates on the current session (idle → False).
  • compose_status_message() returns None when idle.
  • The composed body contains counts/percentages but NEVER:
        - the target string
        - finding titles / descriptions
        - endpoint paths
  • Code field rotates by minute so consecutive sends bypass the BaseNotifier
    30-min dedup window.
"""
import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from core import status_reporter, session as _session


@pytest.fixture(autouse=True)
def _isolated_files(tmp_path, monkeypatch):
    """Point the findings.json and coverage_matrix.json at tmp_path so each
    test gets a clean slate without polluting the repo."""
    # findings module reads from its module-level FINDINGS_FILE; coverage
    # reads from its module-level constant. Patch both.
    findings_path = tmp_path / "findings.json"
    coverage_path = tmp_path / "coverage_matrix.json"
    from core import findings as _findings
    from core import coverage as _coverage
    monkeypatch.setattr(_findings, "FINDINGS_FILE", findings_path)
    # core.coverage uses Path constants for its file too; locate dynamically.
    if hasattr(_coverage, "COVERAGE_FILE"):
        monkeypatch.setattr(_coverage, "COVERAGE_FILE", coverage_path)
    elif hasattr(_coverage, "_FILE"):
        monkeypatch.setattr(_coverage, "_FILE", coverage_path)
    yield


@pytest.fixture
def _clear_session(monkeypatch):
    """Drop any in-memory session state — each test sets exactly what it needs."""
    monkeypatch.setattr(_session, "_current", None)
    yield


# ---------------------------------------------------------------------------
# should_emit() — gating
# ---------------------------------------------------------------------------

class TestShouldEmit:

    def test_no_session_returns_false(self, _clear_session):
        assert status_reporter.should_emit() is False

    def test_running_session_returns_true(self, monkeypatch):
        monkeypatch.setattr(_session, "_current", {
            "status": "running",
            "skill_history": [],
            "tool_invocations": [],
            "started": datetime.now(timezone.utc).isoformat(),
        })
        assert status_reporter.should_emit() is True

    def test_completed_session_returns_false(self, monkeypatch):
        monkeypatch.setattr(_session, "_current", {"status": "complete"})
        assert status_reporter.should_emit() is False

    def test_intervention_required_returns_false(self, monkeypatch):
        # During an active HIR the operator already got the HIR alert —
        # piling a status update on top would be noise.
        monkeypatch.setattr(_session, "_current", {"status": "intervention_required"})
        assert status_reporter.should_emit() is False


# ---------------------------------------------------------------------------
# compose_status_message() — content + privacy
# ---------------------------------------------------------------------------

class TestComposeContent:

    @pytest.fixture
    def _running_session(self, monkeypatch):
        # Note the target string — we'll verify it does NOT appear in the body.
        monkeypatch.setattr(_session, "_current", {
            "status": "running",
            "target": "https://very-sensitive-customer.example.com/admin",
            "started": datetime.now(timezone.utc).isoformat(),
            "skill_history": [
                {"skill": "pentester"},
                {"skill": "osint"},
                {"skill": "web-exploit"},
            ],
            "tool_invocations": list(range(42)),
        })

    def test_idle_returns_none(self, _clear_session):
        assert status_reporter.compose_status_message() is None

    def test_running_returns_dict_with_required_fields(self, _running_session):
        msg = status_reporter.compose_status_message()
        assert msg is not None
        assert {"title", "body", "urgency", "code"} <= msg.keys()
        assert msg["urgency"] == "low"

    def test_body_contains_severity_counts(self, _running_session, tmp_path):
        # Drop a findings.json with two findings of each severity.
        from core import findings as _findings
        findings_data = {
            "findings": [
                {"severity": "critical"}, {"severity": "critical"},
                {"severity": "high"},
                {"severity": "medium"}, {"severity": "medium"}, {"severity": "medium"},
                {"severity": "low"},
                {"severity": "info"},
            ],
        }
        _findings.FINDINGS_FILE.write_text(json.dumps(findings_data))

        msg = status_reporter.compose_status_message()
        body = msg["body"]
        assert "Critical: 2" in body
        assert "High: 1" in body
        assert "Medium:" in body and "3" in body
        assert "Low:" in body
        assert "Info:" in body
        assert "Findings: 8" in body

    def test_body_NEVER_contains_target(self, _running_session):
        msg = status_reporter.compose_status_message()
        body = msg["body"]
        # The big leak we're defending against: target URL/host/path.
        assert "very-sensitive-customer" not in body
        assert "example.com" not in body
        assert "admin" not in body
        assert "https://" not in body

    def test_body_NEVER_contains_finding_titles_or_descriptions(self, _running_session):
        from core import findings as _findings
        # Inject a finding with a sensitive-looking title — it must not leak.
        sensitive = {
            "findings": [{
                "severity": "critical",
                "title": "SQL injection in /api/v1/payment/transfer",
                "description": "PoC: ' OR 1=1-- against the customer DB",
                "evidence": "leaked-creds: admin:hunter2",
                "target": "https://secret.example.com",
            }],
        }
        _findings.FINDINGS_FILE.write_text(json.dumps(sensitive))

        msg = status_reporter.compose_status_message()
        body = msg["body"]
        assert "SQL injection" not in body
        assert "payment" not in body
        assert "PoC" not in body
        assert "OR 1=1" not in body
        assert "hunter2" not in body
        assert "secret.example.com" not in body
        # But the count IS there.
        assert "Critical: 1" in body

    def test_body_contains_skill_count(self, _running_session):
        msg = status_reporter.compose_status_message()
        body = msg["body"]
        # Three distinct skills in our session fixture.
        assert "Skills run: 3" in body

    def test_body_contains_activity_count(self, _running_session):
        msg = status_reporter.compose_status_message()
        # 42 tool invocations in the session fixture.
        assert "Activity: 42" in msg["body"]


# ---------------------------------------------------------------------------
# code rotation — bypasses BaseNotifier dedup so consecutive sends go through
# ---------------------------------------------------------------------------

class TestCodeRotation:

    def test_code_is_minute_bucketed(self, monkeypatch):
        monkeypatch.setattr(_session, "_current", {
            "status": "running",
            "started": datetime.now(timezone.utc).isoformat(),
            "skill_history": [],
            "tool_invocations": [],
        })
        msg = status_reporter.compose_status_message()
        assert msg["code"].startswith("STATUS_UPDATE_")
        # Bucketed by minute → 14-digit YYYYMMDDHHMM suffix.
        suffix = msg["code"].removeprefix("STATUS_UPDATE_")
        assert len(suffix) == 12
        assert suffix.isdigit()
