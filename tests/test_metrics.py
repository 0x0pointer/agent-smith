"""
Tests for core.metrics — pentest run metrics computation and persistence.
"""
import json
import pytest
from datetime import datetime, timezone, timedelta
from pathlib import Path


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_metrics(tmp_path, monkeypatch):
    import core.metrics as m
    monkeypatch.setattr(m, "_METRICS_FILE", tmp_path / "pentest_metrics.jsonl")
    return m


def _make_session(started_offset_min=30):
    now = datetime.now(timezone.utc)
    started = (now - timedelta(minutes=started_offset_min)).isoformat()
    return {
        "id": "test-run-001",
        "started": started,
        "finished": now.isoformat(),
        "target": "https://example.com",
        "depth": "standard",
        "status": "complete",
        "context_chars_sent": 120000,
        "tool_invocations": [],
        "skill_history": [],
        "gates": [],
    }


def _make_cost():
    return {"est_cost_usd": 0.042, "tool_calls_done": 18}


def _make_findings(severities=None):
    severities = severities or []
    findings = []
    for i, sev in enumerate(severities):
        findings.append({
            "id": f"f-{i:03d}",
            "title": f"Finding {i}",
            "severity": sev,
            "status": "confirmed",
            "poc_files": ["poc.http"] if sev in ("critical", "high") else [],
            "escalation_leads": [],
        })
    return {"meta": {}, "findings": findings, "diagrams": []}


def _make_coverage(endpoints=2, total_cells=4, tested=3):
    matrix = []
    ep_ids = [f"ep-{i}" for i in range(endpoints)]
    inj_types = ["sqli", "xss", "ssti", "cmdi"]
    for i in range(total_cells):
        matrix.append({
            "id": f"cell-{i:03d}",
            "endpoint_id": ep_ids[i % endpoints],
            "param": "q",
            "injection_type": inj_types[i % len(inj_types)],
            "status": "tested_clean" if i < tested else "pending",
        })
    return {
        "meta": {"total_cells": total_cells, "tested": tested, "addressed": tested},
        "endpoints": [{"id": eid, "path": f"/{eid}", "method": "GET"} for eid in ep_ids],
        "matrix": matrix,
    }


# ---------------------------------------------------------------------------
# _compute — basic schema completeness
# ---------------------------------------------------------------------------

class TestComputeSchema:

    def test_all_schema_fields_present(self, tmp_metrics):
        session = _make_session()
        record = tmp_metrics._compute(
            session=session,
            cost_summary=_make_cost(),
            findings_data=_make_findings(["critical", "high", "medium"]),
            coverage=_make_coverage(),
            force_completed=False,
            completion_blockers=[],
            quick_log_entries=[],
            steering_history=[],
        )
        required = [
            "run_id", "ts", "target", "depth", "status", "force_completed",
            "duration_minutes", "total_cost_usd", "tool_calls_total",
            "context_chars_total", "cost_per_finding", "tool_calls_per_finding",
            "endpoint_count", "total_cells", "coverage_rate_pct",
            "injection_types_tested", "injection_breadth",
            "findings_total", "findings_critical", "findings_high",
            "findings_medium", "findings_low", "findings_info",
            "poc_coverage_rate_pct", "false_positive_count",
            "escalation_completion_rate_pct",
            "resume_events", "duplicate_tool_calls",
            "steering_interventions", "steering_auto_satisfied",
            "skills_invoked", "skill_chain_depth",
            "unsatisfied_gate_count", "completion_blockers",
            "time_per_skill_minutes",
        ]
        for field in required:
            assert field in record, f"Missing field: {field}"

    def test_identity_fields(self, tmp_metrics):
        session = _make_session()
        rec = tmp_metrics._compute(
            session=session,
            cost_summary=_make_cost(),
            findings_data=_make_findings(),
            coverage=_make_coverage(),
            force_completed=True,
            completion_blockers=["NO DIAGRAM"],
            quick_log_entries=[],
            steering_history=[],
        )
        assert rec["run_id"] == "test-run-001"
        assert rec["target"] == "https://example.com"
        assert rec["depth"] == "standard"
        assert rec["force_completed"] is True
        assert rec["completion_blockers"] == ["NO DIAGRAM"]


# ---------------------------------------------------------------------------
# _compute — cost metrics
# ---------------------------------------------------------------------------

class TestCostMetrics:

    def test_cost_fields_populated(self, tmp_metrics):
        rec = tmp_metrics._compute(
            session=_make_session(),
            cost_summary={"est_cost_usd": 0.06, "tool_calls_done": 30},
            findings_data=_make_findings(["critical", "high"]),
            coverage=_make_coverage(),
            force_completed=False,
            completion_blockers=[],
            quick_log_entries=[],
            steering_history=[],
        )
        assert rec["total_cost_usd"] == 0.06
        assert rec["tool_calls_total"] == 30
        assert rec["cost_per_finding"] == round(0.06 / 2, 6)
        assert rec["tool_calls_per_finding"] == round(30 / 2, 2)

    def test_no_findings_cost_per_finding_is_none(self, tmp_metrics):
        rec = tmp_metrics._compute(
            session=_make_session(),
            cost_summary=_make_cost(),
            findings_data=_make_findings(),
            coverage=_make_coverage(),
            force_completed=False,
            completion_blockers=[],
            quick_log_entries=[],
            steering_history=[],
        )
        assert rec["cost_per_finding"] is None
        assert rec["tool_calls_per_finding"] is None


# ---------------------------------------------------------------------------
# _compute — coverage metrics
# ---------------------------------------------------------------------------

class TestCoverageMetrics:

    def test_coverage_rate_computed(self, tmp_metrics):
        rec = tmp_metrics._compute(
            session=_make_session(),
            cost_summary=_make_cost(),
            findings_data=_make_findings(),
            coverage=_make_coverage(total_cells=10, tested=7),
            force_completed=False,
            completion_blockers=[],
            quick_log_entries=[],
            steering_history=[],
        )
        assert rec["coverage_rate_pct"] == 70.0

    def test_injection_types_from_tested_cells(self, tmp_metrics):
        cov = _make_coverage(total_cells=3, tested=3)
        # Override matrix with known injection types
        cov["matrix"] = [
            {"id": "c1", "endpoint_id": "ep-0", "param": "q", "injection_type": "sqli", "status": "tested_clean"},
            {"id": "c2", "endpoint_id": "ep-0", "param": "q", "injection_type": "xss",  "status": "vulnerable"},
            {"id": "c3", "endpoint_id": "ep-0", "param": "q", "injection_type": "ssti", "status": "pending"},
        ]
        cov["meta"]["total_cells"] = 3
        cov["meta"]["addressed"] = 2

        rec = tmp_metrics._compute(
            session=_make_session(),
            cost_summary=_make_cost(),
            findings_data=_make_findings(),
            coverage=cov,
            force_completed=False,
            completion_blockers=[],
            quick_log_entries=[],
            steering_history=[],
        )
        assert "sqli" in rec["injection_types_tested"]
        assert "xss" in rec["injection_types_tested"]
        assert "ssti" not in rec["injection_types_tested"]
        assert rec["injection_breadth"] == 2


# ---------------------------------------------------------------------------
# _compute — findings metrics
# ---------------------------------------------------------------------------

class TestFindingsMetrics:

    def test_severity_counts(self, tmp_metrics):
        rec = tmp_metrics._compute(
            session=_make_session(),
            cost_summary=_make_cost(),
            findings_data=_make_findings(["critical", "critical", "high", "medium", "low", "info"]),
            coverage=_make_coverage(),
            force_completed=False,
            completion_blockers=[],
            quick_log_entries=[],
            steering_history=[],
        )
        assert rec["findings_critical"] == 2
        assert rec["findings_high"] == 1
        assert rec["findings_medium"] == 1
        assert rec["findings_low"] == 1
        assert rec["findings_info"] == 1
        assert rec["findings_total"] == 6

    def test_poc_coverage_rate(self, tmp_metrics):
        data = {
            "meta": {}, "diagrams": [],
            "findings": [
                {"id": "f1", "severity": "critical", "status": "confirmed",
                 "poc_files": ["poc.http"], "escalation_leads": []},
                {"id": "f2", "severity": "high", "status": "confirmed",
                 "poc_files": [], "escalation_leads": []},
            ],
        }
        rec = tmp_metrics._compute(
            session=_make_session(),
            cost_summary=_make_cost(),
            findings_data=data,
            coverage=_make_coverage(),
            force_completed=False,
            completion_blockers=[],
            quick_log_entries=[],
            steering_history=[],
        )
        # 1 of 2 high/critical has poc → 50%
        assert rec["poc_coverage_rate_pct"] == 50.0

    def test_escalation_completion_rate(self, tmp_metrics):
        data = {
            "meta": {}, "diagrams": [],
            "findings": [
                {"id": "f1", "severity": "critical", "status": "confirmed",
                 "poc_files": [], "escalation_leads": [
                     {"lead": "dump db", "status": "done"},
                     {"lead": "rce", "status": "pending"},
                 ]},
            ],
        }
        rec = tmp_metrics._compute(
            session=_make_session(),
            cost_summary=_make_cost(),
            findings_data=data,
            coverage=_make_coverage(),
            force_completed=False,
            completion_blockers=[],
            quick_log_entries=[],
            steering_history=[],
        )
        # 1 done out of 2 total → 50%
        assert rec["escalation_completion_rate_pct"] == 50.0


# ---------------------------------------------------------------------------
# _compute — context health
# ---------------------------------------------------------------------------

class TestContextHealth:

    def test_resume_events_counted(self, tmp_metrics):
        session = _make_session()
        session["tool_invocations"] = [
            {"summary": "RESUME DETECTED: post-compaction"},
            {"summary": "normal tool call"},
            {"summary": "RESUME DETECTED: again"},
        ]
        rec = tmp_metrics._compute(
            session=session,
            cost_summary=_make_cost(),
            findings_data=_make_findings(),
            coverage=_make_coverage(),
            force_completed=False,
            completion_blockers=[],
            quick_log_entries=[],
            steering_history=[],
        )
        assert rec["resume_events"] == 2

    def test_duplicate_tool_calls_counted(self, tmp_metrics):
        session = _make_session()
        session["tool_invocations"] = [
            {"summary": "DUPLICATE_TOOL_CALL: nmap already run"},
        ]
        rec = tmp_metrics._compute(
            session=session,
            cost_summary=_make_cost(),
            findings_data=_make_findings(),
            coverage=_make_coverage(),
            force_completed=False,
            completion_blockers=[],
            quick_log_entries=[],
            steering_history=[],
        )
        assert rec["duplicate_tool_calls"] == 1

    def test_steering_history_counted(self, tmp_metrics):
        history = [
            {"id": "s1", "status": "auto_satisfied"},
            {"id": "s2", "status": "acknowledged"},
            {"id": "s3", "status": "auto_satisfied"},
        ]
        rec = tmp_metrics._compute(
            session=_make_session(),
            cost_summary=_make_cost(),
            findings_data=_make_findings(),
            coverage=_make_coverage(),
            force_completed=False,
            completion_blockers=[],
            quick_log_entries=[],
            steering_history=history,
        )
        assert rec["steering_interventions"] == 3
        assert rec["steering_auto_satisfied"] == 2


# ---------------------------------------------------------------------------
# _compute_time_per_skill
# ---------------------------------------------------------------------------

class TestTimePerSkill:

    def test_buckets_tool_events_between_skills(self, tmp_metrics):
        from datetime import datetime, timezone, timedelta

        base = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        def ts(offset_min):
            return (base + timedelta(minutes=offset_min)).isoformat()

        entries = [
            {"type": "SKILL", "name": "pentester",   "ts": ts(0)},
            {"type": "TOOL",  "name": "nmap",         "ts": ts(2)},
            {"type": "TOOL",  "name": "httpx",        "ts": ts(5)},
            {"type": "SKILL", "name": "web-exploit",  "ts": ts(10)},
            {"type": "TOOL",  "name": "sqlmap",       "ts": ts(12)},
        ]
        result = tmp_metrics._compute_time_per_skill(entries)
        assert "pentester" in result
        assert "web-exploit" in result
        # pentester: from ts(0) to last tool ts(5) = 5 min
        assert result["pentester"] == 5.0
        # web-exploit: from ts(10) to ts(12) = 2 min
        assert result["web-exploit"] == 2.0

    def test_empty_entries_returns_empty(self, tmp_metrics):
        assert tmp_metrics._compute_time_per_skill([]) == {}


# ---------------------------------------------------------------------------
# _duration_minutes
# ---------------------------------------------------------------------------

class TestDurationMinutes:

    def test_duration_computed(self, tmp_metrics):
        session = {
            "started":  "2025-01-01T10:00:00+00:00",
            "finished": "2025-01-01T10:30:00+00:00",
        }
        assert tmp_metrics._duration_minutes(session) == 30.0

    def test_missing_timestamps_returns_zero(self, tmp_metrics):
        assert tmp_metrics._duration_minutes({}) == 0.0


# ---------------------------------------------------------------------------
# record() — writes to JSONL and load_all() reads it back
# ---------------------------------------------------------------------------

class TestRecordAndLoad:

    def test_record_appends_to_jsonl(self, tmp_metrics):
        tmp_metrics.record(
            session=_make_session(),
            cost_summary=_make_cost(),
            findings_data=_make_findings(["high"]),
            coverage=_make_coverage(),
            force_completed=False,
            completion_blockers=[],
            quick_log_entries=[],
            steering_history=[],
        )
        records = tmp_metrics.load_all()
        assert len(records) == 1
        assert records[0]["target"] == "https://example.com"

    def test_multiple_records_appended_in_order(self, tmp_metrics):
        for i in range(3):
            s = _make_session()
            s["id"] = f"run-{i}"
            tmp_metrics.record(
                session=s,
                cost_summary=_make_cost(),
                findings_data=_make_findings(),
                coverage=_make_coverage(),
                force_completed=False,
                completion_blockers=[],
                quick_log_entries=[],
                steering_history=[],
            )
        records = tmp_metrics.load_all()
        assert len(records) == 3
        assert records[0]["run_id"] == "run-0"
        assert records[2]["run_id"] == "run-2"

    def test_load_all_empty_file(self, tmp_metrics):
        assert tmp_metrics.load_all() == []
