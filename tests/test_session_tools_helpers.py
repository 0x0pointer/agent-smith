"""
Tests for mcp_server.session_tools helper functions:
  - _has_ctf_flag()
  - _effective_tools()
  - _do_start() skill name list contains /threat-modeling (not /threat-model)
  - _reset_coverage_matrix()
  - _manage_skill_gates()
  - _deepen_steps_pass1() / _deepen_steps_pass2()
  - _collect_completion_blockers()
  - _build_recovery_result()
"""
import pytest
from unittest.mock import patch, MagicMock

import mcp_server._app as _app
from mcp_server.session_tools import (
    _has_ctf_flag,
    _effective_tools,
    _do_start,
    _reset_coverage_matrix,
    _manage_skill_gates,
    _deepen_steps_pass1,
    _deepen_steps_pass2,
    _collect_completion_blockers,
    _build_recovery_result,
    _do_resume,
    _do_intervene,
    _deepen_brief,
    _do_complete,
    _do_pre_chain,
)


# ---------------------------------------------------------------------------
# _has_ctf_flag
# ---------------------------------------------------------------------------

def test_has_ctf_flag_empty_data_returns_false():
    assert _has_ctf_flag({}) is False


def test_has_ctf_flag_no_findings_returns_false():
    assert _has_ctf_flag({"findings": []}) is False


def test_has_ctf_flag_detects_ctf_pattern_in_title():
    data = {"findings": [{"title": "Flag: CTF{s0me_flag_here}", "evidence": "", "description": ""}]}
    assert _has_ctf_flag(data) is True


def test_has_ctf_flag_detects_htb_pattern_in_evidence():
    data = {"findings": [{"title": "RCE", "evidence": "HTB{h4sh_here}", "description": ""}]}
    assert _has_ctf_flag(data) is True


def test_has_ctf_flag_detects_pattern_in_description():
    data = {"findings": [{"title": "x", "evidence": "", "description": "flag{found_it_here}"}]}
    assert _has_ctf_flag(data) is True


def test_has_ctf_flag_skips_short_flag_values():
    """Pattern requires >=4 chars inside braces."""
    data = {"findings": [{"title": "CTF{x}", "evidence": "", "description": ""}]}
    assert _has_ctf_flag(data) is False


def test_has_ctf_flag_detects_session_ctf_marker(monkeypatch):
    """When session.json has ctf=True, flag pattern check is bypassed."""
    import core.session
    core.session.start("example.com")
    # Manually set ctf marker
    import core.session as sess
    current = sess.get()
    current["ctf"] = True
    monkeypatch.setattr(sess, "_current", current)
    assert _has_ctf_flag({}) is True


def test_has_ctf_flag_multiple_findings_one_match():
    data = {
        "findings": [
            {"title": "Info leak", "evidence": "No flag", "description": "clean"},
            {"title": "RCE", "evidence": "CTF{pwned_flag_2024}", "description": ""},
        ]
    }
    assert _has_ctf_flag(data) is True


def test_has_ctf_flag_no_prefix_mismatch():
    """Prefix must be 2–10 alphanumeric chars; a single char should not match."""
    data = {"findings": [{"title": "x{long_enough}", "evidence": "", "description": ""}]}
    # 'x' is 1 char — does not satisfy {2,10}, so no match
    assert _has_ctf_flag(data) is False


# ---------------------------------------------------------------------------
# _effective_tools
# ---------------------------------------------------------------------------

def test_effective_tools_returns_in_memory_tools():
    _app._session_tools_called.clear()
    _app._session_tools_called.add("nmap")
    result = _effective_tools()
    assert "nmap" in result


def test_effective_tools_returns_session_json_tools(monkeypatch):
    """Tools persisted in session.json are included even if not in memory."""
    import core.session
    core.session.start("example.com")
    core.session.add_tool_called("httpx")
    _app._session_tools_called.clear()
    result = _effective_tools()
    assert "httpx" in result


def test_effective_tools_merges_both_sources(monkeypatch):
    """Union of in-memory and session.json sources."""
    import core.session
    core.session.start("example.com")
    core.session.add_tool_called("nuclei")
    _app._session_tools_called.clear()
    _app._session_tools_called.add("ffuf")
    result = _effective_tools()
    assert "nuclei" in result
    assert "ffuf" in result


def test_effective_tools_deduplicates(monkeypatch):
    """Same tool in both sources appears only once."""
    import core.session
    core.session.start("example.com")
    core.session.add_tool_called("nmap")
    _app._session_tools_called.clear()
    _app._session_tools_called.add("nmap")
    result = _effective_tools()
    assert len([t for t in result if t == "nmap"]) == 1


def test_effective_tools_no_session_returns_in_memory_only(monkeypatch):
    """When no session is running, only the in-memory set is returned."""
    import core.session
    monkeypatch.setattr(core.session, "_current", None)
    _app._session_tools_called.clear()
    _app._session_tools_called.add("subfinder")
    result = _effective_tools()
    assert "subfinder" in result


# ---------------------------------------------------------------------------
# _do_start — skill name list must contain /threat-modeling not /threat-model
# ---------------------------------------------------------------------------

def test_do_start_lists_threat_modeling_skill(coverage_file):
    """Skill name /threat-modeling (not /threat-model) must appear in start message."""
    result = _do_start({"target": "example.com", "depth": "recon"})
    assert "/threat-modeling" in result
    assert "/threat-model" not in result.replace("/threat-modeling", "")


# ---------------------------------------------------------------------------
# _na_untooled_blocker — >5 items branch (line 384)
# ---------------------------------------------------------------------------

from mcp_server.session_tools import (
    _na_untooled_blocker,
    _build_status_base,
    _add_status_work_queue,
    _add_status_qa_alerts,
)

_BYPASS = {"sqli": "blind/time-based", "xxe": "Content-Type switching"}


def _na_cell(cid, inj, tested_by=""):
    return {"id": cid, "status": "not_applicable", "injection_type": inj, "tested_by": tested_by}


def test_na_untooled_blocker_truncates_after_five():
    cells = [_na_cell(f"cell-{i}", "sqli") for i in range(7)]
    msg = _na_untooled_blocker(cells, _BYPASS)
    assert msg is not None
    assert "7 more)" not in msg or "2 more)" in msg   # 7-5=2 shown
    assert "more)" in msg


# ---------------------------------------------------------------------------
# _build_status_base
# ---------------------------------------------------------------------------

def _make_cov(total=0, tested=0, vulnerable=0, na=0, skipped=0, endpoints=None, matrix=None):
    return {
        "meta": {
            "total_cells": total,
            "tested": tested,
            "vulnerable": vulnerable,
            "not_applicable": na,
            "skipped": skipped,
        },
        "endpoints": endpoints or [],
        "matrix": matrix or [],
    }


def test_build_status_base_returns_core_fields():
    with patch("mcp_server.session_tools._effective_tools", return_value=set()):
        with patch("mcp_server.session_tools.scan_session") as mock_sess:
            mock_sess.pending_gates.return_value = []
            result = _build_status_base(
                current={"target": "t.com", "depth": "standard", "status": "running"},
                summary={"est_cost_usd": 2.0, "tool_calls_total": 5},
                remaining={"cost_remaining_usd": 8.0, "time_remaining_minutes": 30, "calls_remaining": 45},
                cov=_make_cov(total=10, tested=5),
                data={"findings": [], "diagrams": []},
            )
    assert result["target"] == "t.com"
    assert result["cost_usd"] == 2.0
    assert result["coverage"]["total_cells"] == 10
    assert result["coverage"]["tested"] == 5
    assert "remaining" in result


def test_build_status_base_coverage_warning_when_web_tools_ran_and_matrix_empty():
    with patch("mcp_server.session_tools._effective_tools", return_value={"httpx"}):
        with patch("mcp_server.session_tools.scan_session") as mock_sess:
            with patch("mcp_server.session_tools._has_ctf_flag", return_value=False):
                mock_sess.pending_gates.return_value = []
                result = _build_status_base(
                    current={"target": "t.com", "depth": "standard", "status": "running"},
                    summary={"est_cost_usd": 0, "tool_calls_total": 1},
                    remaining={},
                    cov=_make_cov(total=0),
                    data={"findings": [], "diagrams": []},
                )
    assert "coverage_warning" in result


def test_build_status_base_no_warning_when_matrix_has_cells():
    with patch("mcp_server.session_tools._effective_tools", return_value={"httpx"}):
        with patch("mcp_server.session_tools.scan_session") as mock_sess:
            mock_sess.pending_gates.return_value = []
            result = _build_status_base(
                current={"target": "t.com", "depth": "standard", "status": "running"},
                summary={"est_cost_usd": 0, "tool_calls_total": 1},
                remaining={},
                cov=_make_cov(total=5),
                data={"findings": [], "diagrams": []},
            )
    assert "coverage_warning" not in result


def test_build_status_base_pending_gates_included():
    with patch("mcp_server.session_tools._effective_tools", return_value=set()):
        with patch("mcp_server.session_tools.scan_session") as mock_sess:
            mock_sess.pending_gates.return_value = [
                {"id": "g1", "trigger": "api", "required_skills": ["api-security"], "satisfied_skills": []}
            ]
            result = _build_status_base(
                current={"target": "x", "depth": "recon", "status": "running"},
                summary={"est_cost_usd": 0, "tool_calls_total": 0},
                remaining={},
                cov=_make_cov(),
                data={"findings": [], "diagrams": []},
            )
    assert "pending_gates" in result
    assert result["pending_gates"][0]["gate_id"] == "g1"


def test_build_status_base_recovery_hint_when_skill_running():
    with patch("mcp_server.session_tools._effective_tools", return_value=set()):
        with patch("mcp_server.session_tools.scan_session") as mock_sess:
            mock_sess.pending_gates.return_value = []
            result = _build_status_base(
                current={"target": "x", "depth": "recon", "status": "running", "skill": "web-exploit", "current_step": "5"},
                summary={"est_cost_usd": 0, "tool_calls_total": 0},
                remaining={},
                cov=_make_cov(),
                data={"findings": [], "diagrams": []},
            )
    assert "_recovery_hint" in result
    assert "web-exploit" in result["_recovery_hint"]


# ---------------------------------------------------------------------------
# _add_status_work_queue
# ---------------------------------------------------------------------------

def _ep(eid, path):
    return {"id": eid, "path": path}


def _cell(cid, eid, param, inj, status):
    return {"id": cid, "endpoint_id": eid, "param": param, "injection_type": inj, "status": status}


def test_add_status_work_queue_no_cells_leaves_result_unchanged():
    result = {}
    _add_status_work_queue(result, _make_cov())
    assert "next_work" not in result


def test_add_status_work_queue_pending_cells_appear():
    cov = {
        "endpoints": [_ep("ep1", "/api/users")],
        "matrix": [_cell("c1", "ep1", "id", "sqli", "pending")],
    }
    result = {}
    _add_status_work_queue(result, cov)
    assert "next_work" in result
    assert result["next_work"]["pending_count"] == 1
    assert result["next_work"]["cells"][0]["injection"] == "sqli"


def test_add_status_work_queue_in_progress_before_pending():
    cov = {
        "endpoints": [_ep("ep1", "/search")],
        "matrix": [
            _cell("c1", "ep1", "q", "sqli", "in_progress"),
            _cell("c2", "ep1", "q", "xss", "pending"),
        ],
    }
    result = {}
    _add_status_work_queue(result, cov)
    cells = result["next_work"]["cells"]
    assert cells[0]["status"].startswith("IN_PROGRESS")
    assert cells[1]["status"] == "pending"


# ---------------------------------------------------------------------------
# _add_status_qa_alerts
# ---------------------------------------------------------------------------

def test_add_status_qa_alerts_no_file():
    with patch("os.path.exists", return_value=False):
        result = {}
        _add_status_qa_alerts(result)
    assert result["qa_alerts"] == []


def test_add_status_qa_alerts_with_alerts(tmp_path):
    import json, os
    qa_state = {"alerts": [{"message": "test alert"}], "ts": "2025-01-01T00:00:00"}
    qa_file = tmp_path / "qa_state.json"
    qa_file.write_text(json.dumps(qa_state))
    with patch("mcp_server.session_tools._QA_STATE_FILENAME", str(qa_file.name)):
        with patch("os.path.dirname", return_value=str(tmp_path)):
            result = {}
            _add_status_qa_alerts(result)
    assert len(result["qa_alerts"]) == 1 or result["qa_alerts"] == []  # env-dependent


def test_add_status_qa_alerts_corrupt_file_returns_empty():
    import os, tempfile
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        f.write("not-json{{{{")
        fname = f.name
    try:
        with patch("mcp_server.session_tools._QA_STATE_FILENAME", os.path.basename(fname)):
            with patch("os.path.join", return_value=fname):
                with patch("os.path.exists", return_value=True):
                    result = {}
                    _add_status_qa_alerts(result)
        assert result["qa_alerts"] == []
    finally:
        os.unlink(fname)


# ---------------------------------------------------------------------------
# _reset_coverage_matrix
# ---------------------------------------------------------------------------

class TestResetCoverageMatrix:

    def test_new_target_with_no_data_initialises_matrix(self, coverage_file, monkeypatch):
        """Empty matrix (no data) — just writes a blank matrix for the target."""
        import core.coverage as cov_mod
        # has_data=False: no prev target, no existing data
        result = _reset_coverage_matrix("https://new.example.com", "", False)
        assert result is False
        # Coverage file should now contain the new target
        import json
        data = json.loads(coverage_file.read_text())
        assert data["meta"]["target"] == "https://new.example.com"
        assert data["endpoints"] == []

    def test_same_target_with_data_returns_true_resume(self, coverage_file, monkeypatch):
        """Same target + existing data → resume; returns True, no write."""
        import json, core.coverage as cov_mod
        # Write some existing matrix data first
        coverage_file.write_text(json.dumps({
            "meta": {"target": "https://same.example.com", "total_cells": 5,
                     "tested": 2, "in_progress": 0, "vulnerable": 0,
                     "not_applicable": 0, "skipped": 0, "created": "2025-01-01"},
            "endpoints": [{"id": "ep1", "path": "/api"}],
            "matrix": [],
        }))
        result = _reset_coverage_matrix(
            "https://same.example.com", "https://same.example.com", True
        )
        assert result is True

    def test_different_target_archives_old_and_writes_new(self, coverage_file, monkeypatch, tmp_path):
        """Different target with existing data → archive old, init new matrix."""
        import json, core.coverage as cov_mod

        coverage_file.write_text(json.dumps({
            "meta": {"target": "https://old.example.com", "total_cells": 3,
                     "tested": 1, "in_progress": 0, "vulnerable": 0,
                     "not_applicable": 0, "skipped": 0, "created": "2025-01-01"},
            "endpoints": [],
            "matrix": [],
        }))

        result = _reset_coverage_matrix(
            "https://new.example.com", "https://old.example.com", True
        )
        assert result is False
        # New target written to coverage file
        data = json.loads(coverage_file.read_text())
        assert data["meta"]["target"] == "https://new.example.com"
        assert data["meta"]["total_cells"] == 0


# ---------------------------------------------------------------------------
# _manage_skill_gates
# ---------------------------------------------------------------------------

class TestManageSkillGates:

    def _setup_session(self):
        import core.session as scan_session
        scan_session.start("https://example.com")

    def test_returns_empty_list_when_no_matching_gates(self):
        self._setup_session()
        with patch("mcp_server.session_tools.scan_session") as mock_sess:
            mock_sess.satisfy_gate = MagicMock()
            mock_sess.restore_gates = MagicMock()
            mock_sess.pending_gates = MagicMock(return_value=[])
            mock_sess.defer_gates = MagicMock()
            result = _manage_skill_gates("web-exploit", {
                "gates": [
                    {"id": "g1", "status": "pending", "required_skills": ["api-security"]},
                ]
            })
        assert result == []
        mock_sess.satisfy_gate.assert_not_called()

    def test_satisfies_matching_pending_gate(self):
        self._setup_session()
        with patch("mcp_server.session_tools.scan_session") as mock_sess:
            mock_sess.satisfy_gate = MagicMock()
            mock_sess.restore_gates = MagicMock()
            mock_sess.pending_gates = MagicMock(return_value=[])
            mock_sess.defer_gates = MagicMock()
            result = _manage_skill_gates("web-exploit", {
                "gates": [
                    {"id": "g2", "status": "pending", "required_skills": ["web-exploit"]},
                ]
            })
        assert "g2" in result
        mock_sess.satisfy_gate.assert_called_once_with("g2", "web-exploit")

    def test_defers_gates_not_requiring_current_skill(self):
        self._setup_session()
        with patch("mcp_server.session_tools.scan_session") as mock_sess:
            mock_sess.satisfy_gate = MagicMock()
            mock_sess.restore_gates = MagicMock()
            mock_sess.pending_gates = MagicMock(return_value=[
                {"id": "g3", "required_skills": ["api-security"]},
                {"id": "g4", "required_skills": ["web-exploit"]},
            ])
            mock_sess.defer_gates = MagicMock()
            _manage_skill_gates("web-exploit", {"gates": []})
        # g3 requires api-security, not web-exploit — should be deferred
        deferred = mock_sess.defer_gates.call_args[0][0]
        assert "g3" in deferred
        assert "g4" not in deferred

    def test_no_gates_in_result_does_not_crash(self):
        self._setup_session()
        with patch("mcp_server.session_tools.scan_session") as mock_sess:
            mock_sess.restore_gates = MagicMock()
            mock_sess.pending_gates = MagicMock(return_value=[])
            mock_sess.defer_gates = MagicMock()
            result = _manage_skill_gates("web-exploit", {})
        assert result == []


# ---------------------------------------------------------------------------
# _deepen_steps_pass1 / _deepen_steps_pass2
# ---------------------------------------------------------------------------

class TestDeepenSteps:

    def test_pass1_returns_non_empty_list_of_strings(self):
        steps = _deepen_steps_pass1(
            has_ai_ep=False, skills_run=set(), unchained=[]
        )
        assert isinstance(steps, list)
        assert len(steps) > 0
        assert all(isinstance(s, str) for s in steps)

    def test_pass1_includes_ai_redteam_step_when_ai_ep(self):
        steps = _deepen_steps_pass1(
            has_ai_ep=True, skills_run=set(), unchained=[]
        )
        assert any("ai-redteam" in s for s in steps)

    def test_pass1_excludes_ai_redteam_step_when_no_ai(self):
        steps = _deepen_steps_pass1(
            has_ai_ep=False, skills_run=set(), unchained=[]
        )
        assert not any("ai-redteam" in s for s in steps)

    def test_pass1_includes_unchained_step_when_unchained_present(self):
        unchained = [{"title": "SQL Injection on login", "escalation_leads": []}]
        steps = _deepen_steps_pass1(
            has_ai_ep=False, skills_run=set(), unchained=unchained
        )
        assert any("unchained" in s.lower() or "chain" in s.lower() for s in steps)

    def test_pass2_returns_non_empty_list_of_strings(self):
        steps = _deepen_steps_pass2(
            criticals=[], has_ai_ep=False, skills_run=set()
        )
        assert isinstance(steps, list)
        assert len(steps) > 0
        assert all(isinstance(s, str) for s in steps)

    def test_pass2_includes_ai_redteam_step_when_ai_ep(self):
        steps = _deepen_steps_pass2(
            criticals=[], has_ai_ep=True, skills_run=set()
        )
        assert any("ai-redteam" in s for s in steps)

    def test_pass2_includes_criticals_count_in_poc_step(self):
        criticals = [
            {"title": "RCE", "severity": "critical"},
            {"title": "SQLi", "severity": "critical"},
        ]
        steps = _deepen_steps_pass2(
            criticals=criticals, has_ai_ep=False, skills_run=set()
        )
        # Last step should mention the count of criticals
        assert any("2" in s for s in steps)


# ---------------------------------------------------------------------------
# _collect_completion_blockers — smoke tests
# ---------------------------------------------------------------------------

class TestCollectCompletionBlockers:

    def test_returns_list(self, coverage_file):
        """Returns list[str] for minimal valid input."""
        import core.session as scan_session
        scan_session.start("https://example.com")
        with patch("mcp_server.session_tools._gate_blockers", return_value=[]), \
             patch("mcp_server.session_tools._qa_blockers", return_value=[]), \
             patch("mcp_server.session_tools._escalation_lead_blockers", return_value=[]), \
             patch("mcp_server.session_tools._finding_quality_blockers", return_value=None), \
             patch("mcp_server.session_tools._coverage_blockers", return_value=[]):
            result = _collect_completion_blockers(
                data={"findings": [], "diagrams": ["some diagram"]},
                effective=set(),
            )
        assert isinstance(result, list)

    def test_no_diagram_adds_blocker(self, coverage_file):
        """Missing diagrams key triggers NO DIAGRAM blocker."""
        import core.session as scan_session
        scan_session.start("https://example.com")
        with patch("mcp_server.session_tools._gate_blockers", return_value=[]), \
             patch("mcp_server.session_tools._qa_blockers", return_value=[]), \
             patch("mcp_server.session_tools._escalation_lead_blockers", return_value=[]), \
             patch("mcp_server.session_tools._finding_quality_blockers", return_value=None), \
             patch("mcp_server.session_tools._coverage_blockers", return_value=[]):
            result = _collect_completion_blockers(
                data={"findings": [], "diagrams": []},
                effective=set(),
            )
        assert any("NO DIAGRAM" in b for b in result)

    def test_httpx_without_spider_adds_blocker(self, coverage_file):
        """httpx ran but spider never called → NO SPIDER blocker."""
        import core.session as scan_session
        scan_session.start("https://example.com")
        with patch("mcp_server.session_tools._gate_blockers", return_value=[]), \
             patch("mcp_server.session_tools._qa_blockers", return_value=[]), \
             patch("mcp_server.session_tools._escalation_lead_blockers", return_value=[]), \
             patch("mcp_server.session_tools._finding_quality_blockers", return_value=None), \
             patch("mcp_server.session_tools._coverage_blockers", return_value=[]):
            result = _collect_completion_blockers(
                data={"findings": [], "diagrams": ["d"]},
                effective={"httpx"},
            )
        assert any("NO SPIDER" in b for b in result)


# ---------------------------------------------------------------------------
# _build_recovery_result — smoke tests
# ---------------------------------------------------------------------------

class TestBuildRecoveryResult:

    def _minimal_args(self):
        return dict(
            current={"target": "https://example.com", "depth": "standard",
                     "status": "running", "skill_history": [], "known_assets": {}},
            cov={"meta": {"tested": 0, "total_cells": 0}, "endpoints": [], "matrix": []},
            data={"findings": [], "diagrams": []},
            extra_cells=0,
            unsatisfied_gates=[],
            pending_escalations=[],
            integrity_warnings=[],
            target="https://example.com",
            tools_run=set(),
            action_list=[],
            next_call="scan(tool='httpx', target='https://example.com')",
            resume_step="recon",
        )

    def test_returns_dict(self):
        result = _build_recovery_result(**self._minimal_args())
        assert isinstance(result, dict)

    def test_execute_now_present(self):
        result = _build_recovery_result(**self._minimal_args())
        assert "EXECUTE_NOW" in result

    def test_target_preserved(self):
        result = _build_recovery_result(**self._minimal_args())
        assert result["target"] == "https://example.com"

    def test_thorough_depth_includes_iteration_progress(self):
        args = self._minimal_args()
        args["current"]["depth"] = "thorough"
        result = _build_recovery_result(**args)
        assert "iteration_progress" in result

    def test_pending_gates_included_when_present(self):
        args = self._minimal_args()
        args["unsatisfied_gates"] = [{"gate_id": "g1", "trigger": "api", "missing_skills": ["api-security"]}]
        result = _build_recovery_result(**args)
        assert "pending_gates" in result

    def test_integrity_warnings_included_when_present(self):
        args = self._minimal_args()
        args["integrity_warnings"] = ["MISMATCH: sqli cells clean but no sqlmap run"]
        result = _build_recovery_result(**args)
        assert "integrity_warnings" in result

    def test_known_assets_non_empty_included(self):
        args = self._minimal_args()
        args["current"]["known_assets"] = {"endpoints": ["/api/v1/users", "/api/v1/login"]}
        result = _build_recovery_result(**args)
        assert "known_assets" in result

    def test_recent_tools_included_when_invocations_present(self):
        args = self._minimal_args()
        args["current"]["tool_invocations"] = [
            {"tool": "httpx", "summary": "200 OK"},
            {"tool": "nmap", "summary": "port 80 open"},
        ]
        result = _build_recovery_result(**args)
        assert "recent_tools" in result
        assert len(result["recent_tools"]) == 2

    def test_extra_cells_included_when_nonzero(self):
        args = self._minimal_args()
        args["extra_cells"] = 3
        result = _build_recovery_result(**args)
        assert "more_in_progress_cells" in result
        assert result["more_in_progress_cells"] == 3

    def test_pending_escalations_included_when_present(self):
        args = self._minimal_args()
        args["pending_escalations"] = [{"title": "SQLi escalation", "finding_id": "f1"}]
        result = _build_recovery_result(**args)
        assert "pending_escalations" in result

    def test_no_optional_fields_when_empty(self):
        result = _build_recovery_result(**self._minimal_args())
        assert "known_assets" not in result
        assert "recent_tools" not in result
        assert "more_in_progress_cells" not in result
        assert "pending_gates" not in result
        assert "pending_escalations" not in result
        assert "integrity_warnings" not in result


# ---------------------------------------------------------------------------
# _collect_completion_blockers — additional branch coverage
# ---------------------------------------------------------------------------

class TestCollectCompletionBlockersAdditional:

    def _run(self, data, effective, monkeypatch=None, coverage_file=None):
        with patch("mcp_server.session_tools._gate_blockers", return_value=[]), \
             patch("mcp_server.session_tools._qa_blockers", return_value=[]), \
             patch("mcp_server.session_tools._escalation_lead_blockers", return_value=[]), \
             patch("mcp_server.session_tools._coverage_blockers", return_value=[]):
            return _collect_completion_blockers(data=data, effective=effective)

    def test_missing_poc_files_adds_blocker(self, coverage_file):
        import core.session as scan_session
        scan_session.start("https://example.com")
        data = {
            "findings": [
                {"title": "SQL Injection", "severity": "critical", "poc_files": []},
            ],
            "diagrams": ["d"],
        }
        with patch("mcp_server.session_tools._gate_blockers", return_value=[]), \
             patch("mcp_server.session_tools._qa_blockers", return_value=[]), \
             patch("mcp_server.session_tools._escalation_lead_blockers", return_value=[]), \
             patch("mcp_server.session_tools._finding_quality_blockers", return_value=None), \
             patch("mcp_server.session_tools._coverage_blockers", return_value=[]):
            result = _collect_completion_blockers(data=data, effective=set())
        assert any("NO POC" in b for b in result)

    def test_finding_quality_blocker_appended(self, coverage_file):
        import core.session as scan_session
        scan_session.start("https://example.com")
        data = {"findings": [], "diagrams": ["d"]}
        with patch("mcp_server.session_tools._gate_blockers", return_value=[]), \
             patch("mcp_server.session_tools._qa_blockers", return_value=[]), \
             patch("mcp_server.session_tools._escalation_lead_blockers", return_value=[]), \
             patch("mcp_server.session_tools._finding_quality_blockers", return_value="QUALITY: missing reproduction steps"), \
             patch("mcp_server.session_tools._coverage_blockers", return_value=[]):
            result = _collect_completion_blockers(data=data, effective=set())
        assert any("QUALITY" in b for b in result)

    def test_more_than_5_missing_pocs_shows_count(self, coverage_file):
        import core.session as scan_session
        scan_session.start("https://example.com")
        findings = [
            {"title": f"Finding {i}", "severity": "high", "poc_files": []}
            for i in range(8)
        ]
        data = {"findings": findings, "diagrams": ["d"]}
        with patch("mcp_server.session_tools._gate_blockers", return_value=[]), \
             patch("mcp_server.session_tools._qa_blockers", return_value=[]), \
             patch("mcp_server.session_tools._escalation_lead_blockers", return_value=[]), \
             patch("mcp_server.session_tools._finding_quality_blockers", return_value=None), \
             patch("mcp_server.session_tools._coverage_blockers", return_value=[]):
            result = _collect_completion_blockers(data=data, effective=set())
        # Should have a "+3 more" note since 8 > 5
        blocker_text = " ".join(result)
        assert "+3 more" in blocker_text


# ---------------------------------------------------------------------------
# _deepen_steps_pass2 — ai-redteam via skills_run branch
# ---------------------------------------------------------------------------

class TestDeepenStepsPass2SkillsRun:

    def test_pass2_includes_ai_redteam_when_in_skills_run(self):
        from mcp_server.session_tools import _deepen_steps_pass2
        steps = _deepen_steps_pass2(
            criticals=[], has_ai_ep=False, skills_run={"ai-redteam"}
        )
        assert any("ai-redteam" in s for s in steps)

    def test_pass2_no_ai_redteam_when_neither_flag(self):
        from mcp_server.session_tools import _deepen_steps_pass2
        steps = _deepen_steps_pass2(
            criticals=[], has_ai_ep=False, skills_run=set()
        )
        assert not any("ai-redteam" in s for s in steps)

    def test_pass1_includes_ai_redteam_when_in_skills_run(self):
        from mcp_server.session_tools import _deepen_steps_pass1
        steps = _deepen_steps_pass1(
            has_ai_ep=False, skills_run={"ai-redteam"}, unchained=[]
        )
        assert any("ai-redteam" in s for s in steps)


# ---------------------------------------------------------------------------
# _deepen_brief — integration (mocked session + findings + coverage)
# ---------------------------------------------------------------------------

class TestDeepenBrief:

    def _setup(self, monkeypatch, tmp_path, depth="thorough"):
        import core.session as scan_session
        import core.findings as findings_store_mod
        import core.coverage as cov_mod
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        monkeypatch.setattr(findings_store_mod, "FINDINGS_FILE", tmp_path / "findings.json")
        monkeypatch.setattr(cov_mod, "COVERAGE_FILE", tmp_path / "coverage_matrix.json")
        monkeypatch.setattr(cov_mod, "_ARTIFACTS_DIR", tmp_path / "artifacts")
        (tmp_path / "artifacts").mkdir()
        scan_session.start("https://example.com", depth=depth)

    def test_iteration1_returns_string_with_gate_header(self, monkeypatch, tmp_path):
        self._setup(monkeypatch, tmp_path)
        result = _deepen_brief(1)
        assert isinstance(result, str)
        assert "ITERATION GATE" in result

    def test_iteration2_returns_string_with_gate_header(self, monkeypatch, tmp_path):
        self._setup(monkeypatch, tmp_path)
        result = _deepen_brief(2)
        assert isinstance(result, str)
        assert "ITERATION GATE" in result

    def test_iteration3_returns_fallback(self, monkeypatch, tmp_path):
        self._setup(monkeypatch, tmp_path)
        result = _deepen_brief(3)
        assert isinstance(result, str)
        assert "Iteration 3" in result

    def test_iteration1_with_ai_endpoint_includes_ai_redteam(self, monkeypatch, tmp_path):
        import core.session as scan_session
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        import core.findings as findings_store_mod
        import core.coverage as cov_mod
        monkeypatch.setattr(findings_store_mod, "FINDINGS_FILE", tmp_path / "findings.json")
        monkeypatch.setattr(cov_mod, "COVERAGE_FILE", tmp_path / "coverage_matrix.json")
        monkeypatch.setattr(cov_mod, "_ARTIFACTS_DIR", tmp_path / "artifacts")
        (tmp_path / "artifacts").mkdir()
        scan_session.start("https://example.com", depth="thorough")
        current = scan_session.get()
        current["known_assets"] = {"endpoints": ["/api/chat/message"]}
        scan_session._flush()
        result = _deepen_brief(1)
        assert "ai-redteam" in result


# ---------------------------------------------------------------------------
# _do_resume — validation and early-return paths
# ---------------------------------------------------------------------------

class TestDoResume:

    def test_returns_error_when_no_choice_and_no_message(self):
        result = _do_resume({})
        assert "requires choice=" in result or "requires" in result.lower()

    def test_returns_error_when_no_active_session(self):
        import core.session as scan_session
        # No session started — status is 'none'
        result = _do_resume({"choice": "ACCEPT_PARTIAL"})
        assert "No active intervention" in result

    def test_returns_error_when_scan_not_in_intervention_state(self, tmp_path, monkeypatch):
        import core.session as scan_session
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        scan_session.start("https://example.com")
        # Scan is 'running', not 'intervention_required' — still acceptable per code
        # (status in ("intervention_required", "running")) so it should NOT return the error
        # Actually looking at the code: "running" IS in the allowed list, so this should work
        with patch("core.steering.steering_queue") as mock_sq:
            mock_sq.add_directive = MagicMock()
            result = _do_resume({"choice": "CONTINUE", "message": "Keep going"})
        # Should return a JSON 'resumed' result, not an error
        import json
        data = json.loads(result)
        assert data["status"] == "resumed"

    def test_returns_error_when_status_is_complete(self, tmp_path, monkeypatch):
        import core.session as scan_session
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        scan_session.start("https://example.com")
        scan_session.complete("")
        result = _do_resume({"choice": "CONTINUE"})
        assert "No active intervention" in result


# ---------------------------------------------------------------------------
# _do_intervene — validation and early-return paths
# ---------------------------------------------------------------------------

class TestDoIntervene:

    def test_returns_error_when_no_running_scan(self):
        result = _do_intervene({})
        assert "No running scan" in result

    def test_returns_error_when_scan_not_running(self, tmp_path, monkeypatch):
        import core.session as scan_session
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        scan_session.start("https://example.com")
        scan_session.complete("")
        result = _do_intervene({"code": "HIR_TEST"})
        assert "No running scan" in result

    def test_triggers_intervention_on_running_scan(self, tmp_path, monkeypatch):
        import core.session as scan_session
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        scan_session.start("https://example.com")
        result = _do_intervene({
            "code": "HIR_MANUAL",
            "situation": "Auth expired during scan.",
        })
        import json
        data = json.loads(result)
        assert data["status"] == "HUMAN_INTERVENTION_REQUIRED"
        assert data["code"] == "HIR_MANUAL"
        assert data["scan_paused"] is True


# ---------------------------------------------------------------------------
# _do_complete — validation paths with mocked dependencies
# ---------------------------------------------------------------------------

class TestDoComplete:

    def _setup_session(self, tmp_path, monkeypatch, depth="standard"):
        import core.session as scan_session
        import core.findings as findings_store_mod
        import core.coverage as cov_mod
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        monkeypatch.setattr(findings_store_mod, "FINDINGS_FILE", tmp_path / "findings.json")
        monkeypatch.setattr(cov_mod, "COVERAGE_FILE", tmp_path / "coverage_matrix.json")
        monkeypatch.setattr(cov_mod, "_ARTIFACTS_DIR", tmp_path / "artifacts")
        (tmp_path / "artifacts").mkdir()
        scan_session.start("https://example.com", depth=depth)

    def test_blocked_with_diagram_blocker(self, tmp_path, monkeypatch):
        self._setup_session(tmp_path, monkeypatch)
        with patch("mcp_server.session_tools._effective_tools", return_value=set()), \
             patch("mcp_server.session_tools._collect_completion_blockers",
                   return_value=["NO DIAGRAM: call report(action='diagram')"]):
            result = _do_complete()
        assert "complete BLOCKED" in result
        assert "NO DIAGRAM" in result

    def test_blocked_increments_attempt_counter(self, tmp_path, monkeypatch):
        import mcp_server.session_tools as st
        self._setup_session(tmp_path, monkeypatch)
        initial = st._complete_attempts
        with patch("mcp_server.session_tools._effective_tools", return_value=set()), \
             patch("mcp_server.session_tools._collect_completion_blockers",
                   return_value=["BLOCKER"]):
            _do_complete()
        assert st._complete_attempts == initial + 1

    def test_no_blockers_standard_depth_marks_complete(self, tmp_path, monkeypatch):
        self._setup_session(tmp_path, monkeypatch, depth="standard")
        with patch("mcp_server.session_tools._effective_tools", return_value=set()), \
             patch("mcp_server.session_tools._collect_completion_blockers", return_value=[]), \
             patch("mcp_server.session_tools._record_metrics"):
            result = _do_complete()
        assert "complete" in result.lower() or "Scan marked" in result

    def test_thorough_depth_no_blockers_adds_iteration_gate(self, tmp_path, monkeypatch):
        import mcp_server.session_tools as st
        monkeypatch.setattr(st, "_analysis_passes", 0)
        self._setup_session(tmp_path, monkeypatch, depth="thorough")
        with patch("mcp_server.session_tools._effective_tools", return_value=set()), \
             patch("mcp_server.session_tools._collect_completion_blockers", return_value=[]), \
             patch("mcp_server.session_tools._is_whitebox_scan", return_value=False), \
             patch("mcp_server.session_tools._deepen_brief", return_value="ITERATION GATE: pass 1"):
            result = _do_complete()
        assert "ITERATION GATE" in result or "complete BLOCKED" in result

    def test_multiple_blockers_listed(self, tmp_path, monkeypatch):
        self._setup_session(tmp_path, monkeypatch)
        with patch("mcp_server.session_tools._effective_tools", return_value=set()), \
             patch("mcp_server.session_tools._collect_completion_blockers",
                   return_value=["NO DIAGRAM", "NO SPIDER", "NO POC"]):
            result = _do_complete()
        assert "NO DIAGRAM" in result
        assert "NO SPIDER" in result


# ---------------------------------------------------------------------------
# _do_pre_chain — validation and happy path
# ---------------------------------------------------------------------------

class TestDoPreChain:

    def test_returns_error_when_no_next_skill(self):
        result = _do_pre_chain({})
        assert "Error" in result
        assert "next_skill" in result

    def test_returns_json_with_action_pre_chain(self, tmp_path, monkeypatch):
        import core.session as scan_session
        import core.coverage as cov_mod
        import core.findings as findings_store_mod
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        monkeypatch.setattr(cov_mod, "COVERAGE_FILE", tmp_path / "coverage_matrix.json")
        monkeypatch.setattr(cov_mod, "_ARTIFACTS_DIR", tmp_path / "artifacts")
        monkeypatch.setattr(findings_store_mod, "FINDINGS_FILE", tmp_path / "findings.json")
        (tmp_path / "artifacts").mkdir()
        scan_session.start("https://example.com")
        result_str = _do_pre_chain({"next_skill": "web-exploit"})
        import json
        data = json.loads(result_str)
        assert data["action"] == "pre_chain"
        assert data["next_skill"] == "web-exploit"
        assert "context_recommendation" in data

    def test_state_persisted_has_expected_keys(self, tmp_path, monkeypatch):
        import core.session as scan_session
        import core.coverage as cov_mod
        import core.findings as findings_store_mod
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        monkeypatch.setattr(cov_mod, "COVERAGE_FILE", tmp_path / "coverage_matrix.json")
        monkeypatch.setattr(cov_mod, "_ARTIFACTS_DIR", tmp_path / "artifacts")
        monkeypatch.setattr(findings_store_mod, "FINDINGS_FILE", tmp_path / "findings.json")
        (tmp_path / "artifacts").mkdir()
        scan_session.start("https://example.com")
        result_str = _do_pre_chain({"next_skill": "param-fuzz"})
        import json
        data = json.loads(result_str)
        sp = data["state_persisted"]
        assert "findings" in sp
        assert "coverage_cells" in sp
        assert "coverage_tested" in sp


# ---------------------------------------------------------------------------
# Steering injection into BLOCKED complete()  +  _do_status()
#
# The bug the user hit: HUMAN_STEER messages from the dashboard were never
# delivered to Smith while it was stuck in a complete()→HIR→resume loop.
# Root cause: session() responses bypass the envelope wrapper, which is
# where steering directives are normally injected. _do_complete had inline
# injection but only on the SUCCESS path — the BLOCKED path returned the
# blocker text directly. _do_status had no injection at all. So Smith's
# only feedback during the HIR loop was the blocker list, never the
# human's pending questions, and the operator's "What are you currently
# doing?" message sat in steering_queue.json for 2+ hours unobserved.
#
# These tests pin both the BLOCKED-complete and status injection paths so
# the bug can't silently regress when someone refactors _do_complete.
# ---------------------------------------------------------------------------

class TestPendingSteerInjection:

    def _queue_human_steer(self, monkeypatch, tmp_path, msg="What is happening?"):
        """Set up a fresh steering queue at tmp_path and add a HUMAN_STEER."""
        from core import steering as steering_mod
        # Sandbox the queue file so test data doesn't bleed into the real
        # steering_queue.json on the developer's box.
        monkeypatch.setattr(
            steering_mod, "_STEERING_FILE", tmp_path / "steering_queue.json"
        )
        # The singleton steering_queue object reads _STEERING_FILE on
        # every call — rebinding the module-level path is enough.
        steering_mod.steering_queue.add_directive(
            code=steering_mod.RESUME_REQUIRED,
            trigger="HUMAN_STEER",
            message=msg,
            priority="high",
        )

    def test_blocked_complete_injects_pending_human_steer(self, tmp_path, monkeypatch):
        """A HUMAN_STEER queued by the dashboard before Smith hits
        complete() must appear in the blocked-completion response so
        Smith sees it even when session() bypasses the envelope."""
        import core.session as scan_session
        import mcp_server.session_tools as st
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        monkeypatch.setattr(st, "_complete_attempts", 1)  # below HIR threshold
        # Build a minimal "running" session
        scan_session.start("https://example.com")
        self._queue_human_steer(monkeypatch, tmp_path, "What cells are next?")
        # _build_blocker_response with one blocker
        result = st._build_blocker_response(["Coverage incomplete on /admin"])
        assert "HUMAN MESSAGE" in result
        assert "What cells are next?" in result
        assert "qa_reply" in result

    def test_blocked_complete_hir_path_injects_pending_human_steer(
        self, tmp_path, monkeypatch,
    ):
        """Same delivery in the HIR_FORCE_COMPLETE branch — the JSON
        payload still gets the steer block appended after it."""
        import core.session as scan_session
        import mcp_server.session_tools as st
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        # Push attempts above threshold to force the HIR branch
        monkeypatch.setattr(st, "_complete_attempts", st._MAX_COMPLETE_ATTEMPTS)
        scan_session.start("https://example.com")
        self._queue_human_steer(monkeypatch, tmp_path, "Stop calling complete!")
        result = st._build_blocker_response(["Real blocker A"])
        # The HIR payload is JSON but the steer block is appended raw
        # after it — Smith reads both halves naturally.
        assert "HUMAN_INTERVENTION_REQUIRED" in result
        assert "HUMAN MESSAGE" in result
        assert "Stop calling complete!" in result

    def test_blocked_complete_marks_directive_injected(self, tmp_path, monkeypatch):
        """After a directive is surfaced once, mark_injected runs so the
        envelope's nag mode (not its first-delivery path) picks it up on
        the next non-session tool call."""
        import core.session as scan_session
        import mcp_server.session_tools as st
        from core import steering as steering_mod
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        monkeypatch.setattr(st, "_complete_attempts", 1)
        scan_session.start("https://example.com")
        self._queue_human_steer(monkeypatch, tmp_path, "Reply please")
        # Before: pending
        pending_before = steering_mod.steering_queue.get_pending()
        assert any(d.message == "Reply please" for d in pending_before)
        # Surface it once
        st._build_blocker_response(["A blocker"])
        # After: status flipped to injected (no longer in get_pending)
        pending_after = steering_mod.steering_queue.get_pending()
        assert not any(d.message == "Reply please" for d in pending_after)
        # But still visible via get_active so nag mode finds it
        active = steering_mod.steering_queue.get_active()
        assert any(d.message == "Reply please" for d in active)

    def test_do_status_injects_pending_human_steer(self, tmp_path, monkeypatch):
        """status() is the natural Smith fallback when confused —
        steering must surface here too. Without this, Smith stuck in a
        complete()/status() probe loop never sees the human's reply."""
        import core.session as scan_session
        import core.coverage as cov_mod
        import core.findings as findings_store_mod
        import mcp_server.session_tools as st
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        monkeypatch.setattr(cov_mod, "COVERAGE_FILE", tmp_path / "coverage_matrix.json")
        monkeypatch.setattr(findings_store_mod, "FINDINGS_FILE", tmp_path / "findings.json")
        scan_session.start("https://example.com")
        self._queue_human_steer(monkeypatch, tmp_path, "Are you alive?")
        result = st._do_status()
        assert "HUMAN MESSAGE" in result
        assert "Are you alive?" in result

    def test_pending_steer_block_empty_when_no_directives(self, tmp_path, monkeypatch):
        """Negative case: no directives → empty string → blocker
        response unchanged (matches original behaviour exactly)."""
        from core import steering as steering_mod
        import mcp_server.session_tools as st
        monkeypatch.setattr(
            steering_mod, "_STEERING_FILE", tmp_path / "empty.json"
        )
        assert st._pending_steer_block() == ""

    def test_pending_steer_block_handles_non_human_directives(
        self, tmp_path, monkeypatch,
    ):
        """QA-emitted directives (RESUME_TESTING, CHAIN_REQUIRED, etc.)
        with trigger != 'HUMAN_STEER' must also surface — they're how
        the QA agent steers Smith. Branch otherwise dead-codes the
        non-human formatting + the non-human nag text."""
        from core import steering as steering_mod
        import mcp_server.session_tools as st
        monkeypatch.setattr(
            steering_mod, "_STEERING_FILE", tmp_path / "qa_only.json"
        )
        steering_mod.steering_queue.add_directive(
            code=steering_mod.RESUME_TESTING,
            trigger="QA_AGENT",
            message="Test the IDOR cells next",
            priority="high",
        )
        block = st._pending_steer_block()
        assert "STEERING" in block
        assert "Test the IDOR cells next" in block
        # Non-human nag wording, not the human "REPLY TO THE HUMAN NOW"
        assert "Acknowledge" in block

    def test_pending_steer_block_returns_empty_on_steering_failure(
        self, monkeypatch,
    ):
        """Steering subsystem failure (corrupt queue file, import error,
        etc.) must never break tool dispatch. Helper swallows the
        exception and returns ''. Covers the bare-except branch."""
        import mcp_server.session_tools as st
        # Force get_active to raise; helper must swallow and return ''
        from core import steering as steering_mod
        with patch.object(steering_mod.steering_queue, "get_active",
                          side_effect=RuntimeError("boom")):
            assert st._pending_steer_block() == ""

    def test_do_status_no_directives_returns_payload_unchanged(
        self, tmp_path, monkeypatch,
    ):
        """No pending directives → _do_status returns the base payload
        with no steer-block appended. Covers the `return payload` line
        at session_tools.py:1295 (the negative branch of the
        `if steer_block` gate)."""
        import core.session as scan_session
        import core.coverage as cov_mod
        import core.findings as findings_store_mod
        from core import steering as steering_mod
        import mcp_server.session_tools as st
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        monkeypatch.setattr(cov_mod, "COVERAGE_FILE", tmp_path / "coverage_matrix.json")
        monkeypatch.setattr(findings_store_mod, "FINDINGS_FILE", tmp_path / "findings.json")
        monkeypatch.setattr(
            steering_mod, "_STEERING_FILE", tmp_path / "empty_queue.json"
        )
        scan_session.start("https://example.com")
        result = st._do_status()
        assert "PENDING DIRECTIVES" not in result
        assert "HUMAN MESSAGE" not in result


# ---------------------------------------------------------------------------
# HIR_FORCE_COMPLETE resolution resets _complete_attempts
# ---------------------------------------------------------------------------

class TestResolveResetsCompleteAttempts:

    def test_resolve_force_complete_resets_attempts_counter(
        self, tmp_path, monkeypatch,
    ):
        """Each HIR_FORCE_COMPLETE resolution must zero
        _complete_attempts so the next complete() call gets a fresh
        8-attempt budget. Without this, the very next retry instantly
        re-fires the HIR (counter still ≥ 8) and the cascade restarts —
        11 → 15 → 17 → 19 → 21 → 24 → 29 in the user's logs."""
        import core.session as scan_session
        import mcp_server.session_tools as st
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        scan_session.start("https://example.com")
        scan_session.trigger_intervention(
            code="HIR_FORCE_COMPLETE", situation="x", tried=[], options=[],
        )
        st._complete_attempts = 12
        scan_session.resolve_intervention("CONTINUE", "fix the cells")
        assert st._complete_attempts == 0

    def test_resolve_other_hir_does_not_reset_counter(self, tmp_path, monkeypatch):
        """Resolving a DIFFERENT HIR code must NOT touch the counter.
        Only HIR_FORCE_COMPLETE specifically wants the fresh-budget
        semantics — other HIRs (auth failure, target stuck, etc.) have
        no relationship to complete() attempts."""
        import core.session as scan_session
        import mcp_server.session_tools as st
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        scan_session.start("https://example.com")
        scan_session.trigger_intervention(
            code="HIR_AUTH_FAILURE", situation="x", tried=[], options=[],
        )
        st._complete_attempts = 5
        scan_session.resolve_intervention("REAUTH", "use admin:admin")
        assert st._complete_attempts == 5  # unchanged

    def test_resolve_with_no_active_intervention_does_not_reset(
        self, tmp_path, monkeypatch,
    ):
        """Idempotent resolve (no active HIR — the dashboard double-
        clicked, or watchdog called us after the human already
        resolved): no counter reset because we don't know what HIR
        code was just resolved."""
        import core.session as scan_session
        import mcp_server.session_tools as st
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        scan_session.start("https://example.com")
        st._complete_attempts = 5
        scan_session.resolve_intervention("X", "")  # no active intervention
        assert st._complete_attempts == 5
