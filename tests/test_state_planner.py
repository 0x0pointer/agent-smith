"""
Tests for scan_engine state.py and planner.py — M2 server-driven workflow.
"""
import pytest

from mcp_server.scan_engine.state import get_state, _compute_phase
from mcp_server.scan_engine.planner import compute_next, _detect_drift


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def mock_session_and_cost(monkeypatch):
    """Default: no active scan. Tests override via helpers.

    Patches both the canonical modules AND the already-imported references
    in state.py and planner.py (which use `from X import Y` style).
    """
    import core.session as sess
    import core.cost as cost
    import core.coverage as cov
    import mcp_server.scan_engine.state as state_mod
    import mcp_server.scan_engine.planner as planner_mod

    empty_matrix = {
        "meta": {"total_cells": 0, "tested": 0, "vulnerable": 0, "not_applicable": 0, "skipped": 0},
        "endpoints": [],
        "matrix": [],
    }

    monkeypatch.setattr(sess, "get", lambda: None)
    monkeypatch.setattr(cost, "get_summary", lambda: {"tool_calls_total": 0, "est_cost_usd": 0})
    monkeypatch.setattr(sess, "remaining", lambda s: {"time_pct": 0})
    monkeypatch.setattr(cov, "get_matrix", lambda: empty_matrix)
    # Patch already-imported references
    monkeypatch.setattr(state_mod, "get_matrix", lambda: empty_matrix)
    monkeypatch.setattr(planner_mod, "get_matrix", lambda: empty_matrix)


def _set_session(monkeypatch, session_data):
    import core.session as sess
    import mcp_server.scan_engine.state as state_mod
    monkeypatch.setattr(sess, "get", lambda: session_data)
    monkeypatch.setattr(state_mod.scan_session, "get", lambda: session_data)


def _set_coverage(monkeypatch, endpoints=None, matrix=None, meta=None):
    import core.coverage as cov
    import mcp_server.scan_engine.state as state_mod
    import mcp_server.scan_engine.planner as planner_mod
    data = {
        "meta": meta or {"total_cells": 0, "tested": 0, "vulnerable": 0, "not_applicable": 0, "skipped": 0},
        "endpoints": endpoints or [],
        "matrix": matrix or [],
    }
    monkeypatch.setattr(cov, "get_matrix", lambda: data)
    monkeypatch.setattr(state_mod, "get_matrix", lambda: data)
    monkeypatch.setattr(planner_mod, "get_matrix", lambda: data)


# ---------------------------------------------------------------------------
# State tests
# ---------------------------------------------------------------------------

class TestState:
    def test_idle_when_no_session(self):
        state = get_state()
        assert state["phase"] == "idle"
        assert state["status"] == "no_active_scan"

    def test_idle_when_session_not_running(self, monkeypatch):
        _set_session(monkeypatch, {"status": "complete", "target": "http://t.com"})
        state = get_state()
        assert state["phase"] == "idle"

    def test_recon_phase_fresh_scan(self, monkeypatch):
        _set_session(monkeypatch, {
            "status": "running", "target": "http://t.com", "tools_called": [],
        })
        state = get_state()
        assert state["phase"] == "recon"
        assert state["target"] == "http://t.com"

    def test_recon_with_nmap_only(self, monkeypatch):
        _set_session(monkeypatch, {
            "status": "running", "target": "http://t.com", "tools_called": ["nmap"],
        })
        state = get_state()
        assert state["phase"] == "recon"

    def test_discovery_phase_httpx_no_endpoints(self, monkeypatch):
        _set_session(monkeypatch, {
            "status": "running", "target": "http://t.com",
            "tools_called": ["naabu", "httpx"],
        })
        state = get_state()
        assert state["phase"] == "discovery"

    def test_testing_phase_with_pending_cells(self, monkeypatch):
        _set_session(monkeypatch, {
            "status": "running", "target": "http://t.com",
            "tools_called": ["httpx", "spider"],
        })
        _set_coverage(monkeypatch,
            endpoints=[{"id": "ep-1", "path": "/api", "method": "GET"}],
            matrix=[
                {"id": "c1", "endpoint_id": "ep-1", "param": "q", "injection_type": "sqli", "status": "pending"},
            ],
            meta={"total_cells": 1, "tested": 0, "vulnerable": 0, "not_applicable": 0, "skipped": 0},
        )
        state = get_state()
        assert state["phase"] == "testing"
        assert state["coverage"] == "0/1"
        assert state["endpoints"] == 1

    def test_validation_phase_all_tested(self, monkeypatch):
        _set_session(monkeypatch, {
            "status": "running", "target": "http://t.com",
            "tools_called": ["httpx", "spider", "kali"],
        })
        _set_coverage(monkeypatch,
            endpoints=[{"id": "ep-1"}],
            matrix=[
                {"id": "c1", "endpoint_id": "ep-1", "param": "q", "injection_type": "sqli", "status": "tested_clean"},
            ],
            meta={"total_cells": 1, "tested": 1, "vulnerable": 0, "not_applicable": 0, "skipped": 0},
        )
        state = get_state()
        assert state["phase"] == "validation"


class TestComputePhase:
    def test_no_tools_is_recon(self):
        assert _compute_phase(set(), 0, 0, 0) == "recon"

    def test_recon_tools_only(self):
        assert _compute_phase({"nmap", "subfinder"}, 0, 0, 0) == "recon"

    def test_discovery_tools_no_endpoints(self):
        assert _compute_phase({"httpx", "spider"}, 0, 0, 0) == "discovery"

    def test_testing_with_pending_cells(self):
        assert _compute_phase({"httpx", "spider"}, 3, 10, 2) == "testing"

    def test_validation_all_done(self):
        assert _compute_phase({"httpx", "spider"}, 3, 10, 10) == "validation"


# ---------------------------------------------------------------------------
# Planner tests
# ---------------------------------------------------------------------------

class TestPlanner:
    def test_idle_requires_start(self):
        plan = compute_next("httpx", {"phase": "idle", "target": "http://t.com"})
        assert len(plan["required"]) == 1
        assert "start" in plan["required"][0].lower() or "session" in plan["required"][0].lower()

    def test_recon_requires_httpx(self):
        plan = compute_next("nmap", {
            "phase": "recon", "tools_run": [], "target": "http://t.com",
        })
        assert any("httpx" in r.lower() for r in plan["required"])

    def test_recon_httpx_done_no_duplicate(self):
        plan = compute_next("nmap", {
            "phase": "recon", "tools_run": ["httpx"], "target": "http://t.com",
        })
        assert not any("httpx" in r.lower() for r in plan["required"])

    def test_recon_recommends_port_scan(self):
        plan = compute_next("httpx", {
            "phase": "recon", "tools_run": ["httpx"], "target": "http://t.com",
        })
        assert any("naabu" in r.lower() or "port" in r.lower() for r in plan["recommended"])

    def test_discovery_requires_spider(self):
        plan = compute_next("httpx", {
            "phase": "discovery", "tools_run": ["httpx"], "target": "http://t.com",
        })
        assert any("spider" in r.lower() for r in plan["required"])

    def test_discovery_spider_done_requires_register(self):
        plan = compute_next("spider", {
            "phase": "discovery", "tools_run": ["httpx", "spider"], "target": "http://t.com",
        })
        assert any("register" in r.lower() or "coverage" in r.lower() for r in plan["required"])

    def test_validation_recommends_complete(self):
        plan = compute_next("kali", {
            "phase": "validation", "tools_run": ["httpx", "spider", "kali"],
            "target": "http://t.com",
        })
        assert any("complete" in r.lower() for r in plan["recommended"])

    def test_validation_recommends_pocs(self):
        plan = compute_next("kali", {
            "phase": "validation", "tools_run": ["httpx", "spider", "kali"],
            "target": "http://t.com",
        })
        assert any("poc" in r.lower() for r in plan["recommended"])


class TestPlannerTesting:
    """Test the coverage-matrix-driven testing planner."""

    def test_testing_picks_highest_priority(self, monkeypatch):
        _set_session(monkeypatch, {
            "status": "running", "target": "http://t.com",
            "tools_called": ["httpx", "spider"],
        })
        _set_coverage(monkeypatch,
            endpoints=[{"id": "ep-1", "path": "/search", "method": "GET"}],
            matrix=[
                {"id": "c1", "endpoint_id": "ep-1", "param": "q", "injection_type": "xss", "status": "pending"},
                {"id": "c2", "endpoint_id": "ep-1", "param": "q", "injection_type": "sqli", "status": "pending"},
            ],
            meta={"total_cells": 2, "tested": 0, "vulnerable": 0, "not_applicable": 0, "skipped": 0},
        )
        state = get_state()
        plan = compute_next("spider", state)
        # sqli should be picked first (higher priority than xss)
        required_text = " ".join(plan["required"]).lower()
        assert "sqli" in required_text

    def test_testing_continues_in_progress(self, monkeypatch):
        _set_session(monkeypatch, {
            "status": "running", "target": "http://t.com",
            "tools_called": ["httpx", "spider"],
        })
        _set_coverage(monkeypatch,
            endpoints=[{"id": "ep-1", "path": "/api", "method": "POST"}],
            matrix=[
                {"id": "c1", "endpoint_id": "ep-1", "param": "id", "injection_type": "sqli", "status": "in_progress"},
                {"id": "c2", "endpoint_id": "ep-1", "param": "id", "injection_type": "xss", "status": "pending"},
            ],
            meta={"total_cells": 2, "tested": 0, "vulnerable": 0, "not_applicable": 0, "skipped": 0},
        )
        state = get_state()
        plan = compute_next("kali", state)
        required_text = " ".join(plan["required"]).lower()
        assert "continue" in required_text

    def test_testing_all_done_recommends_validation(self, monkeypatch):
        _set_session(monkeypatch, {
            "status": "running", "target": "http://t.com",
            "tools_called": ["httpx", "spider"],
        })
        _set_coverage(monkeypatch,
            endpoints=[{"id": "ep-1"}],
            matrix=[
                {"id": "c1", "endpoint_id": "ep-1", "param": "q", "injection_type": "sqli", "status": "tested_clean"},
            ],
            meta={"total_cells": 1, "tested": 1, "vulnerable": 0, "not_applicable": 0, "skipped": 0},
        )
        state = get_state()
        plan = compute_next("kali", state)
        recommended_text = " ".join(plan["recommended"]).lower()
        assert "complete" in recommended_text or "poc" in recommended_text


# ---------------------------------------------------------------------------
# Drift detection tests
# ---------------------------------------------------------------------------

class TestDriftDetection:
    def test_exploitation_during_recon(self):
        warnings = _detect_drift("kali", "recon", set())
        assert any("DRIFT" in w for w in warnings)

    def test_recon_during_testing(self):
        warnings = _detect_drift("naabu", "testing", {"httpx", "spider"})
        assert any("DRIFT" in w for w in warnings)

    def test_spider_before_httpx(self):
        warnings = _detect_drift("spider", "discovery", set())
        assert any("DRIFT" in w for w in warnings)

    def test_no_drift_normal_flow(self):
        warnings = _detect_drift("httpx", "recon", set())
        assert len(warnings) == 0

    def test_no_drift_spider_after_httpx(self):
        warnings = _detect_drift("spider", "discovery", {"httpx"})
        assert len(warnings) == 0
