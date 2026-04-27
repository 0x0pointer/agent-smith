"""
Tests for P0-P4: model profiles, tool invocations, known assets, tiered recovery, context tracking.
"""
import json
import pytest

from mcp_server.scan_engine.budget import (
    MODEL_PROFILES, get_profile, get_tool_budget, ToolBudget, TOOL_BUDGETS,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clean_session(monkeypatch):
    """Reset session state for each test."""
    import core.session as sess
    monkeypatch.setattr(sess, "_current", None)


@pytest.fixture
def running_session(monkeypatch):
    """Start a session and return it."""
    import core.session as sess
    import core.cost as cost
    cost.reset()
    return sess.start(target="http://t.com", depth="thorough")


@pytest.fixture
def small_session(monkeypatch):
    """Start a session with small profile."""
    import core.session as sess
    import core.cost as cost
    cost.reset()
    return sess.start(target="http://t.com", depth="thorough", model_profile="small")


# ---------------------------------------------------------------------------
# P0 — Model Profiles
# ---------------------------------------------------------------------------

class TestModelProfiles:
    def test_three_profiles_exist(self):
        assert set(MODEL_PROFILES.keys()) == {"full", "medium", "small"}

    def test_full_profile_no_enforcement(self):
        assert MODEL_PROFILES["full"]["enforce_budget"] is False

    def test_medium_profile_enforces_budget(self):
        assert MODEL_PROFILES["medium"]["enforce_budget"] is True
        assert MODEL_PROFILES["medium"]["budget_multiplier"] == 1.0

    def test_small_profile_half_budget(self):
        assert MODEL_PROFILES["small"]["enforce_budget"] is True
        assert MODEL_PROFILES["small"]["budget_multiplier"] == 0.5

    def test_full_no_context_limit(self):
        assert MODEL_PROFILES["full"]["context_budget_chars"] is None

    def test_small_has_context_limit(self):
        assert MODEL_PROFILES["small"]["context_budget_chars"] == 64_000

    def test_get_profile_defaults_to_full(self):
        profile = get_profile()
        assert profile == MODEL_PROFILES["full"]

    def test_get_profile_by_name(self):
        assert get_profile("small") == MODEL_PROFILES["small"]

    def test_get_profile_unknown_falls_back_to_full(self):
        assert get_profile("nonexistent") == MODEL_PROFILES["full"]

    def test_get_profile_reads_from_session(self, small_session):
        profile = get_profile()
        assert profile == MODEL_PROFILES["small"]

    def test_get_tool_budget_full_generous(self):
        """Full profile returns 10x base budget (effectively no limit)."""
        import core.session as sess
        sess.start(target="http://t.com", model_profile="full")
        budget = get_tool_budget("httpx")
        base = TOOL_BUDGETS["httpx"]
        assert budget.max_chars == base.max_chars * 10
        assert budget.max_facts == base.max_facts * 5

    def test_get_tool_budget_medium_unchanged(self):
        """Medium profile returns base budgets as-is."""
        import core.session as sess
        sess.start(target="http://t.com", model_profile="medium")
        budget = get_tool_budget("httpx")
        base = TOOL_BUDGETS["httpx"]
        assert budget.max_chars == base.max_chars
        assert budget.max_facts == base.max_facts

    def test_get_tool_budget_small_halved(self):
        """Small profile returns ~half budgets."""
        import core.session as sess
        sess.start(target="http://t.com", model_profile="small")
        budget = get_tool_budget("httpx")
        base = TOOL_BUDGETS["httpx"]
        assert budget.max_chars == int(base.max_chars * 0.5)

    def test_get_tool_budget_small_has_minimum(self):
        """Small profile doesn't go below minimum values."""
        import core.session as sess
        sess.start(target="http://t.com", model_profile="small")
        budget = get_tool_budget("naabu")
        assert budget.max_chars >= 500
        assert budget.max_facts >= 3
        assert budget.max_evidence_chars >= 200

    def test_session_stores_model_profile(self, running_session):
        assert running_session["model_profile"] == "full"

    def test_session_stores_small_profile(self, small_session):
        assert small_session["model_profile"] == "small"


# ---------------------------------------------------------------------------
# P1 — Tool Invocations
# ---------------------------------------------------------------------------

class TestToolInvocations:
    def test_add_invocation(self, running_session):
        import core.session as sess
        sess.add_tool_invocation("httpx", "http://t.com", "Target is live (HTTP 200)")
        current = sess.get()
        assert len(current["tool_invocations"]) == 1
        inv = current["tool_invocations"][0]
        assert inv["tool"] == "httpx"
        assert inv["target"] == "http://t.com"
        assert inv["summary"] == "Target is live (HTTP 200)"
        assert inv["seq"] == 1

    def test_invocations_have_timestamp(self, running_session):
        import core.session as sess
        sess.add_tool_invocation("nmap", "t.com", "3 ports open")
        inv = sess.get()["tool_invocations"][0]
        assert "timestamp" in inv

    def test_dedup_by_options_hash(self, running_session):
        import core.session as sess
        sess.add_tool_invocation("httpx", "http://t.com", "summary1", options_hash="abc123")
        sess.add_tool_invocation("httpx", "http://t.com", "summary2", options_hash="abc123")
        assert len(sess.get()["tool_invocations"]) == 1

    def test_different_hash_not_deduped(self, running_session):
        import core.session as sess
        sess.add_tool_invocation("httpx", "http://t.com", "summary1", options_hash="aaa")
        sess.add_tool_invocation("nmap", "t.com", "summary2", options_hash="bbb")
        assert len(sess.get()["tool_invocations"]) == 2

    def test_no_hash_never_deduped(self, running_session):
        import core.session as sess
        sess.add_tool_invocation("kali", "t.com", "run1")
        sess.add_tool_invocation("kali", "t.com", "run2")
        assert len(sess.get()["tool_invocations"]) == 2

    def test_summary_truncated_at_200(self, running_session):
        import core.session as sess
        long_summary = "A" * 500
        sess.add_tool_invocation("test", "t.com", long_summary)
        assert len(sess.get()["tool_invocations"][0]["summary"]) == 200

    def test_rotation_at_100(self, running_session):
        import core.session as sess
        for i in range(110):
            sess.add_tool_invocation("tool", "t.com", f"call {i}")
        invocations = sess.get()["tool_invocations"]
        assert len(invocations) <= 100
        assert invocations[0]["summary"] == "call 10"

    def test_no_session_silently_ignored(self):
        import core.session as sess
        sess.add_tool_invocation("httpx", "t.com", "test")
        # No error, no crash

    def test_initial_empty(self, running_session):
        assert running_session["tool_invocations"] == []


# ---------------------------------------------------------------------------
# P2 — Known Assets
# ---------------------------------------------------------------------------

class TestKnownAssets:
    def test_initial_structure(self, running_session):
        assets = running_session["known_assets"]
        assert set(assets.keys()) == {"domains", "ips", "ports", "technologies", "endpoints"}
        assert all(isinstance(v, list) for v in assets.values())

    def test_add_domains(self, running_session):
        import core.session as sess
        sess.update_known_assets("domains", ["api.t.com", "www.t.com"])
        assets = sess.get()["known_assets"]
        assert "api.t.com" in assets["domains"]
        assert "www.t.com" in assets["domains"]

    def test_dedup_domains(self, running_session):
        import core.session as sess
        sess.update_known_assets("domains", ["api.t.com"])
        sess.update_known_assets("domains", ["api.t.com", "new.t.com"])
        assets = sess.get()["known_assets"]
        assert assets["domains"].count("api.t.com") == 1
        assert "new.t.com" in assets["domains"]

    def test_add_ports(self, running_session):
        import core.session as sess
        sess.update_known_assets("ports", [
            {"host": "t.com", "port": 80},
            {"host": "t.com", "port": 443},
        ])
        ports = sess.get()["known_assets"]["ports"]
        assert len(ports) == 2
        assert {"host": "t.com", "port": 80} in ports

    def test_dedup_ports(self, running_session):
        import core.session as sess
        sess.update_known_assets("ports", [{"host": "t.com", "port": 80}])
        sess.update_known_assets("ports", [{"host": "t.com", "port": 80}])
        assert len(sess.get()["known_assets"]["ports"]) == 1

    def test_add_technologies(self, running_session):
        import core.session as sess
        sess.update_known_assets("technologies", ["nginx", "Flask"])
        tech = sess.get()["known_assets"]["technologies"]
        assert "nginx" in tech
        assert "Flask" in tech

    def test_add_endpoints(self, running_session):
        import core.session as sess
        sess.update_known_assets("endpoints", ["/api/users", "/login"])
        eps = sess.get()["known_assets"]["endpoints"]
        assert "/api/users" in eps

    def test_empty_items_ignored(self, running_session):
        import core.session as sess
        sess.update_known_assets("domains", [])
        assert sess.get()["known_assets"]["domains"] == []

    def test_no_session_silently_ignored(self):
        import core.session as sess
        sess.update_known_assets("domains", ["test.com"])
        # No crash


# ---------------------------------------------------------------------------
# P3 — Tiered Recovery
# ---------------------------------------------------------------------------

class TestTieredRecovery:
    def test_full_profile_shows_all_cells(self):
        profile = get_profile("full")
        assert profile["recovery_cells_shown"] is None

    def test_medium_profile_shows_10_cells(self):
        profile = get_profile("medium")
        assert profile["recovery_cells_shown"] == 10

    def test_small_profile_shows_3_cells(self):
        profile = get_profile("small")
        assert profile["recovery_cells_shown"] == 3


# ---------------------------------------------------------------------------
# P4 — Context Tracking
# ---------------------------------------------------------------------------

class TestContextTracking:
    def test_charge_context(self, running_session):
        import core.session as sess
        sess.charge_context(1000)
        sess.charge_context(2000)
        assert sess.get()["context_chars_sent"] == 3000

    def test_initial_zero(self, running_session):
        assert running_session["context_chars_sent"] == 0

    def test_pressure_zero_for_full_profile(self, running_session):
        import core.session as sess
        sess.charge_context(999_999)
        profile = get_profile("full")
        assert sess.get_context_pressure(profile) == 0.0

    def test_pressure_for_small_profile(self, small_session):
        import core.session as sess
        sess.charge_context(32_000)  # half of 64K budget
        profile = get_profile("small")
        assert sess.get_context_pressure(profile) == pytest.approx(0.5, abs=0.01)

    def test_pressure_caps_at_1(self, small_session):
        import core.session as sess
        sess.charge_context(200_000)  # way over 64K budget
        profile = get_profile("small")
        assert sess.get_context_pressure(profile) == 1.0

    def test_pressure_no_session_returns_zero(self):
        import core.session as sess
        profile = get_profile("small")
        assert sess.get_context_pressure(profile) == 0.0

    def test_no_session_charge_silently_ignored(self):
        import core.session as sess
        sess.charge_context(5000)
        # No crash
