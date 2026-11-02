"""Phase 1 of the depth=danger feature (docs/plan-danger-depth.md):

the `danger` depth preset behaves exactly like `thorough`, driven by the two
new predicates `is_thorough_like` / `deep_pivot_enabled` so the behaviour lives
in one place instead of scattered `== "thorough"` literals.
"""
import pytest

import core.session as scan_session
from core.session import THOROUGH_LIKE, is_thorough_like, deep_pivot_enabled


# ── preset ────────────────────────────────────────────────────────────────────

def test_danger_preset_exists_and_is_unlimited_like_thorough():
    d = scan_session.PRESETS["danger"]
    t = scan_session.PRESETS["thorough"]
    assert d["max_cost_usd"] is None and d["max_time_minutes"] is None
    assert d["max_tool_calls"] == 0            # 0 == unlimited
    # same hard-limit shape as thorough
    assert (d["max_cost_usd"], d["max_time_minutes"], d["max_tool_calls"]) == \
           (t["max_cost_usd"], t["max_time_minutes"], t["max_tool_calls"])


# ── is_thorough_like ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("depth,expected", [
    ("thorough", True), ("danger", True),
    ("standard", False), ("recon", False), ("", False), (None, False),
    ("nonexistent", False),
])
def test_is_thorough_like(depth, expected):
    assert is_thorough_like(depth) is expected


def test_thorough_like_set_membership():
    assert THOROUGH_LIKE == frozenset({"thorough", "danger"})


# ── deep_pivot_enabled ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("session,expected", [
    ({"depth": "danger", "scan_mode": "pentest"}, True),      # danger ⇒ deep pivot
    ({"depth": "standard", "scan_mode": "benchmark"}, True),  # benchmark ⇒ deep pivot
    ({"depth": "danger", "scan_mode": "benchmark"}, True),    # both
    ({"depth": "thorough", "scan_mode": "pentest"}, False),   # thorough alone does NOT
    ({"depth": "standard", "scan_mode": "pentest"}, False),
    ({}, False),
    (None, False),
])
def test_deep_pivot_enabled(session, expected):
    assert deep_pivot_enabled(session) is expected


def test_predicates_are_distinct():
    # thorough is thorough-like but NOT deep-pivot; benchmark-standard is the inverse
    assert is_thorough_like("thorough") and not deep_pivot_enabled({"depth": "thorough"})
    s = {"depth": "standard", "scan_mode": "benchmark"}
    assert deep_pivot_enabled(s) and not is_thorough_like(s["depth"])


# ── start() wiring: danger gets thorough's unlimited limits + stores the label ──

def test_start_danger_stores_depth_and_unlimited_limits():
    sess = scan_session.start("example.com", depth="danger")
    assert sess["depth"] == "danger"
    assert sess["limits"]["max_cost_usd"] is None
    assert sess["limits"]["max_time_minutes"] is None
    assert sess["limits"]["max_tool_calls"] == 0
    assert is_thorough_like(sess["depth"])


def test_start_danger_is_deep_pivot_enabled():
    sess = scan_session.start("example.com", depth="danger")
    assert deep_pivot_enabled(sess) is True


# ── one concrete swapped-site proof: recovery analysis-pass line now fires for danger ──

def test_recovery_iter_status_fires_for_danger():
    from mcp_server.session_tools.recovery_build import _recovery_iter_status
    # thorough-like depths get the "Analysis pass X/N" progress line…
    assert _recovery_iter_status({"depth": "danger"}) is not None
    assert _recovery_iter_status({"depth": "thorough"}) is not None
    # …non-thorough-like depths still return None (behaviour unchanged)
    assert _recovery_iter_status({"depth": "standard"}) is None
    assert _recovery_iter_status({"depth": "recon"}) is None
