"""Tests for mcp_server.scan_engine.planner — focused testing-phase guidance."""
from unittest.mock import patch

from mcp_server.scan_engine import planner


def _matrix():
    return {
        "endpoints": [{"id": "ep1", "path": "/login", "method": "POST", "auth_context": "none"}],
        "matrix": [
            {"id": "c1", "endpoint_id": "ep1", "param": "u", "param_type": "body_json",
             "injection_type": "sqli", "status": "pending"},
            {"id": "c2", "endpoint_id": "ep1", "param": "u", "param_type": "body_json",
             "injection_type": "xss", "status": "pending"},
        ],
    }


def test_add_testing_actions_emits_single_high_priority_cell():
    """Single highest-priority pending cell, NOT a 10-cell batch with canned
    payloads. The batch loop drove the model to grind cells with naive payloads
    and false-negative real vulnerabilities — see the coverage-grind regression."""
    required: list = []
    recommended: list = []
    with patch.object(planner, "get_matrix", return_value=_matrix()):
        planner._add_testing_actions(required, recommended, "http://t")
    assert len(required) == 1
    msg = required[0]
    # sqli wins the priority order over xss
    assert "cell c1" in msg
    assert "cell c2" not in msg  # not a batch
    # planner emits a concrete suggestion for the chosen cell only
    assert "sqlmap" in msg.lower() or "/login" in msg


def test_add_testing_actions_done_when_all_addressed():
    required: list = []
    recommended: list = []
    data = _matrix()
    for c in data["matrix"]:
        c["status"] = "tested_clean"
    with patch.object(planner, "get_matrix", return_value=data):
        planner._add_testing_actions(required, recommended, "http://t")
    assert required == []
    assert any("All cells addressed" in r for r in recommended)
