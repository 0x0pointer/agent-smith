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


def test_add_testing_actions_emits_focused_batch():
    required: list = []
    recommended: list = []
    with patch.object(planner, "get_matrix", return_value=_matrix()), \
         patch("mcp_server.scan_engine.budget.get_profile", return_value={"next_batch_size": 10}):
        planner._add_testing_actions(required, recommended, "http://t")
    assert len(required) == 1
    msg = required[0]
    assert "/login" in msg and "overall" in msg          # endpoint focus + progress
    assert "cell c1" in msg and "cell c2" in msg          # whole batch, with concrete requests
    assert "bulk_tested" in msg and "next_batch" in msg   # close + loop guidance


def test_add_testing_actions_done_when_all_addressed():
    required: list = []
    recommended: list = []
    data = _matrix()
    for c in data["matrix"]:
        c["status"] = "tested_clean"
    with patch.object(planner, "get_matrix", return_value=data), \
         patch("mcp_server.scan_engine.budget.get_profile", return_value={"next_batch_size": 10}):
        planner._add_testing_actions(required, recommended, "http://t")
    assert required == []
    assert any("All cells addressed" in r for r in recommended)
