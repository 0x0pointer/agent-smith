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


def test_add_testing_actions_drives_focused_batch():
    """Continuous drive: hand the next focused batch (endpoint-grouped) with a
    concrete command per cell + progress, framed as 'work the matrix'. Anti-grind
    lives in the framing (real probes, honest closures) + the completion gate, not
    in starving the model of guidance."""
    required: list = []
    recommended: list = []
    with patch.object(planner, "get_matrix", return_value=_matrix()):
        planner._add_testing_actions(required, recommended, "http://t")
    assert len(required) == 1
    msg = required[0]
    # both cells on the focused endpoint are handed as a batch, sqli first
    assert "cell c1" in msg and "cell c2" in msg
    assert "WORK THE MATRIX" in msg
    assert "overall" in msg            # progress is surfaced
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


# ── _inject_pending_gates — required-before-completion, not drop-everything-NOW ──

def test_inject_pending_gates_lets_model_finish_recon_first():
    """The chain directive must read as a completion-time requirement that lets the
    model finish its current recon/mapping step — not an insistent 'invoke NOW,
    before any other action, do not defer' that yanks it mid-recon."""
    required = []
    gate = {"id": "auth_coverage", "required_skills": ["credential-audit"],
            "trigger": "auth endpoint /login"}
    with patch("core.session.pending_gates", return_value=[gate]), \
         patch("core.session.get", return_value={"skill_history": []}):
        planner._inject_pending_gates(required)
    assert len(required) == 1
    msg = required[0].lower()
    assert "credential-audit" in msg
    assert "before completion" in msg
    assert "finish your current recon" in msg
    # No drop-everything-now insistence
    assert "before any other action" not in msg
    assert "invoke /credential-audit now" not in msg
    assert "do not defer" not in msg


def test_inject_pending_gates_skips_already_invoked_skill():
    required = []
    gate = {"id": "auth_coverage", "required_skills": ["credential-audit"], "trigger": "auth"}
    with patch("core.session.pending_gates", return_value=[gate]), \
         patch("core.session.get", return_value={"skill_history": [{"skill": "credential-audit"}]}):
        planner._inject_pending_gates(required)
    assert required == []   # skill already chained → no directive
