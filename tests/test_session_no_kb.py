from __future__ import annotations

import pytest

import core.session as scan_session
from mcp_server.session_tools import session
from mcp_server.session_tools.skills import _do_set_skill
from mcp_server.session_tools.start import _start_response


@pytest.mark.asyncio
async def test_kb_add_is_unknown_action():
    out = await session("kb_add", {}, None)
    assert "Unknown action 'kb_add'" in out
    assert "kb_add" not in out.split("Use:", 1)[1]


def test_start_message_has_no_local_kb_norm(monkeypatch):
    monkeypatch.setattr("core.dashboard_auth.read_token", lambda: None)
    msg = _start_response(
        {
            "limits": {"max_cost_usd": None, "max_time_minutes": None, "max_tool_calls": 0},
            "depth_label": "Standard",
            "model_profile": "full",
            "model_profile_reason": "test",
        },
        {"kind": "web", "skill_prior": "/web-exploit", "reason": "test target"},
        "http://target.test",
        "pentest",
        "standard",
        False,
    )
    assert "LOCAL KB AVAILABLE" not in msg
    assert "RECALL-FIRST" not in msg
    assert "scope:'kb'" not in msg
    assert "scope:'docs'" not in msg


def test_set_skill_has_no_recall_hint(monkeypatch):
    monkeypatch.setattr("core.quick_log.quick_log.append", lambda *a, **k: None)
    scan_session.start("http://target.test")
    out = _do_set_skill({"skill": "web-exploit", "reason": "test"})
    assert "Skill 'web-exploit' logged" in out
    assert "RECALL FIRST" not in out
    assert "LOCAL KB AVAILABLE" not in out
