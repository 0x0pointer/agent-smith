"""#3 defence-signature → technique index + #5 escalate on direction (not depth).

The index maps a MAPPED defence (alphanumerics blocked, UNION filtered, complete
tags stripped) to the specific second-order technique + the deterministic tool,
keyed to the defence CLASS so it generalises. The escalation flags techniques the
agent already tried so it changes direction.
"""
from datetime import datetime, timedelta, timezone

import pytest

import core.defense_signatures as ds
import core.qa_agent.checks_skills as cs


# ── index + matcher ──────────────────────────────────────────────────────────

def test_alnum_blocked_maps_to_jsfuck():
    hits = ds.match_observed("the filter blocks all alphanumeric characters", ["xss"])
    assert any(t.id == "xss_alnum_blocked" for t in hits)
    t = next(t for t in hits if t.id == "xss_alnum_blocked")
    assert "jsfuck" in t.tool.lower()


def test_complete_tag_stripped_maps_to_unclosed():
    hits = ds.match_observed("server strips tags with a <[^>]+> regex", ["xss"])
    assert any("unclosed" in t.technique.lower() or "omit the final" in t.technique.lower() for t in hits)


def test_union_filtered_maps_to_sql_keyword_tool():
    hits = ds.match_observed("the WAF says UNION is blocked", ["sqli"])
    t = next(t for t in hits if t.id == "sqli_union_filtered")
    assert "sql_keyword" in t.tool


def test_header_authz_maps_to_replay():
    hits = ds.match_observed("authorization is decided by the X-User-Id header", ["idor"])
    assert any(t.id == "idor_header_authz" for t in hits)


def test_class_filter_scopes_results():
    # an sqli signal should not surface xss techniques
    hits = ds.match_observed("union is blocked", ["xss"])
    assert all(t.cls == "xss" for t in hits)


# ── direction: already-tried technique must not lead ─────────────────────────

def test_recommend_demotes_tried_technique():
    blob = "union is blocked and i already tried UN/**/ION with inline comments"
    recs = ds.recommend(blob, ["sqli"], limit=4)
    # the union technique was tried (/**/), so an untried sqli technique must lead
    assert recs[0].id != "sqli_union_filtered"
    assert not any(m in blob.lower() for m in recs[0].tried_markers)


def test_untried_observed_leads_when_nothing_tried():
    recs = ds.recommend("letters are blocked in the output", ["xss"], limit=4)
    assert recs[0].id == "xss_alnum_blocked"


def test_render_table_flags_tried_and_names_tool():
    table = ds.render_decision_table("letters are blocked", ["xss"])
    assert "DEFENCE → TECHNIQUE" in table and "jsfuck" in table.lower()
    tried = ds.render_decision_table("letters are blocked; tried jsfuck ![]+", ["xss"])
    assert "already tried" in tried


def test_render_table_empty_for_unknown_class():
    assert ds.render_decision_table("anything", ["totally_unknown"]) == ""


# ── escalation delivers the table (direction change in the directive) ────────

DEEP = {"depth": "danger", "skill_history": []}
COV = {"endpoints": [{"path": "/x"}], "matrix": [{"injection_type": "ssti", "status": "pending"}]}


def _iso(delta_min=0):
    return (datetime.now(timezone.utc) + timedelta(minutes=delta_min)).isoformat()


@pytest.fixture
def directives(monkeypatch):
    calls = []
    monkeypatch.setattr(cs._qa, "_has_pending_directives", lambda: False)
    import core.steering as st
    monkeypatch.setattr(st.steering_queue, "add_directive", lambda **k: calls.append(k))
    monkeypatch.setattr(st.steering_queue, "get_active", lambda: [])
    return calls


def test_escalation_injects_defense_table(directives):
    # a finding mentions the mapped defence; no new finding for ~10 min → STUCK
    fd = {"findings": [{"timestamp": _iso(-10),
                        "description": "the {{ }} braces are blocked by the template filter"}]}
    alerts = cs._check_stuck_retrieval_escalation([], fd, DEEP, COV)
    assert alerts and alerts[0]["code"] == "STUCK_RETRIEVAL_ESCALATION"
    msg = directives[0]["message"]
    assert "CHANGE DIRECTION" in msg and "DEFENCE → TECHNIQUE" in msg
    assert "{% " in msg  # the statement-delimiter bypass for blocked {{ }}


def test_escalation_table_flags_tried_technique(directives):
    fd = {"findings": [{"timestamp": _iso(-10),
                        "description": "{{ }} braces are blocked"}]}
    # the agent already tried the {% %} bypass (tried_marker "{%")
    entries = [{"type": "TOOL", "name": "http_request", "command": "GET /x?q={%set%}"}]
    cs._check_stuck_retrieval_escalation(entries, fd, DEEP, COV)
    assert "already tried" in directives[0]["message"]
