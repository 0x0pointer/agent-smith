"""Tests for the stuck-triggered, technique-focused retrieval escalation.

Progress-gated recovery: when a deep-pivot scan stalls on an unsolved web target
(no new finding for a while), force a RETRIEVAL escalation — study the technique
reference + research a methodology source + ADAPT — rather than letting it repeat
or give up. Must NOT fire for a non-deep-pivot scan, before recon, while findings
are still flowing, or while web-exploit is already running.
"""
from datetime import datetime, timedelta, timezone

import pytest

import core.qa_agent.checks_skills as cs


def _iso(delta_min=0):
    return (datetime.now(timezone.utc) + timedelta(minutes=delta_min)).isoformat()


DEEP = {"depth": "danger", "skill_history": []}
COV = {"endpoints": [{"path": "/x"}], "matrix": [{"injection_type": "ssti", "status": "pending"}]}


@pytest.fixture
def directives(monkeypatch):
    """Capture injected directives + force no-pending so the check proceeds."""
    calls = []
    monkeypatch.setattr(cs._qa, "_has_pending_directives", lambda: False)
    import core.steering as st
    monkeypatch.setattr(st.steering_queue, "add_directive", lambda **k: calls.append(k))
    return calls


def test_not_deep_pivot_no_fire():
    assert cs._check_stuck_retrieval_escalation([], {}, {"depth": "standard"}, COV) == []


def test_before_recon_no_fire():
    assert cs._check_stuck_retrieval_escalation([], {}, DEEP, {"endpoints": []}) == []


def test_findings_still_flowing_not_stuck(directives):
    fd = {"findings": [{"ts": _iso(0)}]}  # a finding just landed
    assert cs._check_stuck_retrieval_escalation([], fd, DEEP, COV) == []
    assert directives == []


def test_stalled_fires_with_technique_framing(directives):
    fd = {"findings": [{"ts": _iso(-10)}]}  # no new finding for ~10 min
    alerts = cs._check_stuck_retrieval_escalation([], fd, DEEP, COV)
    assert alerts and alerts[0]["code"] == "STUCK_RETRIEVAL_ESCALATION"
    assert directives and directives[0]["trigger"] == "STUCK_RETRIEVAL_ESCALATION"
    msg = directives[0]["message"]
    assert "refs/ssti.md" in msg          # points at the right local technique ref
    assert "hacktricks" in msg.lower()    # + a methodology source to research
    assert "ADAPT" in msg and "payload list" in msg.lower()  # technique, not payloads


def test_already_escalating_no_fire(directives):
    fd = {"findings": [{"ts": _iso(-10)}]}
    sess = {"depth": "danger", "skill_history": [{"skill": "web-exploit", "ts": _iso(-2)}]}
    assert cs._check_stuck_retrieval_escalation([], fd, sess, COV) == []


def test_sources_are_methodology_urls():
    for c in ("ssti", "sqli", "cmdi", "xxe", "ssrf", "traversal", "deserialization"):
        ref, url = cs._RETRIEVAL_SOURCES[c]
        assert ref.endswith(".md") and url.startswith("https://")
