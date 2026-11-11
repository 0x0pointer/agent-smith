"""Tests for the stuck-triggered, technique-focused retrieval escalation.

Progress-gated recovery: when a deep-pivot scan stalls on an unsolved web target
(no new finding for a while), force a RETRIEVAL escalation that HARNESS-DELIVERS the
technique (reads the local ref and injects a bounded slice inline) rather than only
telling the model to go read/research — because the benchmark model never opens a ref
or webfetches on its own. Must NOT fire for a non-deep-pivot scan, before recon, while
findings are still flowing, or while the web-exploit chain is actually producing.

Two guards were loosened after the first benchmark pass fired the check 0 times:
  Fix 1  web-exploit recency no longer muzzles it outright — only when a finding has
         landed SINCE web-exploit ran (chain is helping). 022 stalled behind this.
  (023)  an UNRELATED pending directive (MISSING_WEB_EXPLOIT) no longer suppresses it;
         only a still-outstanding STUCK directive does (no stacking STUCK on STUCK).
"""
from datetime import datetime, timedelta, timezone

import pytest

import core.qa_agent.checks_skills as cs


def _iso(delta_min=0):
    return (datetime.now(timezone.utc) + timedelta(minutes=delta_min)).isoformat()


DEEP = {"depth": "danger", "skill_history": []}
COV = {"endpoints": [{"path": "/x"}], "matrix": [{"injection_type": "ssti", "status": "pending"}]}


class _Dir:
    def __init__(self, trigger):
        self.trigger = trigger


@pytest.fixture
def directives(monkeypatch):
    """Capture injected directives + force no-pending so the check proceeds."""
    calls = []
    monkeypatch.setattr(cs._qa, "_has_pending_directives", lambda: False)
    import core.steering as st
    monkeypatch.setattr(st.steering_queue, "add_directive", lambda **k: calls.append(k))
    monkeypatch.setattr(st.steering_queue, "get_active", lambda: [])
    return calls


@pytest.fixture
def refs_dir(tmp_path, monkeypatch):
    """A deterministic local ssti ref so Fix 2's inline injection is machine-independent."""
    d = tmp_path / "refs"
    d.mkdir()
    (d / "ssti.md").write_text(
        "### Ref: Server-Side Template Injection (SSTI)\n"
        "Ladder rung 1 — direct-globals gadgets (Flask/Jinja2).\n"
        "Ladder rung 4 — filter bypass via |attr() when dots/underscores are blocked.\n"
        "Blind SSTI via include sink: upload a Jinja-laden file under static/images/.\n"
    )
    monkeypatch.setattr(cs, "_REFS_DIRS", [str(d)])
    return d


def test_not_deep_pivot_no_fire():
    assert cs._check_stuck_retrieval_escalation([], {}, {"depth": "standard"}, COV) == []


def test_before_recon_no_fire():
    assert cs._check_stuck_retrieval_escalation([], {}, DEEP, {"endpoints": []}) == []


def test_findings_still_flowing_not_stuck(directives):
    fd = {"findings": [{"ts": _iso(0)}]}  # a finding just landed
    assert cs._check_stuck_retrieval_escalation([], fd, DEEP, COV) == []
    assert directives == []


def test_stalled_fires_with_technique_framing(directives, refs_dir):
    fd = {"findings": [{"ts": _iso(-10)}]}  # no new finding for ~10 min
    alerts = cs._check_stuck_retrieval_escalation([], fd, DEEP, COV)
    assert alerts and alerts[0]["code"] == "STUCK_RETRIEVAL_ESCALATION"
    assert directives and directives[0]["trigger"] == "STUCK_RETRIEVAL_ESCALATION"
    msg = directives[0]["message"]
    assert "refs/ssti.md" in msg                    # the right technique ref, attributed
    assert "hacktricks" in msg.lower()              # + a methodology source to research
    assert "ADAPT" in msg and "payload list" in msg.lower()  # technique, not payloads


def test_fix2_harness_injects_technique_text_inline(directives, refs_dir):
    """Fix 2: the actual ref CONTENT is delivered in the directive, not just a path."""
    fd = {"findings": [{"ts": _iso(-10)}]}
    cs._check_stuck_retrieval_escalation([], fd, DEEP, COV)
    msg = directives[0]["message"]
    assert "HARNESS-PROVIDED TECHNIQUE REFERENCE" in msg
    assert "Ladder rung 1" in msg          # real ref body, inline
    assert "|attr()" in msg                # the bypass the model kept fumbling toward


def test_fix1_web_exploit_ran_with_finding_since_suppressed(directives, refs_dir):
    """web-exploit ran 2min ago AND a finding landed after it → chain producing → hold off."""
    sess = {"depth": "danger", "skill_history": [{"skill": "web-exploit", "ts": _iso(-2)}]}
    fd = {"findings": [{"ts": _iso(-1)}]}  # finding AFTER web-exploit
    assert cs._check_stuck_retrieval_escalation([], fd, sess, COV) == []


def test_fix1_web_exploit_ran_but_no_finding_since_fires(directives, refs_dir):
    """022 case: web-exploit ran recently but produced nothing since → chain didn't help → FIRE."""
    sess = {"depth": "danger", "skill_history": [{"skill": "web-exploit", "ts": _iso(-2)}]}
    fd = {"findings": [{"ts": _iso(-10)}]}  # last finding predates web-exploit
    alerts = cs._check_stuck_retrieval_escalation([], fd, sess, COV)
    assert alerts and alerts[0]["code"] == "STUCK_RETRIEVAL_ESCALATION"


def test_023_unrelated_pending_directive_does_not_suppress(directives, refs_dir, monkeypatch):
    """023 case: a pending MISSING_WEB_EXPLOIT must not muzzle retrieval escalation."""
    import core.steering as st
    monkeypatch.setattr(st.steering_queue, "get_active", lambda: [_Dir("MISSING_WEB_EXPLOIT")])
    fd = {"findings": []}  # zero findings — the most-stuck state
    sess = {"depth": "danger", "skill_history": [], "started_at": _iso(-30)}
    alerts = cs._check_stuck_retrieval_escalation([], fd, sess, COV)
    assert alerts and alerts[0]["code"] == "STUCK_RETRIEVAL_ESCALATION"


def test_stuck_directive_already_pending_suppresses(directives, monkeypatch):
    """Don't stack STUCK on STUCK: an outstanding STUCK directive does suppress."""
    import core.steering as st
    monkeypatch.setattr(st.steering_queue, "get_active", lambda: [_Dir("STUCK_RETRIEVAL_ESCALATION")])
    fd = {"findings": [{"ts": _iso(-10)}]}
    assert cs._check_stuck_retrieval_escalation([], fd, DEEP, COV) == []


def test_zero_findings_past_recon_is_stuck(directives, refs_dir):
    """A 0-finding run (the most-stuck possible) must trip once past recon."""
    fd = {"findings": []}
    sess = {"depth": "danger", "skill_history": [], "started_at": _iso(-20)}
    alerts = cs._check_stuck_retrieval_escalation([], fd, sess, COV)
    assert alerts and alerts[0]["code"] == "STUCK_RETRIEVAL_ESCALATION"


def test_sources_are_methodology_urls():
    for c in ("ssti", "sqli", "cmdi", "xxe", "ssrf", "traversal", "deserialization"):
        ref, url = cs._RETRIEVAL_SOURCES[c]
        assert ref.endswith(".md") and url.startswith("https://")


def test_load_technique_brief_failsoft(monkeypatch, tmp_path):
    """No readable ref → empty string, never an exception."""
    monkeypatch.setattr(cs, "_REFS_DIRS", [str(tmp_path / "nope")])
    assert cs._load_technique_brief(["ssti", "sqli"]) == ""
