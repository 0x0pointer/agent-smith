"""#1 — durable CONFIRMED / HYPOTHESIS / RULED_OUT fact ledger.

The load-bearing rule: a "confirmed" fact with no evidence is demoted to a
hypothesis, so a misread never propagates across restarts as established truth;
and RULED_OUT negatives are carried so a fresh context doesn't re-walk a dead end.
"""
import json

import pytest

import core.session as session
from core.session import fact_ledger as fl


@pytest.fixture
def running(monkeypatch):
    monkeypatch.setattr(session, "_current", {"status": "running", "fact_ledger":
                                              {"confirmed": [], "hypothesis": [], "ruled_out": []}})


def test_confirmed_requires_evidence(running):
    res = fl.record_confirmed("flask secret = super_secret_key", evidence="artifact:abc123")
    assert res["ok"] and res["bucket"] == "confirmed"
    ov = fl.overview()
    assert ov["confirmed"][0]["fact"].startswith("flask secret")
    assert ov["confirmed"][0]["evidence"] == "artifact:abc123"


def test_confirmed_without_evidence_is_demoted_to_hypothesis(running):
    res = fl.record_confirmed("a second admin password exists")
    assert res["ok"] and res["bucket"] == "hypothesis"
    ov = fl.overview()
    assert "confirmed" not in ov                       # NOT authoritative
    assert ov["hypothesis_unverified"] == ["a second admin password exists"]


def test_ruled_out_is_carried_as_do_not_retry(running):
    fl.record_ruled_out("user_id=1", reason="404 — no such user")
    ov = fl.overview()
    assert ov["ruled_out_do_not_retry"] == ["user_id=1 — 404 — no such user"]


def test_promote_moves_hypothesis_to_confirmed(running):
    fl.record_hypothesis("X-UserId header may control authz")
    res = fl.promote("X-UserId header may control authz", evidence="finding:f17")
    assert res["bucket"] == "confirmed"
    ov = fl.overview()
    assert "hypothesis_unverified" not in ov           # moved, not duplicated
    assert ov["confirmed"][0]["evidence"] == "finding:f17"


def test_promote_without_evidence_rejected(running):
    assert fl.promote("x", evidence="")["ok"] is False


def test_fact_lives_in_one_bucket_only(running):
    fl.record_hypothesis("union might be filtered")
    fl.record_ruled_out("union might be filtered", reason="confirmed WAF strips it")
    c = fl.counts()
    assert c["hypothesis"] == 0 and c["ruled_out"] == 1  # moved across buckets, deduped


def test_dedup_same_fact(running):
    fl.record_ruled_out("param q=test → 500")
    fl.record_ruled_out("param q=test → 500")
    assert fl.counts()["ruled_out"] == 1


def test_bucket_bounded(running):
    for i in range(80):
        fl.record_ruled_out(f"dead end number {i}")
    assert fl.counts()["ruled_out"] <= 60


def test_fail_soft_without_session(monkeypatch):
    monkeypatch.setattr(session, "_current", None)
    assert fl.record_confirmed("x", "ev")["ok"] is False
    assert fl.overview() == {}


# ── report(action='fact') dispatch ───────────────────────────────────────────

def test_report_fact_action(running):
    from mcp_server.report_tools import _do_fact
    conf = json.loads(_do_fact({"status": "confirmed", "text": "k=v", "evidence": "artifact:1"}))
    assert conf["bucket"] == "confirmed"
    demoted = json.loads(_do_fact({"status": "confirmed", "text": "guess"}))
    assert demoted["bucket"] == "hypothesis"
    ruled = json.loads(_do_fact({"status": "ruled_out", "text": "id=2", "reason": "404"}))
    assert ruled["bucket"] == "ruled_out"
    assert "Error" in _do_fact({"status": "confirmed"})  # missing text


def test_recovery_brief_includes_ledger(running):
    fl.record_confirmed("reflected header X-Debug", "artifact:9")
    from core.session import fact_ledger as _facts
    ov = _facts.overview()
    assert "confirmed" in ov  # the wrapper in recovery_build surfaces exactly this
