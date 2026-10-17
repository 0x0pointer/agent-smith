"""Phase 2 remainder (docs/plan-danger-depth.md):
  2e — exploit-escalation push generalised from benchmark-only to deep-pivot (danger too)
  2f — deep-pivot start-norm block
  2h — benchmark mode auto-resolves the self-resolvable HIRs instead of pausing
"""
import pytest

import core.session as scan_session
import core.steering as steering
import core.qa_agent as _qa
from core.qa_agent import hir
from core.qa_agent.checks_health import _check_exploit_escalation


@pytest.fixture
def steer_session(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
    monkeypatch.setattr(steering, "_STEERING_FILE", tmp_path / "steering.json")
    monkeypatch.setattr(_qa, "_last_hir_trigger_ts", {})
    scan_session._current = None
    yield tmp_path
    scan_session._current = None


# ── 2h: benchmark auto-resolves self-resolvable HIRs; pentest still pauses ───────

def test_hir_pauses_in_pentest(steer_session):
    scan_session.start("http://x.test", depth="standard", scan_mode="pentest")
    hir._hir("HIR_BUDGET_LIMIT", "budget nearly exhausted", [], ["EXTEND", "COMPLETE"])
    iv = scan_session.get_intervention()
    assert iv and iv.get("code") == "HIR_BUDGET_LIMIT"          # paused


def test_hir_autoresolves_in_benchmark(steer_session):
    scan_session.start("http://x.test", depth="standard", scan_mode="benchmark")
    hir._hir("HIR_BUDGET_LIMIT", "budget nearly exhausted", [], ["EXTEND", "COMPLETE"])
    assert scan_session.get_intervention() is None             # NOT paused
    directives = steering.steering_queue._load()
    assert any(d.get("trigger") == "BENCHMARK_AUTORESOLVE:HIR_BUDGET_LIMIT" for d in directives)


def test_hir_danger_still_pauses(steer_session):
    # danger is pentest-mode: it keeps HIR (human-in-the-loop), unlike benchmark
    scan_session.start("http://x.test", depth="danger", scan_mode="pentest")
    hir._hir("HIR_BUDGET_LIMIT", "budget nearly exhausted", [], ["EXTEND", "COMPLETE"])
    assert scan_session.get_intervention() is not None


# ── 2e: exploit-escalation fires under deep-pivot (danger + benchmark), not normal ──

def _crit_findings():
    return {"findings": [{"title": "RCE via SSTI", "severity": "critical",
                          "target": "http://x.test/t", "ts": "2020-01-01T00:00:00+00:00"}]}


@pytest.mark.parametrize("session_data,fires", [
    ({"scan_mode": "benchmark"}, True),
    ({"depth": "danger"}, True),
    ({"scan_mode": "pentest", "depth": "standard"}, False),
    ({"scan_mode": "pentest", "depth": "thorough"}, False),
])
def test_exploit_escalation_deep_pivot_gating(steer_session, session_data, fires):
    scan_session.start("http://x.test", depth=session_data.get("depth", "standard"),
                       scan_mode=session_data.get("scan_mode", "pentest"))
    res = _check_exploit_escalation([], _crit_findings(), session_data)
    assert (res is not None) is fires
    if fires:
        assert res["code"] == "EXPLOIT_ESCALATION"


# ── 2f: deep-pivot start norm shows for danger + benchmark, not a normal scan ──

def test_start_norm_deep_pivot_block(coverage_file):
    from mcp_server.session_tools import _do_start
    assert "DEEP-PIVOT MODE" in _do_start({"target": "example.com", "depth": "danger"})
    assert "DEEP-PIVOT MODE" in _do_start(
        {"target": "example.com", "depth": "standard", "scan_mode": "benchmark"})
    assert "DEEP-PIVOT MODE" not in _do_start({"target": "example.com", "depth": "standard"})
