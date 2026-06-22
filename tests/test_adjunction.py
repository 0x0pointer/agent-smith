"""
Tests for the adjunction final-QA adjudication package and its wiring into the
completion gate.

Covers:
  - rubric: rubric_text content, validate_severity_vs_impact, severity_rank
  - verdict: is_adjudicated, coerce_adjudication
  - gate: pending_findings scope, adjudication_blockers
  - directive: persona/rubric/illustration present, inflated-severity hint
  - integration: _collect_completion_blockers blocks until findings are adjudicated
"""
import pytest
from unittest.mock import patch

import core.adjunction as A


# ── rubric ─────────────────────────────────────────────────────────────────────

def test_rubric_text_lists_all_bands_and_anchors():
    text = A.rubric_text()
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        assert sev in text
    # A few anchor phrases that pin the canonical meaning.
    assert "Unauthenticated RCE" in text
    assert "BOLA" in text or "IDOR" in text
    assert "bearer headers" in text  # the CORS / header-auth low-severity anchor


def test_severity_rank_orders_correctly():
    assert A.severity_rank("critical") > A.severity_rank("high") > A.severity_rank("medium")
    assert A.severity_rank("medium") > A.severity_rank("low") > A.severity_rank("info")
    assert A.severity_rank("bogus") == -1


def test_validate_severity_vs_impact_flags_inflated():
    ok, hint = A.validate_severity_vs_impact("critical", "missing security header, informational only")
    assert ok is False
    assert hint and "low-impact" in hint


def test_validate_severity_vs_impact_passes_real_high():
    ok, hint = A.validate_severity_vs_impact("high", "BOLA reading another user's records")
    assert ok is True and hint is None


def test_validate_severity_vs_impact_ignores_medium_and_below():
    assert A.validate_severity_vs_impact("medium", "missing header") == (True, None)
    assert A.validate_severity_vs_impact("low", "anything") == (True, None)


# ── exploit-chain terminal-blast-radius rescoring ───────────────────────────────

def test_chain_terminal_severity_critical_on_proven_ato():
    finding = {"escalation_leads": [
        {"lead": "info-disclosure leaks reset token", "status": "done",
         "result": "used token to achieve full account takeover of victim"},
    ]}
    assert A.chain_terminal_severity(finding) == "critical"


def test_chain_terminal_severity_high_on_cross_object():
    finding = {"escalation_leads": [
        {"lead": "enumerate ids", "status": "done", "result": "read another user's records via IDOR"},
    ]}
    assert A.chain_terminal_severity(finding) == "high"


def test_chain_terminal_severity_none_when_unproven_or_absent():
    # done but no result → not proven
    assert A.chain_terminal_severity(
        {"escalation_leads": [{"lead": "RCE maybe", "status": "done"}]}
    ) is None
    # pending lead → not proven
    assert A.chain_terminal_severity(
        {"escalation_leads": [{"lead": "RCE", "status": "pending", "result": "code execution"}]}
    ) is None
    # no leads at all
    assert A.chain_terminal_severity({}) is None
    assert A.chain_terminal_severity({"escalation_leads": "nope"}) is None


def test_coerce_adjudication_raises_severity_for_proven_chain():
    finding = {
        "id": "f1", "severity": "medium",
        "escalation_leads": [
            {"lead": "open redirect + oauth", "status": "done",
             "result": "captured victim code → account takeover"},
        ],
    }
    out = A.coerce_adjudication(
        {"reproducible": True, "revised_severity": "medium", "rationale": "chained to ATO",
         "artifact_id": "http_request_1_a"},
        finding,
    )
    assert out["revised_severity"] == "critical"
    assert out["chain_escalated_from"] == "medium"


def test_coerce_adjudication_does_not_lower_for_weaker_chain():
    # A high finding whose proven chain only reaches a 'high' terminal stays high
    # (the rule only ever raises, never lowers).
    finding = {
        "id": "f1", "severity": "high",
        "escalation_leads": [
            {"lead": "idor", "status": "done", "result": "read another user's data"},
        ],
    }
    out = A.coerce_adjudication(
        {"reproducible": True, "revised_severity": "high", "rationale": "x", "artifact_id": "a1"},
        finding,
    )
    assert out["revised_severity"] == "high"
    assert "chain_escalated_from" not in out


# ── verdict ──────────────────────────────────────────────────────────────────

def test_is_adjudicated_requires_rationale():
    assert A.is_adjudicated({"adjudication": {"rationale": "reproduced; confirmed"}}) is True
    assert A.is_adjudicated({"adjudication": {"rationale": ""}}) is False
    assert A.is_adjudicated({"adjudication": {}}) is False
    assert A.is_adjudicated({}) is False
    assert A.is_adjudicated({"adjudication": "nope"}) is False


def test_is_adjudicated_reproducible_requires_artifact():
    # reproducible=true with no artifact_id is hollow → not adjudicated.
    assert A.is_adjudicated(
        {"adjudication": {"reproducible": True, "rationale": "it works"}}
    ) is False
    assert A.is_adjudicated(
        {"adjudication": {"reproducible": True, "rationale": "it works", "artifact_id": "   "}}
    ) is False
    # reproducible=true WITH an artifact_id present → adjudicated.
    assert A.is_adjudicated(
        {"adjudication": {"reproducible": True, "rationale": "it works", "artifact_id": "http_request_1_a"}}
    ) is True
    # reproducible=false never needs an artifact.
    assert A.is_adjudicated(
        {"adjudication": {"reproducible": False, "rationale": "could not reproduce"}}
    ) is True


def test_coerce_adjudication_fills_original_from_finding():
    finding = {"id": "f1", "severity": "high"}
    out = A.coerce_adjudication(
        {"reproducible": True, "revised_severity": "low", "rationale": "header auth, no cookie ride"},
        finding,
    )
    assert out["original_severity"] == "high"
    assert out["revised_severity"] == "low"
    assert out["reproducible"] is True
    assert out["rationale"]


def test_coerce_adjudication_coerces_string_reproducible():
    out = A.coerce_adjudication({"reproducible": "no", "rationale": "could not reproduce"}, {})
    assert out["reproducible"] is False


def test_coerce_adjudication_carries_artifact_id():
    # coerce normalizes and carries artifact_id through; it does NOT enforce
    # presence (that's the report_tools boundary + is_adjudicated backstop).
    out = A.coerce_adjudication(
        {"reproducible": True, "rationale": "reproduced it", "artifact_id": "http_request_1_a"}, {}
    )
    assert out["artifact_id"] == "http_request_1_a"
    # reproducible=false does not require / carry an artifact.
    out2 = A.coerce_adjudication({"reproducible": False, "rationale": "no repro"}, {})
    assert "artifact_id" not in out2
    # A reproducible verdict with no artifact still coerces (not None) but will
    # fail is_adjudicated and be rejected at the boundary.
    out3 = A.coerce_adjudication({"reproducible": True, "rationale": "works"}, {})
    assert out3 is not None and A.is_adjudicated({"adjudication": out3}) is False


def test_coerce_adjudication_rejects_empty_rationale():
    assert A.coerce_adjudication({"reproducible": True, "rationale": "   "}, {}) is None
    assert A.coerce_adjudication("not a dict", {}) is None


def test_coerce_adjudication_invalid_revised_falls_back_to_original():
    out = A.coerce_adjudication(
        {"revised_severity": "bogus", "original_severity": "high", "rationale": "x"}, {}
    )
    assert out["revised_severity"] == "high"


# ── gate ─────────────────────────────────────────────────────────────────────

def _finding(fid, sev, adjudicated=False, **extra):
    f = {"id": fid, "severity": sev, "title": f"finding {fid}", "target": "https://t/x"}
    f.update(extra)
    if adjudicated:
        f["adjudication"] = {"reproducible": True, "rationale": "reviewed", "artifact_id": "art1"}
    return f


def test_pending_findings_only_unadjudicated_high_critical():
    data = {"findings": [
        _finding("c1", "critical"),
        _finding("h1", "high"),
        _finding("h2", "high", adjudicated=True),
        _finding("m1", "medium"),       # out of scope
        _finding("l1", "low"),          # out of scope
    ]}
    pending = A.pending_findings(data)
    assert {f["id"] for f in pending} == {"c1", "h1"}


def test_adjudication_blockers_present_then_clears():
    data = {"findings": [_finding("h1", "high")]}
    blockers = A.adjudication_blockers(data)
    assert len(blockers) == 1
    assert "ADJUDICATION REQUIRED" in blockers[0]

    data["findings"][0]["adjudication"] = {"reproducible": True, "rationale": "reviewed", "artifact_id": "art1"}
    assert A.adjudication_blockers(data) == []


def test_adjudication_blockers_empty_when_no_inscope_findings():
    assert A.adjudication_blockers({"findings": [_finding("m1", "medium")]}) == []
    assert A.adjudication_blockers({"findings": []}) == []
    assert A.adjudication_blockers({}) == []


# ── directive ─────────────────────────────────────────────────────────────────

def test_directive_contains_persona_rubric_and_illustration():
    data = {"findings": [_finding("h1", "high", description="reflected xss in search")]}
    d = A.adjudication_blockers(data)[0]
    assert "SENIOR SECURITY REVIEWER" in d
    assert "SEVERITY RUBRIC" in d
    assert "Allow-Credentials" in d            # the illustrative CORS reasoning
    assert "update_finding" in d               # output contract
    assert "id=h1" in d                        # the concrete finding is listed


def test_directive_flags_inflated_severity_inline():
    data = {"findings": [
        _finding("h1", "high", description="missing security header, informational"),
    ]}
    d = A.adjudication_blockers(data)[0]
    assert "⚠" in d  # the validate_severity_vs_impact hint is surfaced to the reviewer


# ── integration: completion gate wiring ─────────────────────────────────────────

def _patch_other_blockers():
    """Silence every OTHER completion-blocker source so the test isolates the
    adjudication blocker."""
    from contextlib import ExitStack
    stack = ExitStack()
    for name in ("_gate_blockers", "_qa_blockers", "_coverage_blockers"):
        stack.enter_context(patch(f"mcp_server.session_tools.{name}", return_value=[]))
    stack.enter_context(
        patch("mcp_server.session_tools._escalation_lead_blockers", return_value=[])
    )
    stack.enter_context(
        patch("core.coverage.get_matrix", return_value={"meta": {}, "matrix": [], "endpoints": []})
    )
    return stack


def test_collect_completion_blockers_includes_adjudication():
    from mcp_server.session_tools import _collect_completion_blockers
    # A high finding that passes the POC + quality gates but is unadjudicated.
    finding = _finding(
        "h1", "high",
        poc_files=["pocs/h1.http"],
        evidence="HTTP/1.1 200 ... reflected",
        reproduction={"type": "http", "command": "curl ...", "expected": "200"},
    )
    data = {"findings": [finding], "diagrams": [{"id": "d1", "mermaid": "graph TD"}]}
    with _patch_other_blockers():
        blockers = _collect_completion_blockers(data, effective=set())
    assert any("ADJUDICATION REQUIRED" in b for b in blockers)

    # Once adjudicated, the adjudication blocker is gone.
    finding["adjudication"] = {"reproducible": True, "rationale": "reproduced; stays high", "artifact_id": "art1"}
    with _patch_other_blockers():
        blockers = _collect_completion_blockers(data, effective=set())
    assert not any("ADJUDICATION REQUIRED" in b for b in blockers)
