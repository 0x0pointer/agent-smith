"""Tests for the confirmed-but-unexploited vuln retrieval-escalation check.

A `vulnerable` coverage cell of a known-payload injection class must raise an
ESCALATE_<TYPE> alert (and, in the live flow, a blocking gate + a directive that
names the exact web-exploit ref and a payload-list research URL). Clean cells,
non-exploitable classes, and already-satisfied/dismissed gates must not fire.
"""
from core.qa_agent.checks_skills import (
    _check_confirmed_vuln_escalation,
    _VULN_ESCALATION,
)


def _cov(*cells):
    return {"matrix": list(cells)}


def test_confirmed_ssti_cell_fires_escalation():
    alerts = _check_confirmed_vuln_escalation(
        _cov({"id": "c1", "injection_type": "ssti", "status": "vulnerable"}),
        {"gates": [], "skill_history": []},
    )
    assert [a["code"] for a in alerts] == ["ESCALATE_SSTI"]
    msg = alerts[0]["message"]
    assert "refs/ssti.md" in msg or "ssti" in msg.lower()


def test_clean_and_non_mapped_cells_ignored():
    alerts = _check_confirmed_vuln_escalation(
        _cov(
            {"id": "a", "injection_type": "sqli", "status": "tested_clean"},  # clean
            {"id": "b", "injection_type": "idor", "status": "vulnerable"},    # not mapped
            {"id": "c", "injection_type": "cors", "status": "vulnerable"},    # not mapped
        ),
        {"gates": [], "skill_history": []},
    )
    assert alerts == []


def test_one_alert_per_injection_type():
    alerts = _check_confirmed_vuln_escalation(
        _cov(
            {"id": "x1", "injection_type": "ssti", "status": "vulnerable"},
            {"id": "x2", "injection_type": "ssti", "status": "vulnerable"},
            {"id": "y1", "injection_type": "xxe", "status": "vulnerable"},
        ),
        {"gates": [], "skill_history": []},
    )
    assert sorted(a["code"] for a in alerts) == ["ESCALATE_SSTI", "ESCALATE_XXE"]


def test_satisfied_or_dismissed_gate_suppresses():
    cov = _cov({"id": "c1", "injection_type": "ssti", "status": "vulnerable"})
    for st in ("satisfied", "not_applicable"):
        alerts = _check_confirmed_vuln_escalation(
            cov, {"gates": [{"id": "exploit_ssti", "status": st}], "skill_history": []}
        )
        assert alerts == [], f"gate status {st!r} should suppress"


def test_no_cells_is_empty():
    assert _check_confirmed_vuln_escalation({}, {"gates": [], "skill_history": []}) == []
    assert _check_confirmed_vuln_escalation({"matrix": []}, {"gates": []}) == []


def test_map_covers_known_payload_classes():
    for cls in ("ssti", "xxe", "cmdi", "sqli", "ssrf", "xss", "deserialization"):
        assert cls in _VULN_ESCALATION
        ref, url = _VULN_ESCALATION[cls]
        assert ref.startswith("refs/") and url.startswith("https://")
