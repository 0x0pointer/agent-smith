"""
Tests for the small-model profile behaviour: profile-gated thorough passes,
condensed adjudication directive, and one-blocker-at-a-time completion.
"""
import pytest

import core.session
from core.adjunction.directive import build_adjudication_directive
from core.adjunction.rubric import rubric_digest, rubric_text
import mcp_server.session_tools as st


def _set_profile(monkeypatch, profile):
    monkeypatch.setattr(core.session, "_current",
                        {"status": "running", "model_profile": profile, "depth": "standard"})


# ── #4 profile-gated thorough passes ────────────────────────────────────────

@pytest.mark.parametrize("profile,expected", [("full", 3), ("medium", 2), ("small", 1)])
def test_min_iterations(monkeypatch, profile, expected):
    _set_profile(monkeypatch, profile)
    assert st._min_iterations() == expected


@pytest.mark.parametrize("profile,expected", [("full", False), ("medium", True), ("small", True)])
def test_condensed_flag(monkeypatch, profile, expected):
    _set_profile(monkeypatch, profile)
    assert st._condensed_directives() is expected


# ── #3 digest adjudication directive ────────────────────────────────────────

def test_rubric_digest_is_compact():
    assert len(rubric_digest()) < len(rubric_text())
    # one line per band, no examples
    assert rubric_digest().count("\n") <= 6


def test_adjudication_directive_digest_much_shorter():
    pending = [{"id": "1", "severity": "high", "title": "SQLi", "description": "d"}]
    full = build_adjudication_directive(pending, digest=False)
    dig = build_adjudication_directive(pending, digest=True)
    assert len(dig) < len(full) / 2
    assert "ADJUDICATION REQUIRED" in dig and "SQLi" in dig
    assert "FINDINGS BAR" in dig            # anti_fp_digest embedded
    assert "REJECT THESE ANTI-PATTERNS" in full and "REJECT THESE ANTI-PATTERNS" not in dig


# ── #1 one-blocker-at-a-time ─────────────────────────────────────────────────

def test_blocker_priority_orders_concrete_before_iteration():
    assert st._blocker_priority("GATE [x]: chain") < st._blocker_priority("⛔ ITERATION GATE: pass")
    assert st._blocker_priority("ADJUDICATION REQUIRED — 3") < st._blocker_priority("NO DIAGRAM: ...")


def test_small_profile_surfaces_one_blocker(monkeypatch):
    _set_profile(monkeypatch, "small")
    monkeypatch.setattr(st, "_complete_attempts", 0)
    blockers = [
        "NO DIAGRAM: add a Mermaid diagram",
        "GATE [auth_coverage]: chain into credential-audit",
        "⛔ ITERATION GATE: re-run deeper",
    ]
    out = st._build_blocker_response(blockers)
    assert "ONE AT A TIME" in out
    assert "3 blockers remain" in out
    # the highest-priority blocker (GATE) is surfaced; the others are held back
    assert "GATE [auth_coverage]" in out
    assert "ITERATION GATE" not in out
    assert "NO DIAGRAM" not in out


def test_full_profile_shows_all_blockers(monkeypatch):
    _set_profile(monkeypatch, "full")
    monkeypatch.setattr(st, "_complete_attempts", 0)
    blockers = ["GATE [a]: x", "NO DIAGRAM: y"]
    out = st._build_blocker_response(blockers)
    assert "ONE AT A TIME" not in out
    assert "GATE [a]" in out and "NO DIAGRAM" in out
