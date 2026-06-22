"""
Tests for the consolidated anti-false-positive doctrine in core.adjunction.rubric.
"""
from core.adjunction import anti_fp_text, anti_fp_digest, PRINCIPLES, ANTI_PATTERNS
from core.adjunction.directive import build_adjudication_directive


def test_principles_and_antipatterns_nonempty():
    assert len(PRINCIPLES) >= 5
    assert len(ANTI_PATTERNS) >= 5


def test_anti_fp_text_covers_core_rules():
    txt = anti_fp_text().lower()
    assert "only report what you can exploit" in txt
    assert "likelihood" in txt and "impact" in txt
    assert "defense-in-depth" in txt


def test_digest_is_compact_single_block():
    d = anti_fp_digest()
    assert "FINDINGS BAR" in d
    assert len(d) < 600  # stays small enough for the hunt-time envelope


def test_directive_embeds_anti_fp():
    d = build_adjudication_directive([
        {"id": "x", "severity": "high", "title": "t", "description": "missing header"},
    ])
    assert "ANTI-FALSE-POSITIVE PRINCIPLES" in d
    assert "REJECT THESE ANTI-PATTERNS" in d
