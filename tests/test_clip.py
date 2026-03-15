"""
Tests for the _clip() output truncation helper in mcp_server._app.

_clip keeps the first 2/3 and last 1/3 of the limit, dropping the middle.
Security tools emit the most important findings at the END, so tail preservation
is the primary correctness requirement.
"""
import pytest
from mcp_server._app import _clip


def test_short_string_returned_unchanged():
    assert _clip("hello", limit=100) == "hello"


def test_string_exactly_at_limit_returned_unchanged():
    text = "x" * 100
    assert _clip(text, limit=100) == text


def test_string_one_char_over_limit_is_clipped():
    text = "x" * 101
    result = _clip(text, limit=100)
    assert "clipped" in result


def test_empty_string_returned_unchanged():
    assert _clip("", limit=100) == ""


def test_result_starts_with_head_content():
    text = "H" * 500 + "T" * 500
    result = _clip(text, limit=300)
    assert result.startswith("H")


def test_result_ends_with_tail_content():
    """Tail content (security findings) must be preserved."""
    text = "H" * 500 + "T" * 500
    result = _clip(text, limit=300)
    assert result.endswith("T")


def test_dropped_count_annotation_is_accurate():
    # 12 000 chars, limit=9000 → head=6000, tail=3000, dropped=3000
    text = "A" * 6_000 + "M" * 3_000 + "Z" * 3_000
    result = _clip(text, limit=9_000)
    assert "3,000 chars clipped" in result


def test_tail_marker_preserved_in_long_output():
    """Critical findings at the very end of tool output must survive clipping."""
    tail_marker = "CRITICAL: remote code execution confirmed"
    text = ("noise line\n" * 1_000) + tail_marker
    result = _clip(text, limit=500)
    assert tail_marker in result


def test_default_limit_is_8000():
    text = "x" * 10_000
    result = _clip(text)
    assert "clipped" in result
    assert len(text[:5_334]) <= len(result)  # head portion present


def test_custom_limit_respected():
    text = "A" * 200
    result = _clip(text, limit=50)
    assert "clipped" in result


def test_head_is_two_thirds_of_limit():
    # limit=90 → head=60, tail=30
    text = "H" * 200 + "T" * 200
    result = _clip(text, limit=90)
    head_part = result.split("\n\n[")[0]
    assert len(head_part) == 60


def test_clipped_annotation_format():
    text = "x" * 20_000
    result = _clip(text, limit=8_000)
    assert "chars clipped" in result
    assert "[…" in result
