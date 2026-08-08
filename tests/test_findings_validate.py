"""
Tests for core.findings_validate — the deterministic trace[] validator.

Two layers: structural shape (always) and file:line resolution against a pinned
codebase (white-box only, via PENTEST_TARGET_PATH).
"""
import pytest

from core import findings_validate as fv


def _step(kind, file="src/app.py", line=1, scope="fn", desc="d"):
    return {"kind": kind, "file": file, "line": line, "scope": scope, "description": desc}


# ── shape ──────────────────────────────────────────────────────────────────────

def test_non_list_rejected():
    ok, errs = fv.validate_finding_trace("nope")
    assert not ok and errs


def test_too_few_steps_rejected():
    ok, errs = fv.validate_finding_trace([_step("entrypoint")])
    assert not ok and any("at least 2" in e for e in errs)


def test_valid_shape_no_codebase():
    ok, errs = fv.validate_finding_trace([_step("entrypoint"), _step("sink", line=2)])
    assert ok, errs


def test_first_must_be_entrypoint():
    ok, errs = fv.validate_finding_trace([_step("propagation"), _step("sink")])
    assert not ok and any("entrypoint" in e for e in errs)


def test_last_must_be_sink():
    ok, errs = fv.validate_finding_trace([_step("entrypoint"), _step("propagation")])
    assert not ok and any("sink" in e for e in errs)


def test_bad_kind_rejected():
    ok, errs = fv.validate_finding_trace([_step("source"), _step("sink")])
    assert not ok and any("kind" in e for e in errs)


def test_bool_line_rejected():
    ok, errs = fv.validate_finding_trace([_step("entrypoint", line=True), _step("sink", line=2)])
    assert not ok and any("positive integer" in e for e in errs)


def test_missing_scope_rejected():
    bad = {"kind": "entrypoint", "file": "a.py", "line": 1, "description": "d"}
    ok, errs = fv.validate_finding_trace([bad, _step("sink")])
    assert not ok and any("scope" in e for e in errs)


# ── filesystem resolution (white-box) ───────────────────────────────────────────

@pytest.fixture
def codebase(tmp_path, monkeypatch):
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("\n".join(f"line{i}" for i in range(1, 21)))  # 20 lines
    monkeypatch.setenv("PENTEST_TARGET_PATH", str(tmp_path))
    return tmp_path


def test_resolution_valid(codebase):
    ok, errs = fv.validate_finding_trace([
        _step("entrypoint", file="src/app.py", line=3),
        _step("sink", file="src/app.py", line=18),
    ])
    assert ok, errs


def test_resolution_missing_file(codebase):
    ok, errs = fv.validate_finding_trace([
        _step("entrypoint", file="src/ghost.py", line=1),
        _step("sink", file="src/app.py", line=2),
    ])
    assert not ok and any("does not exist" in e for e in errs)


def test_resolution_line_past_eof(codebase):
    ok, errs = fv.validate_finding_trace([
        _step("entrypoint", file="src/app.py", line=1),
        _step("sink", file="src/app.py", line=999),
    ])
    assert not ok and any("past the end" in e for e in errs)


def test_resolution_line_slack_allows_small_drift(codebase):
    # 20-line file + 5 slack = up to 25 accepted.
    ok, errs = fv.validate_finding_trace([
        _step("entrypoint", file="src/app.py", line=1),
        _step("sink", file="src/app.py", line=24),
    ])
    assert ok, errs


def test_resolution_path_traversal_rejected(codebase):
    ok, errs = fv.validate_finding_trace([
        _step("entrypoint", file="../../../../etc/passwd", line=1),
        _step("sink", file="src/app.py", line=2),
    ])
    assert not ok and any("does not exist" in e for e in errs)


def test_no_resolution_when_no_codebase(monkeypatch):
    monkeypatch.delenv("PENTEST_TARGET_PATH", raising=False)
    # A nonexistent file passes when no codebase is pinned (shape only).
    ok, errs = fv.validate_finding_trace([
        _step("entrypoint", file="does/not/exist.py", line=1),
        _step("sink", file="does/not/exist.py", line=2),
    ])
    assert ok, errs
