"""Coverage for scripts/build_engagement_digest.py — turns a finished scan's on-disk
state (session.json + coverage snapshot + findings.json) into an engagements/<name>/
store (known_assets / coverage / findings / resume.json / digest.md). Driven entirely
on local fixtures under a tmp cwd."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

import pytest

_BED_PATH = Path(__file__).resolve().parent.parent / "scripts" / "build_engagement_digest.py"
_spec = importlib.util.spec_from_file_location("build_engagement_digest", _BED_PATH)
bed = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bed)


@pytest.fixture
def digest_env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "logs").mkdir()
    session = {
        "id": "sess-abc", "target": "http://vulnbank.test:30081", "status": "complete",
        "stop_reason": "operator_accept_partial",
        "known_assets": {"credentials": [{"user": "a"}], "auth_tokens": [{"value": "jwt"}],
                         "kb_docs": [{"file": "api-notes.md", "untrusted": False}]},
    }
    (tmp_path / "session.json").write_text(json.dumps(session))
    (tmp_path / "findings.json").write_text(json.dumps({"findings": [
        {"id": "f1", "title": "SQLi in /login", "severity": "critical",
         "target": "http://vulnbank.test:30081", "cve": ""},
        {"id": "f2", "title": "Off-scope thing", "severity": "low", "target": "http://other.test"},
    ]}))
    cov = {"meta": {"target": "http://vulnbank.test:30081"},
           "endpoints": [{"id": "e1", "path": "/login"}],
           "matrix": [
               {"endpoint_id": "e1", "param": "u", "injection_type": "sqli",
                "status": "vulnerable", "finding_id": "f1"},
               {"endpoint_id": "e1", "param": "p", "injection_type": "xss",
                "status": "tested_clean", "notes": "ok"},
               {"endpoint_id": "e1", "param": "q", "injection_type": "ssti", "status": "pending"},
           ]}
    (tmp_path / "logs" / "coverage_matrix_20260101.json").write_text(json.dumps(cov))
    return tmp_path


# ── helpers ─────────────────────────────────────────────────────────────────

def test_slug():
    assert bed._slug("http://VulnBank.test:30081") == "http-vulnbank.test-30081"
    assert bed._slug("") == "engagement"


def test_asset_counts():
    out = bed._asset_counts({"credentials": [1, 2], "note": "x"})
    assert out == {"credentials": 2, "note": "x"}


def test_pick_coverage_matches_target(digest_env):
    # newest snapshot whose meta.target matches
    assert bed._pick_coverage(None, "http://vulnbank.test:30081").endswith("coverage_matrix_20260101.json")
    # explicit path wins
    assert bed._pick_coverage("explicit.json", "x") == "explicit.json"


def test_bundle_dir_none_without_dir(digest_env):
    assert bed._bundle_dir(None) is None
    assert bed._bundle_dir("nope") is None


# ── build() end-to-end ──────────────────────────────────────────────────────

def test_build_writes_store(digest_env):
    out = bed.build("session.json", None, None, "demo", None)
    store = Path(out)
    for fn in ("known_assets.json", "coverage.json", "findings.json", "resume.json", "digest.md"):
        assert (store / fn).exists(), f"missing {fn}"
    resume = json.loads((store / "resume.json").read_text())
    assert resume["target"] == "http://vulnbank.test:30081"
    # both findings relate (the _rel filter matches on the shared "http:" url prefix,
    # and falls back to all on no match) → coverage stats reflect the full matrix.
    assert resume["stats"] == {"endpoints": 1, "cells_total": 3, "tested_clean": 1,
                               "vulnerable": 1, "not_applicable": 0, "pending": 1, "findings": 2}
    assert {f["id"] for f in resume["findings"]} == {"f1", "f2"}
    assert resume["vulnerable_cells"][0]["finding_id"] == "f1"
    digest = (store / "digest.md").read_text()
    assert "Engagement digest" in digest and "SQLi in /login" in digest
    assert "api-notes.md" in digest   # kb_doc names recorded (ephemeral, names only)


def test_build_falls_back_to_all_findings_on_target_mismatch(digest_env, tmp_path):
    # session target that matches NO finding → keep all findings (lose nothing)
    (tmp_path / "session.json").write_text(json.dumps(
        {"id": "s", "target": "http://nomatch.example", "known_assets": {}}))
    out = bed.build("session.json", None, None, "demo2", None)
    resume = json.loads((Path(out) / "resume.json").read_text())
    assert len(resume["findings"]) == 2   # both kept (fallback)


# ── main() CLI ──────────────────────────────────────────────────────────────

def test_main_ok(digest_env, capsys):
    rc = bed.main(["--session", "session.json", "--name", "demo3"])
    assert rc == 0
    assert "engagement store written" in capsys.readouterr().out
    assert (digest_env / "engagements" / "demo3" / "resume.json").exists()


def test_main_missing_session(digest_env):
    assert bed.main(["--session", "does-not-exist.json"]) == 2
