from __future__ import annotations

import json

import pytest

from mcp_server.report_tools.recall import _do_recall


@pytest.fixture
def engagement_env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    store = tmp_path / "engagements" / "demo"
    (store / "pocs").mkdir(parents=True)
    (store / "resume.json").write_text(json.dumps({"generated_from": {"session_id": "none"}}), encoding="utf-8")
    (store / "findings.json").write_text(json.dumps({"findings": [{
        "id": "f1",
        "title": "Sudo shell escape on backup host",
        "severity": "high",
        "target": "http://demo",
        "description": "sudo -u root",
        "evidence": "gtfobins sudo",
    }]}), encoding="utf-8")
    (store / "digest.md").write_text("# demo digest\nfound sudo misconfig", encoding="utf-8")
    return tmp_path


@pytest.mark.asyncio
async def test_recall_engagements_only_classic_output_preserved(engagement_env):
    out = await _do_recall({"query": "sudo misconfig", "scope": "engagements"})
    assert "across 1 store(s)" in out
    assert "demo · finding" in out
    assert "PRIOR observations" in out
    assert "KB" not in out


@pytest.mark.asyncio
async def test_recall_defaults_to_prior_engagements_only(engagement_env):
    out = await _do_recall({"query": "sudo misconfig"})
    assert "across 1 store(s)" in out
    assert "demo · finding" in out
    assert "scope 'kb'" not in out


@pytest.mark.asyncio
async def test_recall_removed_kb_docs_and_kind_scopes(engagement_env):
    for scope in ("kb", "docs", "nvd", "wstg"):
        out = await _do_recall({"query": "sudo", "scope": scope})
        assert "no longer supported" in out
        assert scope in out


@pytest.mark.asyncio
async def test_recall_missing_query_help_mentions_only_engagements(engagement_env):
    out = await _do_recall({})
    assert "prior engagement stores only" in out
    assert "scope:'engagements'" in out
    assert "scope:'kb'" not in out
    assert "scope:'docs'" not in out


@pytest.mark.asyncio
async def test_recall_ignores_legacy_kb_dirs(engagement_env):
    legacy = engagement_env / "kb" / "sources" / "legacy"
    legacy.mkdir(parents=True)
    (legacy / "sudo.md").write_text("legacy kb data that should be ignored", encoding="utf-8")
    out = await _do_recall({"query": "legacy kb data"})
    assert "no matches" in out
    assert "kb" not in out.lower() or "scope 'kb'" not in out.lower()
