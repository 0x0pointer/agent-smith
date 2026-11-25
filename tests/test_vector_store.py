from __future__ import annotations

from pathlib import Path

import pytest

from core import vector_store as vector_mod


@pytest.fixture
def vector_env(tmp_path, monkeypatch):
    monkeypatch.setattr(vector_mod, "VECTOR_ROOT", tmp_path / "vectors")
    monkeypatch.setattr(vector_mod, "KB_ROOT", tmp_path / "kb")
    monkeypatch.setattr(vector_mod, "RAW_DIR", tmp_path / "kb" / "sources" / "_raw")
    monkeypatch.setattr(vector_mod, "MANIFEST", tmp_path / "kb" / "MANIFEST.json")
    return tmp_path


def test_ingest_search_by_vault_dataset_and_scope(vector_env):
    vector_mod.ingest_text(vault="security", dataset="wstg", name="wstg.md",
                           text="Testing for default credentials in admin consoles", untrusted=False)
    vector_mod.ingest_text(vault="engagement-demo", dataset="api", name="openapi.json",
                           text="POST /api/login accepts username and password", untrusted=True)

    kb_hits = vector_mod.search("default credentials", vault="security", datasets=["wstg"])
    doc_hits = vector_mod.search("POST /api/login", vault="engagement-demo", datasets=["api"])

    assert kb_hits and kb_hits[0]["dataset"] == "wstg"
    assert doc_hits and doc_hits[0]["dataset"] == "api"
    assert doc_hits[0]["untrusted"] is True


def test_duplicate_idempotent_or_suffixed(vector_env):
    first = vector_mod.ingest_text(vault="security", dataset="skill_ref", name="playbook.md",
                                   text="same text", untrusted=False)
    dup = vector_mod.ingest_text(vault="security", dataset="skill_ref", name="playbook.md",
                                 text="same text", untrusted=False)
    changed = vector_mod.ingest_text(vault="security", dataset="skill_ref", name="playbook.md",
                                     text="different text", untrusted=False)

    assert first["status"] == "ingested"
    assert dup["status"] == "skipped" and dup["reason"] == "duplicate"
    assert changed["status"] == "ingested"
    assert changed["name"] != "playbook.md"


def test_sanitizes_ids_and_delete_blocks_traversal(vector_env):
    result = vector_mod.ingest_text(vault="../../security", dataset="../api", name="../../spec.md",
                                    text="spec text", untrusted=False)
    assert result["doc"]["vault"] == "security"
    assert result["doc"]["dataset"] == "api"
    assert Path(vector_mod.vault_dir("security")).exists()
    assert vector_mod.delete_doc("security", "api", "../../spec.md") is True
    assert vector_mod.delete_doc("security", "api", "../../missing.md") is False


def test_purge_only_engagement_vault(vector_env):
    active = vector_mod.active_vault("scan-1")
    vector_mod.ingest_text(vault=active, dataset="docs", name="notes.md", text="scan data", untrusted=False)
    vector_mod.ingest_text(vault="security", dataset="wstg", name="guide.md", text="static data", untrusted=False)

    purged = vector_mod.purge_active_session("scan-1")

    assert purged == 1
    assert not vector_mod.list_docs(vault=active)
    assert vector_mod.list_docs(vault="security")
