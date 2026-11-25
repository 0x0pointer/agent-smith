from __future__ import annotations

import json
from pathlib import Path

import pytest

import core.session as scan_session
from core import vector_store as vector_mod
from mcp_server.report_tools.recall import _do_recall
from mcp_server.session_tools.kb_add import _do_kb_add
from mcp_server.session_tools.vector_add import _do_vector_add


@pytest.fixture
def vector_add_env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
    monkeypatch.setattr(vector_mod, "VECTOR_ROOT", tmp_path / "vectors")
    monkeypatch.setattr(vector_mod, "KB_ROOT", tmp_path / "kb")
    monkeypatch.setattr(vector_mod, "RAW_DIR", tmp_path / "kb" / "sources" / "_raw")
    monkeypatch.setattr(vector_mod, "MANIFEST", tmp_path / "kb" / "MANIFEST.json")
    scan_session._current = None
    scan_session.start("http://target.example")
    return tmp_path


@pytest.mark.asyncio
async def test_vector_add_file_dir_url_artifact_defaults(vector_add_env, monkeypatch):
    file_path = vector_add_env / "notes.md"
    file_path.write_text("Client notes about auth flow")
    out1 = await _do_vector_add({"path": str(file_path), "dataset": "client"})
    assert "1 document(s) ingested" in out1

    docs_dir = vector_add_env / "docs"
    docs_dir.mkdir()
    (docs_dir / "a.md").write_text("alpha")
    (docs_dir / "b.txt").write_text("beta")
    out2 = await _do_vector_add({"path": str(docs_dir), "dataset": "batch"})
    assert "2 document(s) ingested" in out2

    import mcp_server.session_tools.vector_add as mod
    monkeypatch.setattr(mod, "_fetch_url", lambda url: (b"<html><body>target swagger</body></html>", "text/html"))
    out3 = await _do_vector_add({"url": "http://target.example/swagger", "dataset": "target"})
    assert "UNTRUSTED" in out3

    sid = (scan_session.get() or {})["id"]
    art_dir = vector_add_env / "logs" / "smith-events" / sid
    art_dir.mkdir(parents=True)
    (art_dir / "artifact_001.txt").write_text("artifact login flow")
    out4 = await _do_vector_add({"artifact_id": "artifact_001", "dataset": "artifacts"})
    assert "artifact_001.txt" in out4


@pytest.mark.asyncio
async def test_vector_add_bad_options_no_input_missing_path_url_failure(vector_add_env, monkeypatch):
    assert "JSON object" in await _do_vector_add("not json")
    assert "nothing ingested" in await _do_vector_add({})
    assert "path not found" in await _do_vector_add({"path": "/no/such/file.md"})

    import mcp_server.session_tools.vector_add as mod
    monkeypatch.setattr(mod, "_fetch_url", lambda url: (_ for _ in ()).throw(OSError("boom")))
    out = await _do_vector_add({"url": "http://target.example/fail"})
    assert "url fetch failed" in out


@pytest.mark.asyncio
async def test_kb_add_alias_deprecated_and_recallable(vector_add_env):
    doc = vector_add_env / "api.md"
    doc.write_text("The API rotates JWT signing keys")

    out = await _do_kb_add({"path": str(doc)})
    assert "DEPRECATED" in out

    recall = await _do_recall({"query": "JWT signing keys", "scope": "docs"})
    assert "api.md" in recall


@pytest.mark.asyncio
async def test_url_scheme_file_rejected(vector_add_env):
    out = await _do_vector_add({"url": "file:///etc/passwd"})
    assert "only http/https URLs are supported" in out
