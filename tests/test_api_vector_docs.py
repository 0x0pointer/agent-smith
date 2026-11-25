from __future__ import annotations

import io
import json

import pytest
from fastapi.testclient import TestClient

import core.api_server as api
import core.session as scan_session
from core import vector_store as vector_mod
from core.api_server import app
from mcp_server.report_tools.recall import _do_recall

client = TestClient(app)


@pytest.fixture
def vector_api_env(tmp_path, monkeypatch):
    session_file = tmp_path / "session.json"
    session_file.write_text(json.dumps({"id": "sess-dash", "target": "http://t", "status": "running"}))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(scan_session, "_SESSION_FILE", session_file)
    monkeypatch.setattr(api, "_SESSION_FILE", session_file)
    monkeypatch.setattr(vector_mod, "VECTOR_ROOT", tmp_path / "vectors")
    monkeypatch.setattr(vector_mod, "KB_ROOT", tmp_path / "kb")
    monkeypatch.setattr(vector_mod, "RAW_DIR", tmp_path / "kb" / "sources" / "_raw")
    monkeypatch.setattr(vector_mod, "MANIFEST", tmp_path / "kb" / "MANIFEST.json")
    scan_session._current = None
    yield tmp_path
    scan_session._current = None


def _upload(name: str, content: bytes, *, vault="", dataset="docs", untrusted="false", mime="text/markdown"):
    return client.post(
        "/api/vector/docs",
        files=[("files", (name, io.BytesIO(content), mime))],
        data={"vault": vault, "dataset": dataset, "untrusted": untrusted},
    )


def test_empty_upload_list_delete_recallable(vector_api_env):
    data = client.get("/api/vector/docs").json()
    assert data["docs"] == []

    r = _upload("api.md", b"vault token rotation", dataset="api")
    assert r.status_code == 200 and r.json()["ingested"][0]["name"] == "api.md"

    listed = client.get("/api/vector/docs", params={"dataset": "api"}).json()
    assert listed["docs"][0]["dataset"] == "api"

    d = client.delete("/api/vector/docs", params={"name": "api.md", "dataset": "api"})
    assert d.status_code == 200 and d.json()["ok"] is True


@pytest.mark.asyncio
async def test_vector_docs_recallable(vector_api_env):
    _upload("infra.md", b"the vault token expires hourly")
    out = await _do_recall({"query": "vault token", "scope": "docs"})
    assert "infra.md" in out


def test_kb_docs_aliases_return_deprecation_header_or_field(vector_api_env):
    r = client.get("/api/kb/docs")
    assert r.headers.get("X-Agent-Smith-Deprecated")
    assert "deprecated" in r.json()
    assert int(r.headers["content-length"]) == len(r.content)


def test_too_many_large_empty_unsupported_corrupt_meta_fail_soft(vector_api_env, monkeypatch):
    files = [("files", (f"d{i}.md", io.BytesIO(b"x"), "text/markdown")) for i in range(21)]
    r = client.post("/api/vector/docs", files=files, data={"dataset": "docs", "untrusted": "false"})
    assert r.status_code == 400 and "too many files" in r.json()["error"]

    import core.api_server.routes.vector_routes as vr
    monkeypatch.setattr(vr, "_MAX_FILE_BYTES", 8)
    body = _upload("big.md", b"0123456789 bigger").json()
    assert body["skipped"][0]["reason"] == "file too large (>25 MB)"

    body = _upload("blank.md", b"").json()
    assert body["skipped"][0]["reason"] == "empty file"

    body = _upload("payload.exe", b"MZ", mime="application/octet-stream").json()
    assert "unsupported type" in body["skipped"][0]["reason"]

    vault_dir = vector_mod.vault_dir(vector_mod.active_vault("sess-dash")) / "docs"
    vault_dir.mkdir(parents=True, exist_ok=True)
    (vault_dir / "bad.json").write_text("{corrupt")
    assert client.get("/api/vector/docs").status_code == 200


def test_path_traversal_delete_404(vector_api_env):
    r = client.delete("/api/vector/docs", params={"name": "../../etc/passwd"})
    assert r.status_code == 404
