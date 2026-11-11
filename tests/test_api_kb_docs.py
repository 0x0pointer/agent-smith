"""
Engagement-doc API routes (plan 5.1 §6 dashboard side): /api/kb/docs.

  • GET    lists kb/sessions/<sid>/ docs with untrusted flags
  • POST   multipart upload → parsed + stored + registered (steering best-effort)
  • DELETE removes a doc and its untrusted meta entry

Isolation: kb root monkeypatched to tmp_path, session.json pointed at tmp_path.
"""
from __future__ import annotations

import asyncio
import io
import json

import pytest
from fastapi.testclient import TestClient

import core.api_server as api
import core.session as scan_session
from core import kb as kb_mod
from core.api_server import app

client = TestClient(app)


@pytest.fixture
def kb_api_env(tmp_path, monkeypatch):
    session_file = tmp_path / "session.json"
    session_file.write_text(json.dumps({
        "id": "sess-dash", "target": "http://t", "status": "running",
    }), encoding="utf-8")
    monkeypatch.setattr(scan_session, "_SESSION_FILE", session_file)
    monkeypatch.setattr(api, "_SESSION_FILE", session_file)
    kb_root = tmp_path / "kb"
    monkeypatch.setattr(kb_mod, "KB_ROOT", kb_root)
    monkeypatch.setattr(kb_mod, "SOURCES_DIR", kb_root / "sources")
    monkeypatch.setattr(kb_mod, "RAW_DIR", kb_root / "sources" / "_raw")
    monkeypatch.setattr(kb_mod, "SESSIONS_DIR", kb_root / "sessions")
    monkeypatch.setattr(kb_mod, "INDEX_DB", kb_root / "index.db")
    monkeypatch.setattr(kb_mod, "MANIFEST", kb_root / "MANIFEST.json")
    scan_session._current = None
    yield kb_root
    scan_session._current = None


def _upload(name: str, content: bytes, mime: str = "text/markdown", untrusted: str = "false"):
    return client.post(
        "/api/kb/docs",
        files=[("files", (name, io.BytesIO(content), mime))],
        data={"untrusted": untrusted},
    )


def test_kb_docs_empty(kb_api_env):
    r = client.get("/api/kb/docs")
    assert r.status_code == 200
    data = r.json()
    assert data["session_id"] == "sess-dash"
    assert data["docs"] == []
    assert ".pdf" in data["supported"]


def test_kb_docs_upload_and_list(kb_api_env):
    r = _upload("api-notes.md", b"JWT secret rotation notes")
    assert r.status_code == 200 and r.json()["ok"] is True
    ing = r.json()["ingested"]
    assert ing and ing[0]["name"] == "api-notes.md" and ing[0]["untrusted"] is False

    lst = client.get("/api/kb/docs").json()
    assert [d["name"] for d in lst["docs"]] == ["api-notes.md"]
    assert lst["docs"][0]["untrusted"] is False


def test_kb_docs_upload_untrusted_flags_meta(kb_api_env):
    _upload("target-manual.md", b"fetched from target", untrusted="true")
    meta = json.loads((kb_api_env / "sessions" / "sess-dash" / "meta.json").read_text())
    assert meta["untrusted"] == ["target-manual.md"]
    lst = client.get("/api/kb/docs").json()
    assert lst["docs"][0]["untrusted"] is True


def test_kb_docs_upload_unsupported_skipped(kb_api_env):
    r = _upload("payload.exe", b"MZ...", mime="application/octet-stream")
    body = r.json()
    assert body["ok"] is True and not body["ingested"]
    assert "unsupported type" in body["skipped"][0]["reason"]


def test_kb_docs_upload_openapi_parsed(kb_api_env):
    spec = json.dumps({"openapi": "3.0.0", "paths": {
        "/api/v1/payments": {"post": {"summary": "charge",
                                      "parameters": [{"name": "amount", "in": "body"}]}}}})
    _upload("swagger.json", spec.encode(), mime="application/json")
    stored = (kb_api_env / "sessions" / "sess-dash" / "swagger.json").read_text()
    assert "POST /api/v1/payments" in stored


def test_kb_docs_delete(kb_api_env):
    _upload("doc.md", b"content", untrusted="true")
    r = client.delete("/api/kb/docs/doc.md")
    assert r.status_code == 200 and r.json()["ok"] is True
    assert client.get("/api/kb/docs").json()["docs"] == []
    # untrusted meta entry cleaned up too
    meta_path = kb_api_env / "sessions" / "sess-dash" / "meta.json"
    assert not meta_path.exists() or "doc.md" not in meta_path.read_text()
    assert client.delete("/api/kb/docs/doc.md").status_code == 404


@pytest.mark.asyncio
async def test_kb_docs_uploaded_docs_recallable(kb_api_env):
    """Dashboard upload → immediately searchable via recall scope:'docs'."""
    from mcp_server.report_tools.recall import _do_recall
    _upload("infra.md", b"the vault token expires hourly")
    out = await _do_recall({"query": "vault token", "scope": "docs"})
    assert "docs:sess-dash/infra.md" in out


# ── skip / error branches ────────────────────────────────────────────────────

def test_kb_docs_upload_too_many_files(kb_api_env):
    files = [("files", (f"d{i}.md", io.BytesIO(b"x"), "text/markdown")) for i in range(21)]
    r = client.post("/api/kb/docs", files=files, data={"untrusted": "false"})
    assert r.status_code == 400 and "too many files" in r.json()["error"]


def test_kb_docs_upload_empty_file_skipped(kb_api_env):
    r = _upload("blank.md", b"")
    body = r.json()
    assert body["ok"] is True and not body["ingested"]
    assert body["skipped"][0]["reason"] == "empty file"


def test_kb_docs_upload_too_large_skipped(kb_api_env, monkeypatch):
    import core.api_server.routes.kb_routes as kr
    monkeypatch.setattr(kr, "_MAX_FILE_BYTES", 8)
    r = _upload("big.md", b"0123456789 larger than eight bytes")
    assert r.json()["skipped"][0]["reason"] == "file too large (>25 MB)"


def test_kb_docs_upload_no_text_extracted_skipped(kb_api_env):
    # HTML that strips to nothing → parse status 'empty' → skipped with the parser note
    r = _upload("blank.html", b"<br><hr>", mime="text/html")
    body = r.json()
    assert body["ok"] is True and not body["ingested"]
    assert "no text extracted" in body["skipped"][0]["reason"]


def test_kb_docs_list_tolerates_corrupt_meta(kb_api_env):
    _upload("doc.md", b"content")
    (kb_api_env / "sessions" / "sess-dash" / "meta.json").write_text("{corrupt")
    r = client.get("/api/kb/docs")
    assert r.status_code == 200
    assert [d["name"] for d in r.json()["docs"]] == ["doc.md"]   # corrupt meta → treated as none


def test_kb_docs_delete_tolerates_corrupt_meta(kb_api_env):
    _upload("doc.md", b"content", untrusted="true")
    (kb_api_env / "sessions" / "sess-dash" / "meta.json").write_text("{corrupt")
    r = client.delete("/api/kb/docs/doc.md")
    assert r.status_code == 200 and r.json()["ok"] is True
