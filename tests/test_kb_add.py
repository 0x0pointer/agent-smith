"""Coverage for mcp_server/session_tools/kb_add.py — session(action='kb_add') tier-B
document ingestion (path / dir / url / artifact_id), the trust fence, and the
known_assets.kb_docs record. url/artifact branches are driven without network."""
from __future__ import annotations

import json
import pytest

from core import kb as kb_mod
import core.session as scan_session
from mcp_server.session_tools.kb_add import _do_kb_add, _collect_paths, _name_from_url


@pytest.fixture
def kb_add_env(tmp_path, monkeypatch):
    kb_root = tmp_path / "kb"
    (kb_root / "sessions").mkdir(parents=True)
    monkeypatch.setattr(kb_mod, "KB_ROOT", kb_root)
    monkeypatch.setattr(kb_mod, "SESSIONS_DIR", kb_root / "sessions")
    monkeypatch.setattr(kb_mod, "INDEX_DB", kb_root / "index.db")
    monkeypatch.chdir(tmp_path)
    scan_session.start("http://target.example:30081")
    return tmp_path


@pytest.mark.asyncio
async def test_kb_add_file(kb_add_env):
    doc = kb_add_env / "api-notes.md"
    doc.write_text("# API notes\nPOST /api/login authenticates with user_input.\n")
    out = await _do_kb_add({"path": str(doc)})
    assert "1 document(s) ingested" in out
    assert "UNTRUSTED" not in out          # operator path → trusted by default
    sid = (scan_session.get() or {}).get("id")
    assert list((kb_mod.SESSIONS_DIR / sid).glob("*.md"))
    assert (scan_session.get() or {}).get("known_assets", {}).get("kb_docs")


@pytest.mark.asyncio
async def test_kb_add_dir(kb_add_env):
    d = kb_add_env / "client-docs"
    d.mkdir()
    (d / "a.md").write_text("alpha endpoint doc")
    (d / "b.txt").write_text("beta endpoint doc")
    (d / "skip.bin").write_bytes(b"\x00\x01")   # non-parse ext → not collected
    out = await _do_kb_add({"path": str(d)})
    assert "2 document(s) ingested" in out


@pytest.mark.asyncio
async def test_kb_add_untrusted_override(kb_add_env):
    doc = kb_add_env / "notes.md"
    doc.write_text("some content here")
    out = await _do_kb_add({"path": str(doc), "untrusted": True})
    assert "UNTRUSTED" in out              # explicit untrusted override honored
    assert (scan_session.get() or {}).get("known_assets", {}).get("kb_docs")


@pytest.mark.asyncio
async def test_kb_add_path_not_found(kb_add_env):
    out = await _do_kb_add({"path": "/no/such/file.md"})
    assert "nothing ingested" in out and "not found" in out


@pytest.mark.asyncio
async def test_kb_add_no_input(kb_add_env):
    out = await _do_kb_add({})
    assert "nothing ingested" in out and "path:" in out


@pytest.mark.asyncio
async def test_kb_add_str_opts_parsed(kb_add_env):
    doc = kb_add_env / "x.md"
    doc.write_text("content")
    out = await _do_kb_add(json.dumps({"path": str(doc)}))
    assert "ingested" in out


@pytest.mark.asyncio
async def test_kb_add_bad_str_opts(kb_add_env):
    assert "must be a JSON object" in await _do_kb_add("not json {")


@pytest.mark.asyncio
async def test_kb_add_url(kb_add_env, monkeypatch):
    import mcp_server.session_tools.kb_add as mod
    monkeypatch.setattr(mod, "_fetch_url",
                        lambda url: (b"<html><body>swagger paths /api/login</body></html>", "text/html"))
    out = await _do_kb_add({"url": "http://target.example/api-docs"})
    assert "ingested" in out and "UNTRUSTED" in out   # url-sourced → untrusted fence


@pytest.mark.asyncio
async def test_kb_add_url_fetch_fails(kb_add_env, monkeypatch):
    import mcp_server.session_tools.kb_add as mod
    def _boom(url):
        raise OSError("connection refused")
    monkeypatch.setattr(mod, "_fetch_url", _boom)
    out = await _do_kb_add({"url": "http://target.example/x"})
    assert "nothing ingested" in out and "url fetch failed" in out


@pytest.mark.asyncio
async def test_kb_add_artifact_not_found(kb_add_env):
    out = await _do_kb_add({"artifact_id": "nope_123"})
    assert "nothing ingested" in out and "not found" in out


def test_name_from_url():
    assert _name_from_url("http://x/api-docs/swagger.json?v=2") == "swagger.json"
    assert _name_from_url("http://x/") == "x"
