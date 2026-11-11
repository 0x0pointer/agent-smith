"""Coverage for core/kb.py document helpers — HTML strip, structured/OpenAPI flatten,
PDF naive-salvage, docx fallback, parse_document dispatch, and add_session_doc
(tier-B writer + untrusted meta). All local, no network."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from core import kb as kb_mod


@pytest.fixture
def kb_sessions(tmp_path, monkeypatch):
    monkeypatch.setattr(kb_mod, "KB_ROOT", tmp_path / "kb")
    monkeypatch.setattr(kb_mod, "SESSIONS_DIR", tmp_path / "kb" / "sessions")
    return tmp_path


def test_html_to_text_strips_tags_and_scripts():
    out = kb_mod._html_to_text("<p>Hi &amp; <script>alert(1)</script><b>bye</b></p>")
    assert "Hi &" in out and "bye" in out
    assert "alert" not in out      # <script> body removed


def test_structured_to_text_openapi():
    spec = json.dumps({"openapi": "3.0.0", "paths": {
        "/api/login": {"post": {"summary": "Login", "parameters": [
            {"name": "user", "in": "body"}]}}}})
    out = kb_mod._structured_to_text(spec, "swagger.json")
    assert "OpenAPI 3.0.0" in out
    assert "POST /api/login — Login" in out and "user(body)" in out


def test_structured_to_text_plain_json_and_passthrough():
    assert "key" in kb_mod._structured_to_text('{"key": "val"}', "x.json")
    # a non-dict JSON (list) → returned as-is
    assert kb_mod._structured_to_text("[1,2,3]", "x.json") == "[1,2,3]"
    # unparseable → returned as-is
    assert kb_mod._structured_to_text("not json", "x.json") == "not json"


def test_pdf_naive_salvage(tmp_path):
    # a fake PDF: pdftotext/pypdf both fail on it → naive text-object salvage kicks in
    f = tmp_path / "doc.pdf"
    f.write_bytes(b"%PDF-1.4\n(Hello World salvage text)\nendobj\n")
    text, note = kb_mod._pdf_to_text(f)
    assert isinstance(text, str) and isinstance(note, str)
    assert "Hello World salvage text" in text   # salvaged


def test_docx_fallback_returns_tuple(tmp_path):
    f = tmp_path / "doc.docx"
    f.write_bytes(b"PK\x03\x04 not-a-real-docx")
    text, note = kb_mod._docx_to_text(f)
    assert isinstance(text, str) and isinstance(note, str)


def test_parse_document_dispatch(tmp_path):
    md = tmp_path / "a.md"; md.write_text("# Title\nbody")
    assert kb_mod.parse_document(md) == ("# Title\nbody", "raw", "ok")
    html = tmp_path / "a.html"; html.write_text("<h1>Head</h1><p>para</p>")
    t, note, status = kb_mod.parse_document(html)
    assert status == "ok" and note == "html-strip" and "Head" in t
    j = tmp_path / "a.json"; j.write_text('{"k":"v"}')
    assert kb_mod.parse_document(j)[2] == "ok" and kb_mod.parse_document(j)[1] == "structured"
    empty = tmp_path / "e.txt"; empty.write_text("   ")
    assert kb_mod.parse_document(empty)[2] == "empty"


def test_add_session_doc_and_untrusted_meta(kb_sessions):
    d1 = kb_mod.add_session_doc("sid1", "notes.md", "trusted content", untrusted=False)
    assert d1.exists() and d1.read_text() == "trusted content"
    assert not (kb_mod.SESSIONS_DIR / "sid1" / "meta.json").exists()   # trusted → no meta
    d2 = kb_mod.add_session_doc("sid1", "evil.md", "target content", untrusted=True)
    meta = json.loads((kb_mod.SESSIONS_DIR / "sid1" / "meta.json").read_text())
    assert d2.name in meta["untrusted"]
    # name collision → non-clobbering prefix
    d3 = kb_mod.add_session_doc("sid1", "notes.md", "second", untrusted=False)
    assert d3.name != d1.name and d3.read_text() == "second"


def test_add_session_doc_recovers_corrupt_meta(kb_sessions):
    sdir = kb_mod.SESSIONS_DIR / "sid9"
    sdir.mkdir(parents=True)
    (sdir / "meta.json").write_text("{corrupt json")      # unreadable → recovered as {}
    d = kb_mod.add_session_doc("sid9", "t.md", "content", untrusted=True)
    meta = json.loads((sdir / "meta.json").read_text())
    assert d.name in meta["untrusted"]


def test_parse_document_exception_path(tmp_path):
    # a directory with a .pdf suffix → _pdf_to_text's read_bytes() raises → parse error/skipped
    d = tmp_path / "adir.pdf"
    d.mkdir()
    text, note, status = kb_mod.parse_document(d)
    assert status == "skipped" and "parse error" in note


# ── read_text / structured helpers ───────────────────────────────────────────

def test_read_text_missing_returns_empty(tmp_path):
    assert kb_mod.read_text(tmp_path / "nope.txt") == ""


def test_structured_to_text_yaml_and_bad_op():
    # YAML OpenAPI → flattened (PyYAML available in this env)
    y = "openapi: 3.0.0\npaths:\n  /x:\n    get:\n      summary: get x\n"
    out = kb_mod._structured_to_text(y, "spec.yaml")
    assert "OpenAPI 3.0.0" in out and "GET /x" in out
    # a path op that isn't a dict is skipped → no ops → falls back to a json dump
    spec = json.dumps({"openapi": "3.0", "paths": {"/y": {"get": "not-a-dict"}}})
    out2 = kb_mod._structured_to_text(spec, "s.json")
    assert "openapi" in out2


def test_yaml_helpers():
    assert kb_mod.yaml_ok() is True
    assert kb_mod.yaml_load("a: 1")["a"] == 1


def test_chunk_splits_long_text():
    assert kb_mod._chunk("short") == ["short"]
    big = "\n\n".join("para " + ("x" * 500) for _ in range(30))   # > _MAX_CHUNK
    parts = kb_mod._chunk(big)
    assert len(parts) > 1


# ── FTS index round-trip (open_index create → replace → query → stats) ────────

def test_index_roundtrip(kb_sessions):
    db = kb_sessions / "idx.db"
    con = kb_mod.open_index(db, create=True)
    assert con is not None
    try:
        gtfo = [{"source": "kb:gtfobins/sudo", "kind": "gtfobins", "title": "sudo",
                 "tags": ["suid", "shell"], "text": "sudo lets a user run a root shell",
                 "untrusted": False}]
        wstg = [{"source": "kb:wstg/athn-02", "kind": "wstg", "title": "default creds",
                 "tags": ["athn"], "text": "testing for default credentials admin admin",
                 "untrusted": False}]
        assert kb_mod.replace_source(con, "kb:gtfobins", gtfo) == 1
        kb_mod.replace_source(con, "kb:wstg", wstg)
        kb_mod.record_meta(con, "gtfobins", 1, "ref-sha", "GPL")
        # AND-match (all terms in one doc)
        assert any(h["kind"] == "gtfobins" for h in kb_mod.query_index(con, "sudo root shell"))
        # kind filter + OR-fallback (no single doc has both terms)
        hits2 = kb_mod.query_index(con, "sudo credentials", ["wstg"], 8)
        assert hits2 and all(h["kind"] == "wstg" for h in hits2)
        # sub-2-char tokens only → no usable terms → []
        assert kb_mod.query_index(con, "a b c") == []
        stats = kb_mod.index_stats(con)
        assert stats["kinds"].get("gtfobins") == 1 and stats["built_at"]
    finally:
        con.close()


def test_open_index_missing_returns_none(tmp_path):
    assert kb_mod.open_index(tmp_path / "absent.db") is None


# ── flat-scan providers + manifest + unindexed dirs ──────────────────────────

def test_iter_kb_sources_skips_raw_and_empty(kb_sessions, monkeypatch):
    src = kb_sessions / "kb" / "sources"
    monkeypatch.setattr(kb_mod, "SOURCES_DIR", src)
    assert kb_mod.iter_kb_sources() == []                  # not a dir yet
    (src / "gtfobins").mkdir(parents=True)
    (src / "gtfobins" / "sudo.md").write_text("sudo root shell")
    (src / "gtfobins" / "empty.md").write_text("   ")       # empty → skipped
    (src / "_raw").mkdir()
    (src / "_raw" / "clone.md").write_text("raw clone noise")  # _raw → skipped
    titles = [d["title"] for d in kb_mod.iter_kb_sources()]
    assert "gtfobins/sudo.md" in titles
    assert not any("clone" in t or "empty" in t for t in titles)


def test_iter_session_docs_fence_and_skips(kb_sessions):
    sdir = kb_mod.SESSIONS_DIR / "sid1"
    sdir.mkdir(parents=True)
    (sdir / "notes.md").write_text("vault token rotates hourly")
    (sdir / "empty.txt").write_text("  ")                   # empty → skipped
    (sdir / "skip.bin").write_bytes(b"\x00\x01")            # non-flat ext → skipped
    (sdir / "meta.json").write_text("{corrupt")            # unreadable meta → swallowed
    docs = kb_mod.iter_session_docs()
    titles = [d["title"] for d in docs]
    assert "notes.md" in titles
    assert not any("empty" in t or "skip" in t for t in titles)
    assert docs[0]["source"].startswith("docs:sid1/")


def test_purge_session_docs(kb_sessions):
    assert kb_mod.purge_session_docs() == 0                 # no sessions dir yet
    sdir = kb_mod.SESSIONS_DIR / "sid1"
    sdir.mkdir(parents=True)
    (sdir / "a.md").write_text("x")
    (sdir / "meta.json").write_text("{}")                   # meta/raw_ not counted
    (sdir / "raw_1_x.md").write_text("y")
    assert kb_mod.purge_session_docs() == 1 and not sdir.exists()


def test_load_manifest(tmp_path):
    assert kb_mod.load_manifest(tmp_path / "none.json") == {}
    good = tmp_path / "m.json"
    good.write_text('{"gtfobins": {"docs": 3}}')
    assert kb_mod.load_manifest(good)["gtfobins"]["docs"] == 3
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert kb_mod.load_manifest(bad) == {}


def test_unindexed_source_dirs(kb_sessions, monkeypatch):
    src = kb_sessions / "kb" / "sources"
    monkeypatch.setattr(kb_mod, "SOURCES_DIR", src)
    assert kb_mod.unindexed_source_dirs(None) == []         # no sources dir
    (src / "myorg-playbooks").mkdir(parents=True)
    (src / "gtfobins").mkdir()
    (src / "_raw").mkdir()                                   # _raw always excluded
    # no index → every non-_raw dir is flat-scanned
    assert {d.name for d in kb_mod.unindexed_source_dirs(None)} == {"myorg-playbooks", "gtfobins"}
    # an index recording gtfobins as built → only the unbuilt dir remains
    con = kb_mod.open_index(kb_sessions / "idx.db", create=True)
    kb_mod.record_meta(con, "gtfobins", 1)
    try:
        assert {d.name for d in kb_mod.unindexed_source_dirs(con)} == {"myorg-playbooks"}
    finally:
        con.close()
