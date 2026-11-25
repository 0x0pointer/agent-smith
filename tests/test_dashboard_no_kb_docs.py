from __future__ import annotations

import pathlib

from fastapi.testclient import TestClient

from core.api_server import app


client = TestClient(app)


def test_kb_docs_routes_removed():
    assert client.get("/api/kb/docs").status_code == 404
    assert client.post("/api/kb/docs", files={"files": ("x.txt", b"x")}).status_code == 404
    assert client.delete("/api/kb/docs/doc.md").status_code == 404


def test_operator_actions_tab_has_no_engagement_documents():
    html = pathlib.Path("dashboard/tabs/setup-gates.html").read_text(encoding="utf-8")
    assert "Resource requests" in html
    assert "Manual setup gates" in html
    assert "Engagement documents" not in html
    assert "kb-docs-input" not in html
    assert "/api/kb/docs" not in html


def test_setup_gates_js_has_no_kb_fetch_or_upload_handlers():
    js = pathlib.Path("dashboard/js/setup-gates.js").read_text(encoding="utf-8")
    assert "pollSetupGates" in js
    assert "/api/wishlist" in js
    assert "/api/kb/docs" not in js
    assert "_uploadKbDocs" not in js
    assert "_loadKbDocs" not in js
    assert "kb-docs" not in js
