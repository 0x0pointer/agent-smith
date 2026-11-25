import json
from pathlib import Path

from fastapi.testclient import TestClient

import core.api_server as api
import core.session as scan_session
from core import vector_store as vector_mod
from core.api_server import app

client = TestClient(app)


def test_setup_gates_uses_vector_vaults_not_kb_docs(tmp_path, monkeypatch):
    session_file = tmp_path / "session.json"
    session_file.write_text(json.dumps({"id": "sess-ui", "target": "http://t", "status": "running"}))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(scan_session, "_SESSION_FILE", session_file)
    monkeypatch.setattr(api, "_SESSION_FILE", session_file)
    monkeypatch.setattr(vector_mod, "VECTOR_ROOT", tmp_path / "vectors")
    monkeypatch.setattr(vector_mod, "KB_ROOT", tmp_path / "kb")
    monkeypatch.setattr(vector_mod, "RAW_DIR", tmp_path / "kb" / "sources" / "_raw")
    monkeypatch.setattr(vector_mod, "MANIFEST", tmp_path / "kb" / "MANIFEST.json")
    scan_session._current = None
    vector_mod.ingest_text(vault="engagement-sess-ui", dataset="docs", name="brief.md", text="alpha", untrusted=False)
    vector_mod.ingest_text(vault="engagement-sess-ui", dataset="api", name="openapi.md", text="beta", untrusted=False)
    vector_mod.ingest_text(vault="security", dataset="refs", name="owasp.md", text="gamma", untrusted=False)

    payload = client.get("/api/vector/docs").json()
    assert payload["vaults"] == [
        {
            "name": "engagement-sess-ui",
            "datasets": [{"name": "api", "docs": 1}, {"name": "docs", "docs": 1}],
            "docs": 2,
        },
        {
            "name": "security",
            "datasets": [{"name": "refs", "docs": 1}],
            "docs": 1,
        },
    ]

    root = Path(__file__).resolve().parent.parent / "dashboard"
    html = (root / "tabs" / "setup-gates.html").read_text()
    js = (root / "js" / "setup-gates.js").read_text()

    assert "Vector vaults" in html
    assert 'id="vector-vaults-wrap"' in html
    assert "/api/vector/docs" in js
    assert "_renderVectorVaults" in js
    assert "_selectVectorVaultDataset" in js
    assert "data.vaults" in js
    assert "vault.name" in js
    assert "vault.docs" in js
    assert "dataset.name" in js
    assert "dataset.docs" in js
    assert "Engagement documents" not in html
    assert "_uploadKbDocs" not in js
