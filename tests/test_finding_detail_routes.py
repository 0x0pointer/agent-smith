"""
Tests for the finding "dossier" routes added by the dashboard redesign:
  - GET /finding/{id}          → standalone detail page (HTML)
  - GET /api/findings/{id}     → one finding + related exploit chains (JSON)

Uses FastAPI's TestClient — no real HTTP server needed.
"""
import json
from unittest.mock import patch

from fastapi.testclient import TestClient

from core.api_server import app

client = TestClient(app)


# ── GET /finding/{id} — standalone dossier page ───────────────────────────────

def test_finding_detail_page_renders_html():
    resp = client.get("/finding/abc-123")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


def test_finding_detail_page_embeds_the_id():
    # Jinja autoescapes finding_id into data-finding-id so finding.js can read it.
    resp = client.get("/finding/d508b493-39d7-4606-9702-9ff9bcc3d5c6")
    assert resp.status_code == 200
    assert "d508b493-39d7-4606-9702-9ff9bcc3d5c6" in resp.text


# ── GET /api/findings/{id} — single finding + related chains ──────────────────

def _write_findings(tmp_path, monkeypatch, data):
    import core.api_server as srv
    f = tmp_path / "findings.json"
    f.write_text(json.dumps(data))
    monkeypatch.setattr(srv, "_FINDINGS_FILE", f)
    return f


def test_api_finding_returns_finding_when_present(tmp_path, monkeypatch):
    _write_findings(tmp_path, monkeypatch, {
        "meta": {"target": "example.com"},
        "findings": [{"id": "f1", "title": "SQLi", "severity": "high"}],
        "chains": [],
    })
    resp = client.get("/api/findings/f1")
    assert resp.status_code == 200
    body = resp.json()
    assert body["finding"]["id"] == "f1"
    assert body["finding"]["title"] == "SQLi"
    assert body["archived"] is False
    assert body["chains"] == []
    assert body["meta"]["target"] == "example.com"


def test_api_finding_404_when_unknown(tmp_path, monkeypatch):
    _write_findings(tmp_path, monkeypatch, {"findings": [{"id": "f1"}], "chains": []})
    resp = client.get("/api/findings/does-not-exist")
    assert resp.status_code == 404
    assert resp.json()["error"] == "not found"


def test_api_finding_falls_back_to_archived(tmp_path, monkeypatch):
    _write_findings(tmp_path, monkeypatch, {
        "findings": [{"id": "live"}],
        "archived": [{"id": "gone", "title": "Deleted finding"}],
        "chains": [],
    })
    resp = client.get("/api/findings/gone")
    assert resp.status_code == 200
    body = resp.json()
    assert body["finding"]["title"] == "Deleted finding"
    assert body["archived"] is True


def test_api_finding_attaches_related_chain_and_renders_svg(tmp_path, monkeypatch):
    _write_findings(tmp_path, monkeypatch, {
        "findings": [{"id": "f1", "title": "Prompt injection"}],
        "chains": [{
            "name": "PI to PII exfil",
            "combined_severity": "critical",
            "mermaid": "graph TD\n  A-->B",
            "steps": [{"from_finding_id": "f1", "to_finding_id": "f2"}],
        }],
    })
    with patch("core.api_server._render_mermaid_svgs", return_value={"0": "<svg>chain</svg>"}):
        resp = client.get("/api/findings/f1")
    assert resp.status_code == 200
    chains = resp.json()["chains"]
    assert len(chains) == 1
    assert chains[0]["svg"] == "<svg>chain</svg>"


def test_api_finding_skips_unrelated_chain(tmp_path, monkeypatch):
    _write_findings(tmp_path, monkeypatch, {
        "findings": [{"id": "f1"}],
        "chains": [{
            "name": "unrelated",
            "mermaid": "graph TD\n  X-->Y",
            "steps": [{"from_finding_id": "other", "to_finding_id": "another"}],
        }],
    })
    with patch("core.api_server._render_mermaid_svgs") as mock_render:
        resp = client.get("/api/findings/f1")
    assert resp.status_code == 200
    assert resp.json()["chains"] == []
    mock_render.assert_not_called()


def test_api_finding_keeps_prerendered_chain_svg(tmp_path, monkeypatch):
    _write_findings(tmp_path, monkeypatch, {
        "findings": [{"id": "f1"}],
        "chains": [{
            "name": "cached",
            "mermaid": "graph TD\n  A-->B",
            "svg": "<svg>cached</svg>",
            "steps": [{"to_finding_id": "f1"}],
        }],
    })
    with patch("core.api_server._render_mermaid_svgs") as mock_render:
        resp = client.get("/api/findings/f1")
    assert resp.status_code == 200
    assert resp.json()["chains"][0]["svg"] == "<svg>cached</svg>"
    mock_render.assert_not_called()
