"""
Tests for core.api_server FastAPI routes.
Uses FastAPI's TestClient — no real HTTP server needed.
"""
import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi.testclient import TestClient

from core.api_server import app, _read_json

client = TestClient(app)


# ── _read_json helper ─────────────────────────────────────────────────────────

def test_read_json_returns_dict_for_valid_file(tmp_path):
    f = tmp_path / "data.json"
    f.write_text('{"key": "value"}')
    assert _read_json(f) == {"key": "value"}

def test_read_json_returns_empty_for_missing_file(tmp_path):
    assert _read_json(tmp_path / "nonexistent.json") == {}

def test_read_json_returns_empty_for_invalid_json(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text("not json {{{")
    assert _read_json(f) == {}


# ── GET / ─────────────────────────────────────────────────────────────────────

def test_dashboard_returns_html():
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


# ── GET /api/findings ─────────────────────────────────────────────────────────

def test_api_findings_returns_json(tmp_path, monkeypatch):
    import core.api_server as srv
    monkeypatch.setattr(srv, "_FINDINGS_FILE", tmp_path / "findings.json")
    response = client.get("/api/findings")
    assert response.status_code == 200
    assert response.json() == {}

def test_api_findings_returns_data_when_file_exists(tmp_path, monkeypatch):
    import core.api_server as srv
    f = tmp_path / "findings.json"
    f.write_text('{"findings": [{"title": "SQLi"}]}')
    monkeypatch.setattr(srv, "_FINDINGS_FILE", f)
    response = client.get("/api/findings")
    assert response.status_code == 200
    assert response.json()["findings"][0]["title"] == "SQLi"


# ── GET /api/session ──────────────────────────────────────────────────────────

def test_api_session_returns_json(tmp_path, monkeypatch):
    import core.api_server as srv
    monkeypatch.setattr(srv, "_SESSION_FILE", tmp_path / "session.json")
    response = client.get("/api/session")
    assert response.status_code == 200
    assert response.json() == {}

def test_api_session_returns_data_when_file_exists(tmp_path, monkeypatch):
    import core.api_server as srv
    f = tmp_path / "session.json"
    f.write_text('{"target": "example.com", "status": "running"}')
    monkeypatch.setattr(srv, "_SESSION_FILE", f)
    response = client.get("/api/session")
    assert response.json()["target"] == "example.com"


# ── GET /api/cost ─────────────────────────────────────────────────────────────

def test_api_cost_returns_json(tmp_path, monkeypatch):
    import core.api_server as srv
    monkeypatch.setattr(srv, "_COST_FILE", tmp_path / "cost.json")
    response = client.get("/api/cost")
    assert response.status_code == 200
    assert response.json() == {}

def test_api_cost_returns_data_when_file_exists(tmp_path, monkeypatch):
    import core.api_server as srv
    f = tmp_path / "cost.json"
    f.write_text('{"est_cost_usd": 0.05}')
    monkeypatch.setattr(srv, "_COST_FILE", f)
    response = client.get("/api/cost")
    assert response.json()["est_cost_usd"] == 0.05


# ── GET /api/logs ─────────────────────────────────────────────────────────────

def test_api_logs_returns_lines(tmp_path, monkeypatch):
    import core.api_server as srv
    import core.logger as log_module
    log_file = tmp_path / "pentest.log"
    log_file.write_text("line1\nline2\nline3\n")
    monkeypatch.setattr(log_module, "_LOG_DIR", tmp_path)
    monkeypatch.setattr(log_module, "log_path", log_file)
    response = client.get("/api/logs")
    assert response.status_code == 200
    data = response.json()
    assert "lines" in data
    assert "line1" in data["lines"]

def test_api_logs_missing_log_file(tmp_path, monkeypatch):
    import core.logger as log_module
    missing = tmp_path / "missing.log"
    monkeypatch.setattr(log_module, "_LOG_DIR", tmp_path)
    monkeypatch.setattr(log_module, "log_path", missing)
    response = client.get("/api/logs")
    assert response.status_code == 200
    assert response.json()["lines"] == []

def test_api_logs_path_traversal_rejected(tmp_path, monkeypatch):
    import core.logger as log_module
    monkeypatch.setattr(log_module, "_LOG_DIR", tmp_path)
    monkeypatch.setattr(log_module, "log_path", tmp_path / "pentest.log")
    response = client.get("/api/logs?file=../../etc/passwd")
    assert response.status_code == 200
    data = response.json()
    assert data.get("error") is not None or data.get("lines") == []


# ── GET /api/threat-model ─────────────────────────────────────────────────────

def test_api_threat_model_no_dir(tmp_path, monkeypatch):
    import core.api_server as srv
    monkeypatch.setattr(srv, "_THREAT_MODEL_DIR", tmp_path / "nonexistent")
    response = client.get("/api/threat-model")
    assert response.status_code == 200
    data = response.json()
    assert data["files"] == []
    assert data["content"] == ""

def test_api_threat_model_returns_file_list(tmp_path, monkeypatch):
    import core.api_server as srv
    monkeypatch.setattr(srv, "_THREAT_MODEL_DIR", tmp_path)
    (tmp_path / "model1.md").write_text("# Threat model")
    (tmp_path / "model2.md").write_text("# Another model")
    response = client.get("/api/threat-model")
    assert response.status_code == 200
    assert len(response.json()["files"]) == 2

def test_api_threat_model_path_traversal_rejected(tmp_path, monkeypatch):
    import core.api_server as srv
    monkeypatch.setattr(srv, "_THREAT_MODEL_DIR", tmp_path)
    response = client.get("/api/threat-model?file=../../etc/passwd")
    assert response.status_code == 400

def test_api_threat_model_reads_content(tmp_path, monkeypatch):
    import core.api_server as srv
    monkeypatch.setattr(srv, "_THREAT_MODEL_DIR", tmp_path)
    md = tmp_path / "model.md"
    md.write_text("# My threat model\nsome content")
    with patch("core.api_server._get_svgs", new=AsyncMock(return_value={})):
        response = client.get("/api/threat-model?file=model.md")
    assert response.status_code == 200
    assert "My threat model" in response.json()["content"]

def test_api_threat_model_missing_file_returns_empty(tmp_path, monkeypatch):
    import core.api_server as srv
    monkeypatch.setattr(srv, "_THREAT_MODEL_DIR", tmp_path)
    response = client.get("/api/threat-model?file=ghost.md")
    assert response.status_code == 200
    assert response.json()["content"] == ""


# ── PATCH /api/findings/{id} ──────────────────────────────────────────────────

def test_api_patch_finding_success(monkeypatch):
    from core import findings as findings_mod
    monkeypatch.setattr(findings_mod, "update_finding", AsyncMock(return_value=True))
    response = client.patch("/api/findings/abc123", json={"gh_issue": "https://github.com/org/repo/issues/1"})
    assert response.status_code == 200
    assert response.json()["ok"] is True

def test_api_patch_finding_invalid_json():
    response = client.patch("/api/findings/abc123", content=b"not json", headers={"content-type": "application/json"})
    assert response.status_code == 400


# ── lifecycle helpers ─────────────────────────────────────────────────────────

def test_read_pid_returns_none_for_missing_file(tmp_path, monkeypatch):
    import core.api_server as srv
    monkeypatch.setattr(srv, "_PID_FILE", tmp_path / "dashboard.pid")
    assert srv._read_pid() is None

def test_read_pid_returns_int_when_file_exists(tmp_path, monkeypatch):
    import core.api_server as srv
    pid_file = tmp_path / "dashboard.pid"
    pid_file.write_text("12345")
    monkeypatch.setattr(srv, "_PID_FILE", pid_file)
    assert srv._read_pid() == 12345

def test_write_pid_creates_file(tmp_path, monkeypatch):
    import core.api_server as srv
    pid_file = tmp_path / "logs" / "dashboard.pid"
    pid_file.parent.mkdir()
    monkeypatch.setattr(srv, "_PID_FILE", pid_file)
    srv._write_pid(99999)
    assert pid_file.read_text() == "99999"

def test_pid_alive_returns_false_for_dead_pid():
    import core.api_server as srv
    assert srv._pid_alive(999999999) is False

def test_pid_alive_returns_true_for_self():
    import core.api_server as srv
    import os
    assert srv._pid_alive(os.getpid()) is True

def test_port_healthy_returns_false_for_unused_port():
    import core.api_server as srv
    assert srv._port_healthy(19999) is False
