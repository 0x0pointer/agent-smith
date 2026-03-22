"""
Tests for tools.metasploit.server — Flask API for Metasploit container.

Uses Flask test client — no Docker needed.
Skipped entirely if Flask is not installed (it lives inside the Docker image).
"""
import json
import sys
import os
from unittest.mock import patch, MagicMock

import pytest

flask = pytest.importorskip("flask", reason="Flask only installed inside Metasploit Docker image")

# Add the metasploit tools dir to path so we can import server
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools", "metasploit"))
import server  # noqa: E402


@pytest.fixture
def client():
    server.app.config["TESTING"] = True
    with server.app.test_client() as c:
        yield c


@pytest.fixture(autouse=True)
def _clear_api_secret():
    """Reset API secret between tests."""
    original = server._API_SECRET
    server._API_SECRET = ""
    yield
    server._API_SECRET = original


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------

def test_health_returns_ok(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


# ---------------------------------------------------------------------------
# Command endpoint — basic functionality
# ---------------------------------------------------------------------------

def test_run_command_success(client):
    mock_result = MagicMock()
    mock_result.stdout = b"uid=0(root)"
    mock_result.stderr = b""
    with patch("server.subprocess.run", return_value=mock_result):
        resp = client.post("/api/command", json={"command": "id"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["stdout"] == "uid=0(root)"
    assert data["timed_out"] is False


def test_run_command_empty_returns_400(client):
    resp = client.post("/api/command", json={"command": ""})
    assert resp.status_code == 400
    assert "empty" in resp.get_json()["error"]


def test_run_command_no_command_key_returns_400(client):
    resp = client.post("/api/command", json={})
    assert resp.status_code == 400


def test_run_command_includes_stderr(client):
    mock_result = MagicMock()
    mock_result.stdout = b""
    mock_result.stderr = b"warning: something"
    with patch("server.subprocess.run", return_value=mock_result):
        resp = client.post("/api/command", json={"command": "ls /nonexistent"})
    data = resp.get_json()
    assert data["stderr"] == "warning: something"


def test_run_command_timeout(client):
    import subprocess
    exc = subprocess.TimeoutExpired(cmd="sleep 999", timeout=1)
    exc.stdout = b"partial"
    exc.stderr = b""
    with patch("server.subprocess.run", side_effect=exc):
        resp = client.post("/api/command", json={"command": "sleep 999", "timeout": 1})
    data = resp.get_json()
    assert data["timed_out"] is True
    assert data["stdout"] == "partial"


def test_run_command_timeout_no_output(client):
    import subprocess
    exc = subprocess.TimeoutExpired(cmd="sleep 999", timeout=1)
    exc.stdout = None
    exc.stderr = None
    with patch("server.subprocess.run", side_effect=exc):
        resp = client.post("/api/command", json={"command": "sleep 999"})
    data = resp.get_json()
    assert data["timed_out"] is True
    assert data["stdout"] == ""
    assert data["stderr"] == ""


# ---------------------------------------------------------------------------
# API secret authentication
# ---------------------------------------------------------------------------

def test_api_secret_blocks_unauthorized(client):
    server._API_SECRET = "mysecret"
    resp = client.post("/api/command", json={"command": "id"})
    assert resp.status_code == 403
    assert "unauthorized" in resp.get_json()["error"]


def test_api_secret_allows_authorized(client):
    server._API_SECRET = "mysecret"
    mock_result = MagicMock()
    mock_result.stdout = b"root"
    mock_result.stderr = b""
    with patch("server.subprocess.run", return_value=mock_result):
        resp = client.post(
            "/api/command",
            json={"command": "whoami"},
            headers={"X-API-Secret": "mysecret"},
        )
    assert resp.status_code == 200
    assert resp.get_json()["stdout"] == "root"


def test_api_secret_wrong_key_blocked(client):
    server._API_SECRET = "mysecret"
    resp = client.post(
        "/api/command",
        json={"command": "id"},
        headers={"X-API-Secret": "wrongkey"},
    )
    assert resp.status_code == 403


def test_no_secret_set_allows_all(client):
    server._API_SECRET = ""
    mock_result = MagicMock()
    mock_result.stdout = b"ok"
    mock_result.stderr = b""
    with patch("server.subprocess.run", return_value=mock_result):
        resp = client.post("/api/command", json={"command": "echo ok"})
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Binary output handling
# ---------------------------------------------------------------------------

def test_invalid_utf8_decoded_with_replace(client):
    mock_result = MagicMock()
    mock_result.stdout = b"\xff\xfe raw"
    mock_result.stderr = b""
    with patch("server.subprocess.run", return_value=mock_result):
        resp = client.post("/api/command", json={"command": "cat binary"})
    data = resp.get_json()
    assert isinstance(data["stdout"], str)
