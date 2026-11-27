"""
Tests for the per-session dashboard bearer-token gate.

The suite-wide autouse fixture (tests/conftest.py) disables the gate so the
other API tests can hit /api/* without a header; here we re-enable it via
SMITH_DASHBOARD_AUTH=1 and exercise the real behaviour.
"""
import pytest
import sqlite3
from fastapi.testclient import TestClient

from core.api_server import app
from core import dashboard_auth
from core import paths as _paths


@pytest.fixture
def token_file(tmp_path, monkeypatch):
    """Redirect the token file to tmp and re-enable enforcement."""
    monkeypatch.setattr(_paths, "DASHBOARD_TOKEN_FILE", tmp_path / "dashboard.token")
    monkeypatch.setenv("SMITH_DASHBOARD_AUTH", "1")
    return _paths.DASHBOARD_TOKEN_FILE


def test_healthz_open_even_with_token(token_file):
    dashboard_auth.mint_token()
    assert TestClient(app).get("/healthz").status_code == 200


def test_api_open_when_no_session_token(token_file):
    # No token minted yet → nothing sensitive to protect → open.
    assert TestClient(app).get("/api/session").status_code == 200


def test_api_401_without_bearer(token_file):
    dashboard_auth.mint_token()
    assert TestClient(app).get("/api/session").status_code == 401


def test_api_401_with_wrong_bearer(token_file):
    dashboard_auth.mint_token()
    r = TestClient(app).get("/api/session", headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401


def test_api_200_with_correct_bearer(token_file):
    tok = dashboard_auth.mint_token()
    r = TestClient(app).get("/api/session", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200


def test_mint_rotates_and_verifies(token_file):
    t1 = dashboard_auth.mint_token()
    assert dashboard_auth.verify(t1)
    t2 = dashboard_auth.mint_token()
    assert t2 and t2 != t1
    assert dashboard_auth.verify(t2)
    assert not dashboard_auth.verify(t1)      # old token invalidated
    assert not dashboard_auth.verify("")
    assert not dashboard_auth.verify(None)


def test_token_file_is_0600(token_file):
    import os
    import stat
    dashboard_auth.mint_token()
    mode = stat.S_IMODE(os.stat(token_file).st_mode)
    # On POSIX the file must not be group/world readable.
    if os.name == "posix":
        assert mode & 0o077 == 0, oct(mode)


def test_db_tokens_store_hashes_and_scope_run_ids(monkeypatch, tmp_path):
    db_path = tmp_path / "auth.db"
    monkeypatch.setenv("SMITH_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.delenv("SMITH_SINGLE_RUN", raising=False)

    token = dashboard_auth.mint_run_token("run-a")
    meta = dashboard_auth.verify_bearer(token)

    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "select run_id, role, token_hash from dashboard_tokens"
        ).fetchone()

    assert meta == {"run_id": "run-a", "role": "run"}
    assert row[0] == "run-a"
    assert row[1] == "run"
    assert row[2] != token
