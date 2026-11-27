import sqlite3
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from core.api_server import app
from core import dashboard_auth
from core import db as db_store


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _create_run(client: TestClient, operator_token: str, target: str) -> dict:
    with patch("subprocess.Popen", return_value=MagicMock(pid=1234)):
        response = client.post(
            "/api/runs",
            json={"target": target, "depth": "recon"},
            headers=_headers(operator_token),
        )
    assert response.status_code == 200
    return response.json()


def test_operator_token_can_create_and_stop(monkeypatch, tmp_path):
    db_path = tmp_path / "runs.db"
    monkeypatch.setenv("SMITH_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("SMITH_DASHBOARD_AUTH", "1")
    monkeypatch.delenv("SMITH_SINGLE_RUN", raising=False)

    client = TestClient(app)
    operator_token = dashboard_auth.mint_operator_token()

    created = _create_run(client, operator_token, "https://a.example")
    listed = client.get("/api/runs", headers=_headers(operator_token))
    stopped = client.post(f"/api/runs/{created['run_id']}/stop", headers=_headers(operator_token))

    assert created["status"] == "running"
    assert created["token"]
    assert "#k=" in created["dashboard_url"]
    assert listed.status_code == 200
    assert listed.json()[0]["run_id"] == created["run_id"]
    assert stopped.status_code == 200
    assert stopped.json()["status"] == "stopped"


def test_api_runs_list_persists_after_restart(monkeypatch, tmp_path):
    db_path = tmp_path / "runs.db"
    monkeypatch.setenv("SMITH_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("SMITH_DASHBOARD_AUTH", "1")
    monkeypatch.delenv("SMITH_SINGLE_RUN", raising=False)

    operator_token = dashboard_auth.mint_operator_token()
    first_client = TestClient(app)
    created = _create_run(first_client, operator_token, "https://persist.example")

    second_client = TestClient(app)
    listed = second_client.get("/api/runs", headers=_headers(operator_token))

    assert listed.status_code == 200
    assert [row["run_id"] for row in listed.json()] == [created["run_id"]]


def test_run_token_scopes_existing_tabs(monkeypatch, tmp_path):
    db_path = tmp_path / "runs.db"
    monkeypatch.setenv("SMITH_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("SMITH_DASHBOARD_AUTH", "1")
    monkeypatch.delenv("SMITH_SINGLE_RUN", raising=False)

    client = TestClient(app)
    operator_token = dashboard_auth.mint_operator_token()
    run_a = _create_run(client, operator_token, "https://a.example")
    run_b = _create_run(client, operator_token, "https://b.example")

    repo = db_store.get_repository()
    repo.save_snapshot(run_a["run_id"], "findings", {"findings": [{"title": "SQLi A"}]})
    repo.save_snapshot(run_a["run_id"], "session", {"target": "https://a.example", "status": "running"})
    repo.save_snapshot(run_b["run_id"], "findings", {"findings": [{"title": "XSS B"}]})
    repo.save_snapshot(run_b["run_id"], "session", {"target": "https://b.example", "status": "running"})

    findings_a = client.get("/api/findings", headers=_headers(run_a["token"]))
    session_b = client.get("/api/session", headers=_headers(run_b["token"]))

    assert findings_a.json()["findings"][0]["title"] == "SQLi A"
    assert session_b.json()["target"] == "https://b.example"


def test_cross_run_token_rejected(monkeypatch, tmp_path):
    db_path = tmp_path / "runs.db"
    monkeypatch.setenv("SMITH_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("SMITH_DASHBOARD_AUTH", "1")
    monkeypatch.delenv("SMITH_SINGLE_RUN", raising=False)

    client = TestClient(app)
    operator_token = dashboard_auth.mint_operator_token()
    run_a = _create_run(client, operator_token, "https://a.example")
    run_b = _create_run(client, operator_token, "https://b.example")

    response = client.post(f"/api/runs/{run_b['run_id']}/stop", headers=_headers(run_a["token"]))

    assert response.status_code == 403
