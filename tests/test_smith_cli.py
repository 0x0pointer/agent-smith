import json
import os

import pytest

import smith_cli
from control_plane import orchestrator


@pytest.fixture(autouse=True)
def _isolate_database_url(monkeypatch):
    """main() sets a default SMITH_DATABASE_URL for its process. setenv first so
    monkeypatch records the original value and undoes that write; a bare delenv
    of an unset variable records nothing, and the URL would leak into later
    tests (which would then try to reach a real Postgres)."""
    monkeypatch.setenv("SMITH_DATABASE_URL", "placeholder")
    monkeypatch.delenv("SMITH_DATABASE_URL")


def test_smith_start_prints_started(monkeypatch, capsys):
    monkeypatch.setattr(
        "control_plane.orchestrator.start_control_plane",
        lambda: {"status": "started", "dashboard_url": "http://127.0.0.1:7777"},
    )
    assert smith_cli.main(["start"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "started"


def test_smith_status_prints_health(monkeypatch, capsys):
    monkeypatch.setattr(
        "control_plane.orchestrator.control_plane_status",
        lambda: {"database": "healthy", "dashboard": "running", "orchestrator": "running"},
    )
    assert smith_cli.main(["status"]) == 0
    body = json.loads(capsys.readouterr().out)
    assert body["database"] == "healthy"


def test_smith_stop_prints_stopped(monkeypatch, capsys):
    monkeypatch.setattr(
        "control_plane.orchestrator.stop_control_plane",
        lambda: {"status": "stopped"},
    )
    assert smith_cli.main(["stop"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "stopped"


def test_smith_status_checks_the_database_smith_start_uses(monkeypatch, capsys):
    """`smith status` in a fresh shell must check the database `smith start`
    brought up, not report it unavailable because SMITH_DATABASE_URL is unset."""
    seen = {}

    def _status():
        seen["url"] = os.environ.get("SMITH_DATABASE_URL")
        return {"database": "healthy"}

    monkeypatch.setattr("control_plane.orchestrator.control_plane_status", _status)
    assert smith_cli.main(["status"]) == 0
    assert seen["url"] == orchestrator._DEFAULT_DATABASE_URL


def test_smith_keeps_an_explicit_database_url(monkeypatch, capsys):
    monkeypatch.setenv("SMITH_DATABASE_URL", "sqlite:///custom.db")
    seen = {}

    def _status():
        seen["url"] = os.environ.get("SMITH_DATABASE_URL")
        return {"database": "healthy"}

    monkeypatch.setattr("control_plane.orchestrator.control_plane_status", _status)
    assert smith_cli.main(["status"]) == 0
    assert seen["url"] == "sqlite:///custom.db"


def test_control_plane_status_does_not_change_the_environment(monkeypatch):
    """Reading status must not switch the database on for a long-lived process."""
    monkeypatch.setattr("core.db.get_repository", lambda: None)
    monkeypatch.setattr("control_plane.orchestrator._read_pid_file", lambda path: None)

    orchestrator.control_plane_status()

    assert "SMITH_DATABASE_URL" not in os.environ
