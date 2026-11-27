from unittest.mock import MagicMock, patch

import pytest

from control_plane import orchestrator
from core import db as db_store


def test_create_run_inserts_row_and_starts_worker(monkeypatch, tmp_path):
    db_path = tmp_path / "runs.db"
    monkeypatch.setenv("SMITH_DATABASE_URL", f"sqlite:///{db_path}")

    with patch("subprocess.Popen", return_value=MagicMock(pid=4321)):
        created = orchestrator.create_run({"target": "https://a.example", "depth": "recon"})

    listed = orchestrator.list_runs()
    assert created["run_id"].startswith("run-")
    assert listed[0]["run_id"] == created["run_id"]
    assert listed[0]["status"] == "running"


def test_concurrent_create_two_runs(monkeypatch, tmp_path):
    db_path = tmp_path / "runs.db"
    monkeypatch.setenv("SMITH_DATABASE_URL", f"sqlite:///{db_path}")

    with patch("subprocess.Popen", side_effect=[MagicMock(pid=1), MagicMock(pid=2)]):
        run_a = orchestrator.create_run({"target": "https://a.example", "depth": "recon"})
        run_b = orchestrator.create_run({"target": "https://b.example", "depth": "recon"})

    rows = orchestrator.list_runs()
    assert run_a["run_id"] != run_b["run_id"]
    assert {row["run_id"] for row in rows} == {run_a["run_id"], run_b["run_id"]}


def test_create_run_validation_400(monkeypatch, tmp_path):
    db_path = tmp_path / "runs.db"
    monkeypatch.setenv("SMITH_DATABASE_URL", f"sqlite:///{db_path}")

    with pytest.raises(ValueError):
        orchestrator.create_run({"target": "", "depth": "bogus"})


def test_docker_failure_marks_failed_and_cleans(monkeypatch, tmp_path):
    db_path = tmp_path / "runs.db"
    monkeypatch.setenv("SMITH_DATABASE_URL", f"sqlite:///{db_path}")

    with patch("subprocess.Popen", side_effect=OSError("docker failed")):
        with pytest.raises(OSError):
            orchestrator.create_run({"target": "https://broken.example", "depth": "recon"})

    rows = orchestrator.list_runs()
    assert rows[0]["status"] == "failed"
