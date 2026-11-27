import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from control_plane import orchestrator
from core.api_server import app
from core import dashboard_auth


def _configure_db(monkeypatch, tmp_path):
    db_path = tmp_path / "runs.db"
    monkeypatch.setenv("SMITH_DATABASE_URL", f"sqlite:///{db_path}")
    return db_path


def _configure_authenticated_multi_run(monkeypatch, tmp_path):
    _configure_db(monkeypatch, tmp_path)
    monkeypatch.setenv("SMITH_DASHBOARD_AUTH", "1")
    monkeypatch.delenv("SMITH_SINGLE_RUN", raising=False)


def test_create_run_inserts_row_and_starts_worker(monkeypatch, tmp_path):
    _configure_db(monkeypatch, tmp_path)

    with patch("subprocess.Popen", return_value=MagicMock(pid=4321)):
        created = orchestrator.create_run({"target": "https://a.example", "depth": "recon"})

    listed = orchestrator.list_runs()
    assert created["run_id"].startswith("run-")
    assert listed[0]["run_id"] == created["run_id"]
    assert listed[0]["status"] == "running"


def test_concurrent_create_two_runs(monkeypatch, tmp_path):
    _configure_db(monkeypatch, tmp_path)

    with patch("subprocess.Popen", side_effect=[MagicMock(pid=1), MagicMock(pid=2)]):
        run_a = orchestrator.create_run({"target": "https://a.example", "depth": "recon"})
        run_b = orchestrator.create_run({"target": "https://b.example", "depth": "recon"})

    rows = orchestrator.list_runs()
    assert run_a["run_id"] != run_b["run_id"]
    assert {row["run_id"] for row in rows} == {run_a["run_id"], run_b["run_id"]}


def test_create_run_validation_400(monkeypatch, tmp_path):
    _configure_db(monkeypatch, tmp_path)

    with pytest.raises(ValueError):
        orchestrator.create_run({"target": "", "depth": "bogus"})


def test_create_run_rejects_non_dict_without_side_effects(monkeypatch, tmp_path):
    _configure_db(monkeypatch, tmp_path)

    with patch("subprocess.Popen") as popen:
        with pytest.raises(ValueError, match="object"):
            orchestrator.create_run([])

    assert popen.call_count == 0
    assert orchestrator.list_runs() == []


def test_create_run_rejects_oversized_scope_without_side_effects(monkeypatch, tmp_path):
    _configure_db(monkeypatch, tmp_path)

    payload = {
        "target": "https://valid.example",
        "depth": "recon",
        "scope": ["a" * 600 for _ in range(130)],
    }
    with patch("subprocess.Popen") as popen:
        with pytest.raises(ValueError, match="scope"):
            orchestrator.create_run(payload)

    assert popen.call_count == 0
    assert orchestrator.list_runs() == []


def test_api_create_run_malformed_body_400_without_side_effects(monkeypatch, tmp_path):
    _configure_authenticated_multi_run(monkeypatch, tmp_path)

    client = TestClient(app)
    operator_token = dashboard_auth.mint_operator_token()

    with patch("subprocess.Popen") as popen:
        response = client.post(
            "/api/runs",
            content="[",
            headers={**{"Content-Type": "application/json"}, "Authorization": f"Bearer {operator_token}"},
        )

    assert response.status_code == 400
    assert popen.call_count == 0
    assert orchestrator.list_runs() == []


def test_docker_failure_marks_failed_and_cleans(monkeypatch, tmp_path):
    _configure_db(monkeypatch, tmp_path)

    with patch("subprocess.Popen", side_effect=OSError("docker failed")):
        with pytest.raises(OSError):
            orchestrator.create_run({"target": "https://broken.example", "depth": "recon"})

    rows = orchestrator.list_runs()
    assert rows[0]["status"] == "failed"


def test_create_run_retries_generated_id_collision_before_side_effects(monkeypatch, tmp_path):
    _configure_db(monkeypatch, tmp_path)
    new_run_id = MagicMock(return_value="run-same")
    monkeypatch.setattr(orchestrator, "_new_run_id", new_run_id)

    with patch("subprocess.Popen", return_value=MagicMock(pid=1111)):
        original = orchestrator.create_run({"target": "https://original.example", "depth": "recon"})

    with patch("subprocess.Popen") as popen:
        with pytest.raises(orchestrator.RunIdCollisionError):
            orchestrator.create_run({"target": "https://collision.example", "depth": "danger"})

    rows = orchestrator.list_runs()
    assert original["run_id"] == "run-same"
    assert popen.call_count == 0
    assert len(rows) == 1
    assert rows[0]["run_id"] == "run-same"
    assert rows[0]["target"] == "https://original.example"
    assert rows[0]["depth"] == "recon"
    assert new_run_id.call_count > 2


def test_create_run_spawns_agent_driver_with_run_start_context(monkeypatch, tmp_path):
    _configure_db(monkeypatch, tmp_path)
    monkeypatch.setattr(orchestrator, "_new_run_id", lambda: "run-context")

    captured = {}

    def _capture_popen(args, **kwargs):
        captured["args"] = list(args)
        captured["kwargs"] = kwargs
        return MagicMock(pid=2222)

    with patch("subprocess.Popen", side_effect=_capture_popen):
        orchestrator.create_run({
            "target": "https://target.example",
            "depth": "thorough",
            "scope": ["https://target.example/app"],
            "out_of_scope": ["https://target.example/admin"],
        })

    env = captured["kwargs"]["env"]
    argv_text = "\n".join(str(part) for part in captured["args"])
    options_path = Path(env["SMITH_WORKDIR"]) / orchestrator._RUN_START_OPTIONS_FILENAME
    assert captured["args"][:3] != [orchestrator.sys.executable, "-m", "mcp_server"]
    assert env["SMITH_RUN_ID"] == "run-context"
    assert env["SMITH_WORKDIR"].endswith("/runs/run-context")
    assert env["SMITH_RUN_TARGET"] == "https://target.example"
    assert env["SMITH_RUN_DEPTH"] == "thorough"
    assert "https://target.example/app" in env["SMITH_RUN_SCOPE"]
    assert "https://target.example/admin" in env["SMITH_RUN_OUT_OF_SCOPE"]
    assert "session(action='start'" in argv_text
    assert str(options_path) in argv_text
    assert "https://target.example" not in argv_text
    assert json.loads(options_path.read_text(encoding="utf-8")) == {
        "target": "https://target.example",
        "depth": "thorough",
        "scope": ["https://target.example/app"],
        "out_of_scope": ["https://target.example/admin"],
    }


def test_stop_run_cleans_only_targeted_resources(monkeypatch, tmp_path):
    _configure_db(monkeypatch, tmp_path)

    with patch("subprocess.Popen", return_value=MagicMock(pid=4321)):
        created = orchestrator.create_run({"target": "https://a.example", "depth": "recon"})

    with (
        patch("control_plane.orchestrator._stop_worker", return_value=[] ) as stop_worker,
        patch("control_plane.orchestrator._stop_run_tooling", return_value=[] ) as stop_tools,
    ):
        stopped = orchestrator.stop_run(created["run_id"])

    assert stopped["status"] == "stopped"
    assert stop_worker.call_args.args == (created["run_id"], 4321)
    assert stop_tools.call_args.args == (created["run_id"],)


def test_start_control_plane_starts_services_and_returns_operator_token(monkeypatch):
    monkeypatch.setattr("control_plane.orchestrator._start_database", lambda: {"database": "healthy"})
    monkeypatch.setattr("control_plane.orchestrator._wait_for_database", lambda timeout_s=15.0: True)
    monkeypatch.setattr("control_plane.orchestrator._start_dashboard", lambda: 101)
    monkeypatch.setattr("control_plane.orchestrator._wait_for_dashboard", lambda timeout_s=5.0: True)
    monkeypatch.setattr("control_plane.orchestrator._wait_for_orchestrator", lambda timeout_s=5.0: True)
    monkeypatch.setattr("core.dashboard_auth.mint_operator_token", lambda: "operator-token")

    started = orchestrator.start_control_plane()

    assert started == {
        "status": "started",
        "database": "healthy",
        "dashboard": "running",
        "orchestrator": "running",
        "dashboard_url": "http://127.0.0.1:7777",
        "operator_token": "operator-token",
    }


def test_start_control_plane_reports_unhealthy_without_minting_when_database_not_ready(monkeypatch):
    monkeypatch.setattr("control_plane.orchestrator._start_database", lambda: {"database": "healthy"})
    monkeypatch.setattr("control_plane.orchestrator._wait_for_database", lambda timeout_s=15.0: False)
    mint = MagicMock(return_value="operator-token")
    monkeypatch.setattr("core.dashboard_auth.mint_operator_token", mint)

    started = orchestrator.start_control_plane()

    assert started["status"] == "unhealthy"
    assert started["database"] == "unavailable"
    assert "operator_token" not in started
    assert mint.call_count == 0


def test_control_plane_status_reflects_real_health(monkeypatch):
    monkeypatch.setattr("core.db.get_repository", lambda: object())
    monkeypatch.setattr("control_plane.orchestrator._read_pid_file", lambda path: 123)
    monkeypatch.setattr("control_plane.orchestrator._pid_alive", lambda pid: pid == 123)
    monkeypatch.setattr("control_plane.orchestrator._dashboard_healthy", lambda: True)
    monkeypatch.setattr("control_plane.orchestrator._orchestrator_healthy", lambda: True)

    status = orchestrator.control_plane_status()

    assert status == {
        "database": "healthy",
        "dashboard": "running",
        "orchestrator": "running",
        "api": "healthy",
    }


def test_control_plane_status_does_not_report_orchestrator_running_from_marker_pid(monkeypatch):
    monkeypatch.setattr("core.db.get_repository", lambda: object())
    monkeypatch.setattr("control_plane.orchestrator._read_pid_file", lambda path: 456)
    monkeypatch.setattr("control_plane.orchestrator._pid_alive", lambda pid: True)
    monkeypatch.setattr("control_plane.orchestrator._dashboard_healthy", lambda: False)
    monkeypatch.setattr("control_plane.orchestrator._orchestrator_healthy", lambda: False)

    status = orchestrator.control_plane_status()

    assert status["orchestrator"] == "stopped"
    assert status["api"] == "unavailable"


def test_stop_control_plane_terminates_services(monkeypatch):
    monkeypatch.setattr("control_plane.orchestrator._read_pid_file", lambda path: 123)
    with (
        patch("control_plane.orchestrator._terminate_pid") as terminate,
        patch("control_plane.orchestrator._stop_database") as stop_db,
        patch("pathlib.Path.unlink") as unlink,
    ):
        stopped = orchestrator.stop_control_plane()

    assert stopped == {"status": "stopped"}
    assert terminate.call_args_list[0].args == (123,)
    assert stop_db.call_count == 1
    assert unlink.call_count == 1
