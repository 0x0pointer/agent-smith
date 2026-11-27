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

    with patch.object(orchestrator, "_worker_alive", return_value=True):
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
    assert Path(env["SMITH_WORKDIR"]).parts[-2:] == ("runs", "run-context")
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


def test_pid_alive_probes_without_signalling():
    """Liveness must not go through os.kill(pid, 0): on Windows signal 0 is
    CTRL_C_EVENT, so the probe failed for a live dashboard (and could interrupt it)."""
    import os
    with patch("os.kill", side_effect=AssertionError("os.kill must not be used")):
        assert orchestrator._pid_alive(os.getpid()) is True
        assert orchestrator._pid_alive(2**22 + 12345) is False
        assert orchestrator._pid_alive(None) is False
        assert orchestrator._pid_alive(0) is False


def test_worker_alive_works_without_waitpid_nohang(monkeypatch):
    """Windows has no os.WNOHANG; the liveness check must not crash there."""
    import os
    monkeypatch.delattr(os, "WNOHANG", raising=False)
    assert orchestrator._worker_alive(os.getpid()) is True
    assert orchestrator._worker_alive(2**22 + 12345) is False
    assert orchestrator._worker_alive(None) is False


def test_pid_alive_treats_a_zombie_as_gone():
    import psutil
    proc = MagicMock()
    proc.status.return_value = psutil.STATUS_ZOMBIE
    with patch("psutil.Process", return_value=proc):
        assert orchestrator._pid_alive(4321) is False


def test_terminate_pid_uses_psutil_and_reports_missing_process():
    import psutil
    proc = MagicMock()
    with patch("psutil.Process", return_value=proc) as ctor:
        assert orchestrator._terminate_pid(4321) is True
    ctor.assert_called_once_with(4321)
    proc.terminate.assert_called_once_with()

    with patch("psutil.Process", side_effect=psutil.NoSuchProcess(4321)):
        assert orchestrator._terminate_pid(4321) is False
    assert orchestrator._terminate_pid(None) is False


def test_stop_worker_force_kills_a_worker_that_ignores_terminate(monkeypatch):
    """The escalation must not reference signal.SIGKILL, which Windows lacks."""
    import psutil
    proc = MagicMock()
    proc.status.return_value = psutil.STATUS_RUNNING
    monkeypatch.setattr(orchestrator.time, "sleep", lambda s: None)
    clock = iter([0.0, 10.0, 10.0, 10.0])
    monkeypatch.setattr(orchestrator.time, "time", lambda: next(clock, 10.0))
    with patch("psutil.Process", return_value=proc):
        errors = orchestrator._stop_worker("run-abc", 4321)

    assert errors == []
    proc.terminate.assert_called_once_with()
    proc.kill.assert_called_once_with()


def test_stop_worker_reports_a_kill_that_is_refused(monkeypatch):
    import psutil
    proc = MagicMock()
    proc.status.return_value = psutil.STATUS_RUNNING
    proc.kill.side_effect = psutil.AccessDenied(4321)
    monkeypatch.setattr(orchestrator.time, "sleep", lambda s: None)
    clock = iter([0.0, 10.0, 10.0, 10.0])
    monkeypatch.setattr(orchestrator.time, "time", lambda: next(clock, 10.0))
    with patch("psutil.Process", return_value=proc):
        errors = orchestrator._stop_worker("run-abc", 4321)

    assert len(errors) == 1 and errors[0].startswith("worker run-abc:")


@pytest.mark.parametrize("platform", ["linux", "darwin", "win32"])
def test_dashboard_is_spawned_detached_from_the_starting_terminal(monkeypatch, tmp_path, platform):
    monkeypatch.setattr(orchestrator.sys, "platform", platform)
    monkeypatch.setattr(orchestrator._paths, "DASHBOARD_PID_FILE", tmp_path / "dashboard.pid")
    captured = {}

    def _capture(args, **kwargs):
        captured.update(kwargs)
        return MagicMock(pid=4321)

    with patch("subprocess.Popen", side_effect=_capture):
        assert orchestrator._start_dashboard() == 4321

    assert captured["stdin"] is orchestrator.subprocess.DEVNULL
    if platform == "win32":
        assert "start_new_session" not in captured
        assert captured["creationflags"] & 0x00000200  # CREATE_NEW_PROCESS_GROUP
        assert captured["creationflags"] & 0x00000008  # DETACHED_PROCESS
    else:
        assert captured["start_new_session"] is True
        assert "creationflags" not in captured


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


def test_list_runs_exposes_timestamps_for_dashboard_sorting(monkeypatch, tmp_path):
    _configure_db(monkeypatch, tmp_path)

    with patch("subprocess.Popen", return_value=MagicMock(pid=4321)):
        orchestrator.create_run({"target": "https://a.example", "depth": "recon"})

    row = orchestrator.list_runs()[0]
    assert row["created_at"]
    assert row["updated_at"] >= row["created_at"]


def test_worker_gets_a_private_tool_server_carrying_the_run_identity(monkeypatch, tmp_path):
    """Run identity is process-wide, so each worker must NOT share the installed
    MCP server: it gets its own stdio server started with the run's environment."""
    _configure_db(monkeypatch, tmp_path)
    captured = {}

    def _capture(args, **kwargs):
        captured["args"] = list(args)
        return MagicMock(pid=4321)

    with patch("subprocess.Popen", side_effect=_capture):
        created = orchestrator.create_run({"target": "https://a.example", "depth": "recon"})

    args = captured["args"]
    assert "--strict-mcp-config" in args
    config_path = Path(args[args.index("--mcp-config") + 1])
    # Flags must precede the prompt.
    assert args.index("--mcp-config") < args.index("-p")

    server = json.loads(config_path.read_text())["mcpServers"]["pentest-agent"]
    assert server["args"] == ["-m", "mcp_server", "--transport", "stdio"]
    assert server["env"]["SMITH_RUN_ID"] == created["run_id"]
    assert Path(server["env"]["SMITH_WORKDIR"]) == config_path.parent
    assert server["env"]["SMITH_DATABASE_URL"].startswith("sqlite:///")
    # Holds the database URL: owner-only. (POSIX mode bits; Windows has no
    # group/other bits to check — the file inherits the profile's ACL.)
    if orchestrator.sys.platform != "win32":
        assert (config_path.stat().st_mode & 0o077) == 0


def test_two_runs_get_different_tool_server_configs(monkeypatch, tmp_path):
    _configure_db(monkeypatch, tmp_path)
    seen = []

    def _capture(args, **kwargs):
        seen.append(list(args))
        return MagicMock(pid=len(seen))

    with patch("subprocess.Popen", side_effect=_capture):
        orchestrator.create_run({"target": "https://a.example", "depth": "recon"})
        orchestrator.create_run({"target": "https://b.example", "depth": "recon"})

    configs = [json.loads(Path(a[a.index("--mcp-config") + 1]).read_text()) for a in seen]
    ids = [c["mcpServers"]["pentest-agent"]["env"]["SMITH_RUN_ID"] for c in configs]
    dirs = [c["mcpServers"]["pentest-agent"]["env"]["SMITH_WORKDIR"] for c in configs]
    assert len(set(ids)) == 2 and len(set(dirs)) == 2


def test_non_claude_workers_are_left_on_their_own_mcp_config(tmp_path):
    args = ["opencode", "run", "--dangerously-skip-permissions", "prompt"]
    assert orchestrator._with_run_mcp_server(args, "opencode", tmp_path / "mcp.json") == args


def test_run_whose_agent_stopped_is_idle_and_can_be_resumed(monkeypatch, tmp_path):
    """Nothing respawns a stopped worker: the run shows as idle until the operator
    resumes it, and resuming never starts a second agent next to a live one."""
    _configure_db(monkeypatch, tmp_path)
    with patch("subprocess.Popen", return_value=MagicMock(pid=4321)):
        created = orchestrator.create_run({"target": "https://a.example", "depth": "recon"})
    run_id = created["run_id"]

    with patch.object(orchestrator, "_worker_alive", return_value=False):
        assert orchestrator.list_runs()[0]["status"] == "idle"
        assert orchestrator.run_agent_state(run_id)["idle"] is True

        spawned = {}

        def _capture(args, **kwargs):
            spawned["args"] = list(args)
            return MagicMock(pid=5555)

        with patch("subprocess.Popen", side_effect=_capture):
            result = orchestrator.resume_run(run_id)

    assert result == {"run_id": run_id, "resumed": True, "pid": 5555}
    prompt = spawned["args"][spawned["args"].index("-p") + 1]
    assert "session(action='recovery')" in prompt
    assert "--strict-mcp-config" in spawned["args"]          # same private tool server
    # The new worker is what stop/idle now track.
    assert orchestrator._worker_pid(orchestrator._db.get_repository(), run_id) == 5555

    with patch.object(orchestrator, "_worker_alive", return_value=True), patch("subprocess.Popen") as popen:
        assert orchestrator.resume_run(run_id)["resumed"] is False
    popen.assert_not_called()


def test_worker_pid_survives_the_tool_server_rewriting_the_session(monkeypatch, tmp_path):
    """The run's tool server persists its own session document, which has no
    worker pid. Stop and idle detection must keep working after that."""
    _configure_db(monkeypatch, tmp_path)
    with patch("subprocess.Popen", return_value=MagicMock(pid=4321)):
        created = orchestrator.create_run({"target": "https://a.example", "depth": "recon"})
    repo = orchestrator._db.get_repository()
    repo.save_snapshot(created["run_id"], "session", {"status": "running", "target": "https://a.example"})

    assert orchestrator._worker_pid(repo, created["run_id"]) == 4321
    with patch.object(orchestrator, "_stop_worker", return_value=[]) as stop, \
         patch.object(orchestrator, "_stop_run_tooling", return_value=[]):
        orchestrator.stop_run(created["run_id"])
    stop.assert_called_once_with(created["run_id"], 4321)


def test_ended_run_is_not_idle_and_cannot_be_resumed(monkeypatch, tmp_path):
    _configure_db(monkeypatch, tmp_path)
    with patch("subprocess.Popen", return_value=MagicMock(pid=4321)):
        created = orchestrator.create_run({"target": "https://a.example", "depth": "recon"})
    with patch.object(orchestrator, "_stop_worker", return_value=[]), \
         patch.object(orchestrator, "_stop_run_tooling", return_value=[]):
        orchestrator.stop_run(created["run_id"])

    with patch.object(orchestrator, "_worker_alive", return_value=False), patch("subprocess.Popen") as popen:
        assert orchestrator.list_runs()[0]["status"] == "stopped"
        assert orchestrator.resume_run(created["run_id"])["resumed"] is False
    popen.assert_not_called()


def test_source_is_validated_against_the_registry_and_passed_to_the_run(monkeypatch, tmp_path):
    _configure_db(monkeypatch, tmp_path)
    registry = tmp_path / "sources.yaml"
    registry.write_text("sources:\n  team-kb:\n    url: http://127.0.0.1:8900\n")
    monkeypatch.setenv("SOURCE_REGISTRY", str(registry))
    captured = {}

    def _capture(args, **kwargs):
        captured["workdir"] = Path(kwargs["env"]["SMITH_WORKDIR"])
        return MagicMock(pid=4321)

    with patch("subprocess.Popen", side_effect=_capture):
        orchestrator.create_run({"target": "https://a.example", "depth": "recon", "source": "team-kb"})
    options = json.loads((captured["workdir"] / "control_plane_start.json").read_text())
    assert options["source"] == "team-kb"

    # No source chosen: the key is simply absent.
    with patch("subprocess.Popen", side_effect=_capture):
        orchestrator.create_run({"target": "https://b.example", "depth": "recon"})
    assert "source" not in json.loads((captured["workdir"] / "control_plane_start.json").read_text())

    # A typo fails the request instead of silently starting without the Source.
    with patch("subprocess.Popen") as popen, pytest.raises(ValueError, match="unknown source"):
        orchestrator.create_run({"target": "https://c.example", "depth": "recon", "source": "nope"})
    popen.assert_not_called()


def test_run_workdir_is_always_inside_the_runs_root(monkeypatch, tmp_path):
    """A run id reaches the orchestrator from URLs; it must never become a path
    outside <runtime>/runs, whatever it contains or whatever was recorded."""
    _configure_db(monkeypatch, tmp_path)
    root = Path(orchestrator.os.path.realpath(Path(orchestrator._paths.RUNTIME_ROOT) / "runs"))

    for hostile in ("../../etc", "..", "run-1/../../x", "/abs/path", "a\x00b", ""):
        path = orchestrator._contained_workdir(hostile)
        assert path.parent == root, hostile

    # A recorded directory outside the root is ignored in favour of the derived one.
    assert orchestrator._contained_workdir("run-abc", "/etc").parent == root
    inside = root / "run-abc"
    assert orchestrator._contained_workdir("run-abc", str(inside)) == inside


def test_resume_uses_the_stored_run_and_rejects_unknown_ids(monkeypatch, tmp_path):
    _configure_db(monkeypatch, tmp_path)
    with patch("subprocess.Popen") as popen:
        for hostile in ("../../etc/passwd", "run-does-not-exist"):
            with pytest.raises(KeyError):
                orchestrator.resume_run(hostile)
    popen.assert_not_called()


def test_validation_failures_map_to_fixed_public_messages():
    public = orchestrator.public_validation_error
    assert public(ValueError("target required")) == "target required"
    assert public(ValueError("unknown source '<script>alert(1)</script>'")) == "unknown source"
    assert public(ValueError("scope exceeds 128 entries")) == "too many scope entries"
    assert public(ValueError("/secret/path/leaked in a traceback")) == "invalid request"


def test_stop_keeps_the_recorded_workdir(monkeypatch, tmp_path):
    """The tool server rewrites the session snapshot without a workdir; stopping
    must not blank the run's recorded directory."""
    _configure_db(monkeypatch, tmp_path)
    with patch("subprocess.Popen", return_value=MagicMock(pid=4321)):
        created = orchestrator.create_run({"target": "https://a.example", "depth": "recon"})
    repo = orchestrator._db.get_repository()
    before = repo.get_run(created["run_id"])["workdir"]
    repo.save_snapshot(created["run_id"], "session", {"status": "running", "target": "https://a.example"})

    with patch.object(orchestrator, "_stop_worker", return_value=[]), \
         patch.object(orchestrator, "_stop_run_tooling", return_value=[]):
        orchestrator.stop_run(created["run_id"])

    assert before and repo.get_run(created["run_id"])["workdir"] == before
