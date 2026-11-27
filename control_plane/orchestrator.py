from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path
from urllib import error as urllib_error
from urllib import request as urllib_request

from core import dashboard_auth
from core import db as _db
from core import paths as _paths
from core import run_context as _run_context
from tools.docker_cli import docker_executable

_DEPTHS = {"recon", "standard", "thorough", "danger"}
_TARGET_MAX_LENGTH = 2048
_LIST_MAX_ITEMS = 128
_LIST_ENTRY_MAX_LENGTH = 512
_DEFAULT_DATABASE_URL = "postgresql+psycopg://smith:smith@127.0.0.1:55432/agent_smith"
_CONTROL_PLANE_PORT = 7777
_COMPOSE_FILE = _paths.REPO_ROOT / "docker-compose.yml"
_RUN_ID_ATTEMPTS = 5
_KNOWN_AGENT_CLIENTS = {"claude", "opencode", "codex"}


class RunIdCollisionError(RuntimeError):
    pass


def _dashboard_base_url() -> str:
    return f"http://127.0.0.1:{_CONTROL_PLANE_PORT}"


def _new_run_id() -> str:
    return f"run-{uuid.uuid4().hex[:8]}"


def _run_container_name(run_id: str, tool: str) -> str:
    return f"smith-{_run_context.sanitize_run_id(tool)}-{_run_context.sanitize_run_id(run_id)}"


def _run_network_name(run_id: str) -> str:
    return f"smith-run-{_run_context.sanitize_run_id(run_id)}"


def _validate_string_list(name: str, value: object) -> list[str]:
    if value in (None, ""):
        return []
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a list")
    if len(value) > _LIST_MAX_ITEMS:
        raise ValueError(f"{name} exceeds {_LIST_MAX_ITEMS} entries")
    cleaned: list[str] = []
    for entry in value:
        text = str(entry or "").strip()
        if not text:
            continue
        if len(text) > _LIST_ENTRY_MAX_LENGTH:
            raise ValueError(f"{name} entry too long")
        cleaned.append(text)
    return cleaned


def _validate(payload: object) -> tuple[str, str, list[str], list[str]]:
    if not isinstance(payload, dict):
        raise ValueError("request body must be an object")
    target = str(payload.get("target") or "").strip()
    depth = str(payload.get("depth") or "standard").strip() or "standard"
    if not target:
        raise ValueError("target required")
    if len(target) > _TARGET_MAX_LENGTH:
        raise ValueError("target too long")
    if depth not in _DEPTHS:
        raise ValueError("invalid depth")
    scope = _validate_string_list("scope", payload.get("scope"))
    out_of_scope = _validate_string_list("out_of_scope", payload.get("out_of_scope"))
    return target, depth, scope, out_of_scope


def _workdir_for(run_id: str) -> Path:
    path = _workdir_path_for(run_id)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _workdir_path_for(run_id: str) -> Path:
    return Path(_paths.RUNTIME_ROOT) / "runs" / run_id


def _initial_run_prompt(target: str, depth: str, scope: list[str], out_of_scope: list[str]) -> str:
    options = {
        "target": target,
        "depth": depth,
        "scope": scope,
        "out_of_scope": out_of_scope,
    }
    return (
        "Start a new agent-smith pentest run from the dashboard control plane. "
        f"First call session(action='start', options={json.dumps(options, sort_keys=True)}). "
        "Then call session(action='status') and continue autonomously with the next recommended "
        "tool call until the scan is complete or genuinely blocked."
    )


def _agent_client() -> str:
    client = os.environ.get("SMITH_WORKER_CLIENT", "").strip().lower() or "claude"
    return client if client in _KNOWN_AGENT_CLIENTS else "claude"


def _agent_spawn_args(client: str, prompt: str) -> list[str]:
    from core.api_server.smith.spawn import _build_spawn_args

    return _build_spawn_args(client, client, None, prompt)


def _spawn_worker(
    run_id: str,
    workdir: Path,
    target: str,
    depth: str,
    scope: list[str],
    out_of_scope: list[str],
) -> int:
    env = os.environ.copy()
    env["SMITH_RUN_ID"] = run_id
    env["SMITH_WORKDIR"] = str(workdir)
    env["SMITH_RUN_TARGET"] = target
    env["SMITH_RUN_DEPTH"] = depth
    env["SMITH_RUN_SCOPE"] = json.dumps(scope)
    env["SMITH_RUN_OUT_OF_SCOPE"] = json.dumps(out_of_scope)
    env.setdefault("SMITH_SESSION_ORIGIN", "operator")
    logs_dir = workdir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    prompt = _initial_run_prompt(target, depth, scope, out_of_scope)
    args = _agent_spawn_args(_agent_client(), prompt)
    spawn_kwargs = {
        "cwd": str(_paths.REPO_ROOT),
        "env": env,
        "start_new_session": sys.platform != "win32",
    }
    if sys.platform == "win32":
        spawn_kwargs.pop("start_new_session", None)
        spawn_kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
    with (logs_dir / "worker.log").open("a", encoding="utf-8") as log_fh:
        proc = subprocess.Popen(args, stdout=log_fh, stderr=log_fh, **spawn_kwargs)
    return int(getattr(proc, "pid", 0) or 0)


def _read_json(url: str, timeout: float = 2.0) -> tuple[int | None, object]:
    try:
        with urllib_request.urlopen(url, timeout=timeout) as response:
            import json

            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib_error.HTTPError as exc:
        return exc.code, None
    except Exception:
        return None, None


def _ensure_database_url() -> str:
    return os.environ.get("SMITH_DATABASE_URL", "").strip() or _DEFAULT_DATABASE_URL


def _write_pid_file(path: Path, pid: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(pid), encoding="utf-8")


def _read_pid_file(path: Path) -> int | None:
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except Exception:
        return None


def _pid_alive(pid: int | None) -> bool:
    if not pid or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _terminate_pid(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return False
    return True


def _start_dashboard() -> int:
    existing = _read_pid_file(_paths.DASHBOARD_PID_FILE)
    if _pid_alive(existing):
        return existing or 0
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "core.api_server:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(_CONTROL_PLANE_PORT),
            "--no-access-log",
            "--log-level",
            "critical",
        ],
        cwd=str(_paths.REPO_ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    pid = int(getattr(proc, "pid", 0) or 0)
    _write_pid_file(_paths.DASHBOARD_PID_FILE, pid)
    return pid


def _compose_cmd(*args: str) -> list[str]:
    return [docker_executable(), "compose", "-f", str(_COMPOSE_FILE), *args]


def _start_database() -> dict:
    url = _ensure_database_url()
    os.environ.setdefault("SMITH_DATABASE_URL", url)
    if url.startswith("sqlite:///"):
        return {"database": "healthy", "database_url": url}
    result = subprocess.run(
        _compose_cmd("up", "-d", "postgres"),
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "failed to start postgres")
    return {"database": "healthy", "database_url": url}


def _stop_database() -> None:
    url = os.environ.get("SMITH_DATABASE_URL", "").strip()
    if url.startswith("sqlite:///"):
        return
    subprocess.run(
        _compose_cmd("stop", "postgres"),
        capture_output=True,
        text=True,
        check=False,
    )


def _dashboard_healthy() -> bool:
    status, _ = _read_json(f"{_dashboard_base_url()}/healthz")
    return status == 200


def _wait_for_dashboard(timeout_s: float = 5.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if _dashboard_healthy():
            return True
        time.sleep(0.1)
    return _dashboard_healthy()


def _wait_for_database(timeout_s: float = 15.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if _db.get_repository() is not None:
            return True
        time.sleep(0.2)
    return _db.get_repository() is not None


def _orchestrator_healthy() -> bool:
    status, _ = _read_json(f"{_dashboard_base_url()}/api/runs")
    return status in {200, 401, 403}


def _wait_for_orchestrator(timeout_s: float = 5.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if _orchestrator_healthy():
            return True
        time.sleep(0.1)
    return _orchestrator_healthy()


def create_run(payload: object) -> dict:
    target, depth, scope, out_of_scope = _validate(payload)
    repo = _db.get_repository()
    if repo is None:
        raise RuntimeError("database unavailable")

    run_id = ""
    workdir = Path()
    session_doc: dict | None = None
    for _ in range(_RUN_ID_ATTEMPTS):
        candidate = _new_run_id()
        candidate_workdir = _workdir_path_for(candidate)
        candidate_doc = {
            "run_id": candidate,
            "target": target,
            "depth": depth,
            "scope": scope or [target],
            "out_of_scope": out_of_scope,
            "status": "starting",
            "workdir": str(candidate_workdir),
        }
        if repo.create_run(candidate, candidate_doc, str(candidate_workdir)):
            run_id = candidate
            workdir = _workdir_for(run_id)
            session_doc = candidate_doc
            break
    if session_doc is None:
        raise RunIdCollisionError("could not allocate unique run id")

    token = dashboard_auth.mint_run_token(run_id)
    session_doc["status"] = "running"
    repo.save_snapshot(run_id, "session", session_doc)
    try:
        worker_pid = _spawn_worker(
            run_id,
            workdir,
            target,
            depth,
            scope or [target],
            out_of_scope,
        )
        session_doc["worker_pid"] = worker_pid
        repo.upsert_run(run_id, session_doc, str(workdir))
        repo.save_snapshot(run_id, "session", session_doc)
    except Exception:
        session_doc["status"] = "failed"
        repo.upsert_run(run_id, session_doc, str(workdir))
        repo.save_snapshot(run_id, "session", session_doc)
        _stop_run_tooling(run_id)
        shutil.rmtree(workdir, ignore_errors=True)
        raise
    return {
        "run_id": run_id,
        "status": "running",
        "dashboard_url": f"{_dashboard_base_url()}/#k={token}",
        "token": token,
    }


def list_runs() -> list[dict]:
    rows = _db.list_runs()
    return [
        {
            "run_id": row.get("run_id"),
            "target": row.get("target"),
            "status": row.get("status"),
            "depth": row.get("depth"),
            "workdir": row.get("workdir"),
        }
        for row in rows
    ]


def mint_existing_run_token(run_id: str) -> dict:
    repo = _db.get_repository()
    if repo is None:
        raise RuntimeError("database unavailable")
    if not repo.get_run(run_id):
        raise KeyError(run_id)
    token = dashboard_auth.mint_run_token(run_id)
    return {
        "run_id": run_id,
        "dashboard_url": f"{_dashboard_base_url()}/#k={token}",
        "token": token,
    }


def _stop_worker(run_id: str, worker_pid: int | None) -> list[str]:
    errors: list[str] = []
    if not worker_pid:
        return errors
    if not _terminate_pid(worker_pid):
        return errors
    deadline = time.time() + 5
    while _pid_alive(worker_pid) and time.time() < deadline:
        time.sleep(0.1)
    if _pid_alive(worker_pid):
        try:
            os.kill(worker_pid, signal.SIGKILL)
        except OSError as exc:
            errors.append(f"worker {run_id}: {exc}")
    return errors


def _stop_run_tooling(run_id: str) -> list[str]:
    errors: list[str] = []
    containers = [
        _run_container_name(run_id, "kali"),
        _run_container_name(run_id, "metasploit"),
        _run_container_name(run_id, "mobsf"),
    ]
    try:
        stop_result = subprocess.run(
            [docker_executable(), "stop", "-t", "3", *containers],
            capture_output=True,
            text=True,
            check=False,
        )
        stop_stderr = (stop_result.stderr or "").lower()
        if stop_result.returncode != 0 and "no such container" not in stop_stderr:
            errors.append(stop_result.stderr.strip() or "failed to stop run containers")
    except OSError as exc:
        errors.append(f"failed to stop run containers: {exc}")
    try:
        network_result = subprocess.run(
            [docker_executable(), "network", "rm", _run_network_name(run_id)],
            capture_output=True,
            text=True,
            check=False,
        )
        network_stderr = (network_result.stderr or "").lower()
        if network_result.returncode != 0 and "no such network" not in network_stderr:
            errors.append(network_result.stderr.strip() or "failed to remove run network")
    except OSError as exc:
        errors.append(f"failed to remove run network: {exc}")
    return errors


def stop_run(run_id: str) -> dict:
    repo = _db.get_repository()
    if repo is None:
        raise RuntimeError("database unavailable")
    session_doc = repo.load_snapshot(run_id, "session") or {"run_id": run_id}
    cleanup_errors = []
    cleanup_errors.extend(_stop_worker(run_id, session_doc.get("worker_pid")))
    cleanup_errors.extend(_stop_run_tooling(run_id))
    session_doc["status"] = "stopped"
    session_doc["cleanup_errors"] = cleanup_errors
    repo.upsert_run(run_id, session_doc, session_doc.get("workdir", ""))
    repo.save_snapshot(run_id, "session", session_doc)
    result = {"run_id": run_id, "status": "stopped"}
    if cleanup_errors:
        result["cleanup_errors"] = cleanup_errors
    return result


def start_control_plane() -> dict:
    status = _start_database()
    if not _wait_for_database():
        return {
            "status": "unhealthy",
            "database": "unavailable",
            "dashboard": "stopped",
            "orchestrator": "stopped",
            "dashboard_url": _dashboard_base_url(),
        }
    try:
        operator_token = dashboard_auth.mint_operator_token()
    except RuntimeError:
        return {
            "status": "unhealthy",
            "database": "unavailable",
            "dashboard": "stopped",
            "orchestrator": "stopped",
            "dashboard_url": _dashboard_base_url(),
        }
    dashboard_pid = _start_dashboard()
    dashboard_ok = bool(dashboard_pid) and _wait_for_dashboard()
    orchestrator_ok = dashboard_ok and _wait_for_orchestrator()
    return {
        "status": "started" if dashboard_ok and orchestrator_ok else "unhealthy",
        "database": status["database"],
        "dashboard": "running" if dashboard_ok else "failed",
        "orchestrator": "running" if orchestrator_ok else "failed",
        "dashboard_url": _dashboard_base_url(),
        "operator_token": operator_token,
    }


def stop_control_plane() -> dict:
    dashboard_pid = _read_pid_file(_paths.DASHBOARD_PID_FILE)
    _terminate_pid(dashboard_pid)
    _paths.DASHBOARD_PID_FILE.unlink(missing_ok=True)
    _stop_database()
    return {"status": "stopped"}


def control_plane_status() -> dict:
    repo = _db.get_repository()
    dashboard_pid = _read_pid_file(_paths.DASHBOARD_PID_FILE)
    dashboard_ok = _pid_alive(dashboard_pid) and _dashboard_healthy()
    orchestrator_ok = dashboard_ok and _orchestrator_healthy()
    return {
        "database": "healthy" if repo else "unavailable",
        "dashboard": "running" if dashboard_ok else "stopped",
        "orchestrator": "running" if orchestrator_ok else "stopped",
        "api": "healthy" if dashboard_ok and orchestrator_ok else "unavailable",
    }
