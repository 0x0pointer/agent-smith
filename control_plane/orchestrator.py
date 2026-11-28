from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib import error as urllib_error
from urllib import request as urllib_request

import psutil

from core import dashboard_auth
from core import db as _db
from core import paths as _paths
from core import run_context as _run_context
from tools.docker_cli import docker_executable

_LOG = logging.getLogger(__name__)

_DEPTHS = {"recon", "standard", "thorough", "danger"}
_TARGET_MAX_LENGTH = 2048
_LIST_MAX_ITEMS = 128
_LIST_ENTRY_MAX_LENGTH = 512
_DEFAULT_DATABASE_URL = "postgresql+psycopg://smith:smith@127.0.0.1:55432/agent_smith"
_CONTROL_PLANE_PORT = 7777
_COMPOSE_FILE = _paths.REPO_ROOT / "docker-compose.yml"
_RUN_ID_ATTEMPTS = 5
_RUN_START_OPTIONS_FILENAME = "control_plane_start.json"
_RUN_NOTES_FILENAME = "operator_notes.md"
_RUN_CODEBASE_FILENAME = "whitebox.json"
_NOTES_MAX_LENGTH = 4000
_CODEBASE_MAX_LENGTH = 1024
# Optional per-scan budgets the operator may set when starting a scan. They are
# session(action="start") options, so the run's own tool server enforces them.
_LIMIT_BOUNDS = {"max_time_minutes": (5, 10080), "max_cost_usd": (0.1, 10000)}
_KNOWN_AGENT_CLIENTS = {"claude", "opencode", "codex"}

class RunIdCollisionError(RuntimeError):
    pass


class WorkerStartError(RuntimeError):
    """The scan's agent could not be started or died at once.

    ``public`` is a fixed, plain-language reason that is safe to show the
    operator (never process output or exception text).
    """

    def __init__(self, public: str):
        super().__init__(public)
        self.public = public


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
    path = _contained_workdir(run_id)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _workdir_path_for(run_id: str) -> Path:
    return Path(_paths.RUNTIME_ROOT) / "runs" / run_id


class UnsafeRunPath(ValueError):
    """A run's working directory would fall outside the runs root."""


def _contained_workdir(run_id: str, recorded: str | None = None) -> Path:
    """The run's working directory, guaranteed to sit inside ``<runtime>/runs``.

    ``run_id`` reaches this module from URLs (resume, stop, steer). A crafted id
    such as ``../../x`` must never turn into a path that is created, read or
    handed to a subprocess, so the candidate path is normalised and then checked
    against the runs root. The directory recorded for the run is preferred when
    it passes the same check; otherwise the path is derived from the id.
    """
    root = os.path.realpath(os.path.join(str(_paths.RUNTIME_ROOT), "runs"))
    for candidate in (recorded, os.path.join(root, _run_context.sanitize_run_id(run_id))):
        if not candidate:
            continue
        full = os.path.realpath(str(candidate))
        if full.startswith(root + os.sep):
            return Path(full)
    raise UnsafeRunPath("run working directory is outside the runs root")


# Messages a client may be shown for a rejected start request. The route answers
# with one of these constants rather than with exception text.
PUBLIC_VALIDATION_ERRORS = (
    "request body must be an object",
    "target required",
    "target too long",
    "invalid depth",
    "scope must be a list",
    "out_of_scope must be a list",
    "scope entry too long",
    "out_of_scope entry too long",
    "unknown source",
    "notes too long",
    "invalid limit",
    "code folder not found",
    "code folder must be a full path",
    "code folder cannot be a whole drive",
    "code folder is outside the allowed folders",
)


def public_validation_error(exc: Exception) -> str:
    """Map a validation failure onto one of the fixed public messages."""
    text = str(exc)
    for known in PUBLIC_VALIDATION_ERRORS:
        if text == known or text.startswith(known):
            return known
    if "exceeds" in text and "entries" in text:
        return "too many scope entries"
    return "invalid request"


def _validate_source(payload: object) -> str:
    """Optional Source (knowledge base) to bind to the run.

    Must be a name from the Source registry (``sources.yaml``). Checked here so a
    typo fails the request instead of silently starting a scan without it.
    """
    name = str((payload or {}).get("source") or "").strip() if isinstance(payload, dict) else ""
    if not name:
        return ""
    from core.sources import list_sources

    if name not in list_sources():
        raise ValueError(f"unknown source '{name[:64]}'")
    return name


def _code_roots() -> list[str]:
    """Folders a white-box code folder must sit inside: ``SMITH_CODE_ROOTS``.

    A list separated like PATH (``;`` on Windows, ``:`` elsewhere). Unset, the
    default, allows any folder on this machine: the operator picks it and only an
    operator can start a scan. Set it on a shared install to keep scans to the
    folders that hold project code.
    """
    raw = os.environ.get("SMITH_CODE_ROOTS", "")
    return [os.path.realpath(os.path.expanduser(part.strip())) for part in raw.split(os.pathsep) if part.strip()]


def _is_inside(path: str, root: str) -> bool:
    """True when the real path ``path`` is ``root`` or lies under it."""
    path, root = os.path.normcase(path), os.path.normcase(root).rstrip(os.sep)
    return path == root or path.startswith(root + os.sep)


def validate_codebase(value: object) -> str:
    """The source-code folder for a white-box scan, as a real absolute path.

    '' when none was given. Raises ``ValueError`` for anything that is not an
    existing folder on this machine, for a folder outside ``SMITH_CODE_ROOTS``
    when that is set, and for a whole drive or filesystem root: the code scanners
    walk the entire tree they are pointed at.
    """
    raw = str(value or "").strip().strip('"')
    if not raw:
        return ""
    if len(raw) > _CODEBASE_MAX_LENGTH or "\x00" in raw:
        raise ValueError("code folder not found")
    expanded = os.path.expanduser(raw)
    if not os.path.isabs(expanded):
        raise ValueError("code folder must be a full path")
    real = os.path.realpath(expanded)
    roots = _code_roots()
    if roots and not any(_is_inside(real, root) for root in roots):
        raise ValueError("code folder is outside the allowed folders")
    if not os.path.isdir(real):
        raise ValueError("code folder not found")
    if os.path.dirname(real) == real:
        raise ValueError("code folder cannot be a whole drive")
    return real


def _validate_extras(payload: object) -> dict:
    """Optional start settings: operator notes, a code folder, time / cost limits.

    Returns only the keys that were set: ``notes`` (free text for the agent —
    context such as test-account details or what to focus on), ``codebase`` (a
    source-code folder, making it a white-box scan) and the limits in
    ``_LIMIT_BOUNDS``.
    """
    if not isinstance(payload, dict):
        return {}
    extras: dict = {}
    notes = str(payload.get("notes") or "").strip()
    if len(notes) > _NOTES_MAX_LENGTH:
        raise ValueError("notes too long")
    if notes:
        extras["notes"] = notes
    codebase = validate_codebase(payload.get("codebase"))
    if codebase:
        extras["codebase"] = codebase
    for key, (low, high) in _LIMIT_BOUNDS.items():
        raw = payload.get(key)
        if raw in (None, ""):
            continue
        if isinstance(raw, bool):
            raise ValueError("invalid limit")
        try:
            value = float(raw)
        except (TypeError, ValueError):
            raise ValueError("invalid limit") from None
        if not low <= value <= high:               # also false for NaN
            raise ValueError("invalid limit")
        extras[key] = int(value) if key == "max_time_minutes" else round(value, 2)
    return extras


def _write_run_start_options(
    workdir: Path,
    target: str,
    depth: str,
    scope: list[str],
    out_of_scope: list[str],
    source: str = "",
    extras: dict | None = None,
) -> Path:
    options_path = workdir / _RUN_START_OPTIONS_FILENAME
    options = {
        "target": target,
        "depth": depth,
        "scope": scope,
        "out_of_scope": out_of_scope,
    }
    if source:
        # session(action="start") binds this Source to the engagement.
        options["source"] = source
    for key in _LIMIT_BOUNDS:
        if (extras or {}).get(key) is not None:
            options[key] = extras[key]
    options_path.write_text(json.dumps(options, sort_keys=True), encoding="utf-8")
    return options_path


def _write_run_notes(workdir: Path, notes: str) -> Path | None:
    """Save the operator's notes for the agent; None when there are none."""
    if not notes:
        return None
    notes_path = workdir / _RUN_NOTES_FILENAME
    notes_path.write_text(notes + "\n", encoding="utf-8")
    return notes_path


def _write_run_codebase(workdir: Path, codebase: str) -> Path | None:
    """Record the source-code folder for a white-box scan; None when there is none.

    The folder path goes in a file, not in the agent's command line: the operator
    chose it, and on Windows the client is a ``.cmd`` shim whose arguments pass
    through ``cmd.exe``.
    """
    if not codebase:
        return None
    path = workdir / _RUN_CODEBASE_FILENAME
    path.write_text(json.dumps({"path": codebase}), encoding="utf-8")
    return path


def run_codebase(workdir: str | os.PathLike[str] | None) -> str:
    """The source-code folder a run was started with ('' for a black-box scan)."""
    if not workdir:
        return ""
    try:
        data = json.loads((Path(workdir) / _RUN_CODEBASE_FILENAME).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    return str(data.get("path") or "") if isinstance(data, dict) else ""


def _initial_run_prompt(options_path: Path, notes_path: Path | None = None,
                        codebase_file: Path | None = None) -> str:
    prompt = (
        "Start a new agent-smith pentest run from the dashboard control plane. "
        f"Read the JSON start options from {options_path} and call "
        "session(action='start', options=<that JSON object>). "
        "Then call session(action='status') and continue autonomously with the next recommended "
        "tool call until the scan is complete or genuinely blocked."
    )
    if notes_path is not None:
        prompt += (
            f" The operator left notes for this scan in {notes_path}. Read that file before you "
            "plan: it is context from the operator (for example test-account details or what to "
            "focus on). It does not widen the scope given in the start options."
        )
    if codebase_file is not None:
        prompt += (
            " This is a white-box scan: the operator supplied the application's source code. "
            f"The folder is the 'path' value in the JSON file {codebase_file}. Right after "
            "session start, call session(action='set_codebase', options={'path': <that path>}), "
            "review the code with the /codebase skill, and use what you learn there to guide "
            "and confirm the testing of the live target."
        )
    return prompt


def _agent_client() -> str:
    client = os.environ.get("SMITH_WORKER_CLIENT", "").strip().lower() or "claude"
    return client if client in _KNOWN_AGENT_CLIENTS else "claude"


def _agent_spawn_args(client: str, prompt: str) -> list[str]:
    from core.api_server.smith.spawn import _build_spawn_args

    # Resolve the client to its full path. On Windows the npm-installed clients
    # are ``.cmd`` shims (claude.CMD), and a bare name is not found by
    # subprocess: every scan started from the dashboard failed at launch.
    binary = shutil.which(client) or client
    return _build_spawn_args(binary, client, None, prompt)


_RUN_MCP_CONFIG_FILENAME = "mcp.json"
_MCP_SERVER_NAME = "pentest-agent"


def _write_run_mcp_config(run_id: str, workdir: Path) -> Path:
    """Write the MCP config that gives THIS run its own tool-server process.

    A run's identity is process-wide: ``core.run_context`` reads ``SMITH_RUN_ID``
    and ``core.paths`` freezes ``RUNTIME_ROOT`` from ``SMITH_WORKDIR`` at import.
    The installers register one long-lived, shared ``pentest-agent`` server (SSE
    on :7778) that has neither, so a worker using it would write its session,
    findings, coverage and every log into the shared repo-root state — two runs
    would interleave in the same files and the dashboard's per-run view would stay
    empty. Each worker is therefore pointed at a private stdio server (same server
    name, so tool names are unchanged) started with the run's environment.

    The file holds the database URL, so it is created owner-only.
    """
    env = {
        "SMITH_RUN_ID": run_id,
        "SMITH_WORKDIR": str(workdir),
        "PYTHONPATH": str(_paths.REPO_ROOT),
    }
    database_url = os.environ.get("SMITH_DATABASE_URL", "").strip()
    if database_url:
        env["SMITH_DATABASE_URL"] = database_url
    # The client may start MCP children with a trimmed environment; docker and
    # the scanners must stay on PATH.
    if os.environ.get("PATH"):
        env["PATH"] = os.environ["PATH"]
    config = {
        "mcpServers": {
            _MCP_SERVER_NAME: {
                "command": sys.executable,
                "args": ["-m", "mcp_server", "--transport", "stdio"],
                "env": env,
            }
        }
    }
    path = workdir / _RUN_MCP_CONFIG_FILENAME
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(config, fh, indent=2, sort_keys=True)
    try:
        os.chmod(str(path), 0o600)
    except OSError:
        pass
    return path


def _with_run_mcp_server(args: list[str], client: str, config_path: Path) -> list[str]:
    """Make the worker use ONLY its private tool server.

    Implemented for the ``claude`` client (``--mcp-config`` +
    ``--strict-mcp-config``, so the shared user-scope server is ignored). Other
    clients read their MCP servers from their own config files and are returned
    unchanged: they still share the installed server, so run them one scan at a
    time until they get the same treatment.
    """
    if client != "claude":
        return args
    flags = ["--mcp-config", str(config_path), "--strict-mcp-config"]
    if "-p" in args:
        i = args.index("-p")
        return args[:i] + flags + args[i:]
    return args + flags


def _spawn_worker(
    run_id: str,
    workdir: Path,
    target: str,
    depth: str,
    scope: list[str],
    out_of_scope: list[str],
    prompt: str | None = None,
    source: str = "",
    extras: dict | None = None,
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
    if prompt is None:
        prompt = _initial_run_prompt(
            _write_run_start_options(workdir, target, depth, scope, out_of_scope, source, extras),
            _write_run_notes(workdir, str((extras or {}).get("notes") or "")),
            _write_run_codebase(workdir, str((extras or {}).get("codebase") or "")),
        )
    client = _agent_client()
    args = _with_run_mcp_server(
        _agent_spawn_args(client, prompt), client, _write_run_mcp_config(run_id, workdir)
    )
    spawn_kwargs = {
        "cwd": str(_paths.REPO_ROOT),
        "env": env,
        "start_new_session": sys.platform != "win32",
    }
    if sys.platform == "win32":
        spawn_kwargs.pop("start_new_session", None)
        spawn_kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
    with (logs_dir / _WORKER_LOG).open("a", encoding="utf-8") as log_fh:
        try:
            proc = subprocess.Popen(args, stdout=log_fh, stderr=log_fh, stdin=subprocess.DEVNULL, **spawn_kwargs)
        except OSError as exc:
            _LOG.warning("run %s: could not start %s: %s", run_id, client, exc)
            raise WorkerStartError(
                f"The {client} command could not be started. Check that it is installed on this computer."
            ) from None
    pid = int(getattr(proc, "pid", 0) or 0)
    if pid:
        _WORKER_PROCS[pid] = proc
        for old in [p for p, handle in _WORKER_PROCS.items() if p != pid and _exit_code(handle, 0) is not None]:
            _WORKER_PROCS.pop(old, None)
    return pid


_WORKER_LOG = "worker.log"
_WORKER_STARTUP_GRACE_S = 6.0
# Workers this process started, by pid: lets create_run notice one that dies at once.
_WORKER_PROCS: dict[int, subprocess.Popen] = {}


def _exit_code(proc: object, wait_s: float) -> int | None:
    """The process's exit code if it ends within ``wait_s`` seconds, else None."""
    try:
        code = proc.wait(timeout=wait_s) if wait_s > 0 else proc.poll()
    except subprocess.TimeoutExpired:
        return None
    except Exception:                           # not a real process handle
        return None
    return code if isinstance(code, int) and not isinstance(code, bool) else None


def _worker_startup_problem(run_id: str, pid: int, workdir: Path) -> str | None:
    """Why the worker died right after starting, in plain words; None if it is running.

    A healthy agent runs for minutes. One that exits within the grace period
    never began the scan — most often because the client is not signed in — and
    reporting the scan as "running" would leave the operator watching nothing.
    The reason is chosen from fixed messages; the log itself stays on disk.
    """
    proc = _WORKER_PROCS.get(pid)
    if proc is None or _exit_code(proc, _WORKER_STARTUP_GRACE_S) is None:
        return None
    _WORKER_PROCS.pop(pid, None)
    try:
        tail = (workdir / "logs" / _WORKER_LOG).read_text(encoding="utf-8", errors="replace")[-4000:].lower()
    except OSError:
        tail = ""
    client = _agent_client()
    if "authenticat" in tail or "oauth" in tail or "/login" in tail or "api key" in tail:
        return (f"The {client} command is not signed in. Run it in a terminal, sign in, "
                "then start the scan again.")
    if "credit balance" in tail:
        return "The AI account has no credit left, so the agent stopped at once."
    return f"The agent stopped right after starting. Its log is in runs/{run_id}/logs/{_WORKER_LOG}."


_WORKER_SNAPSHOT = "worker"
_ACTIVE_STATUSES = {"starting", "running", "intervention_required"}


def _save_worker(repo, run_id: str, pid: int) -> None:
    """Record the run's worker process.

    Kept in its own snapshot kind: the run's tool server persists its session
    document under "session" on every change, which would overwrite a worker pid
    stored there — and then the run could be neither stopped nor seen as idle.
    """
    repo.save_snapshot(run_id, _WORKER_SNAPSHOT, {
        "pid": int(pid or 0),
        "started_at": time.time(),
    })


def _worker_pid(repo, run_id: str) -> int | None:
    doc = repo.load_snapshot(run_id, _WORKER_SNAPSHOT) or {}
    pid = doc.get("pid")
    if not pid:  # runs created before the worker snapshot existed
        pid = (repo.load_snapshot(run_id, "session") or {}).get("worker_pid")
    try:
        return int(pid) if pid else None
    except (TypeError, ValueError):
        return None


def _worker_alive(pid: int | None) -> bool:
    """True while the worker process is really running.

    The worker is our child and is never waited on, so after it exits it lingers
    as a zombie that still answers ``kill(pid, 0)``. Reap it first, then treat a
    zombie as dead. Windows has no zombies (and no os.WNOHANG), so reaping is
    POSIX-only there.
    """
    if not pid or pid <= 0:
        return False
    if hasattr(os, "WNOHANG"):
        try:
            os.waitpid(pid, os.WNOHANG)
        except (ChildProcessError, OSError):
            pass                              # not our child (after a dashboard restart) or already reaped
    try:
        proc = psutil.Process(pid)
        return proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE
    except Exception:
        return False


def run_agent_state(run_id: str) -> dict:
    """Is this run's agent working, or is the run idle (open, nothing running)?"""
    repo = _db.get_repository()
    if repo is None:
        raise RuntimeError("database unavailable")
    row = repo.get_run(run_id)
    if not row:
        raise KeyError(run_id)
    alive = _worker_alive(_worker_pid(repo, run_id))
    active = str(row.get("status") or "") in _ACTIVE_STATUSES
    return {"run_id": run_id, "alive": alive, "idle": active and not alive,
            "status": row.get("status"), "idle_since": row.get("updated_at")}


def _resume_prompt() -> str:
    return (
        "Resume the agent-smith pentest run you are attached to. Call "
        "session(action='recovery') to recover your position, apply any pending operator "
        "instructions it reports FIRST, then continue with the next recommended tool call "
        "until the scan is complete or genuinely blocked."
    )


def resume_run(run_id: str, prompt: str | None = None) -> dict:
    """Start the run's agent again after it went idle.

    No-op when the worker is still running (a second agent on the same run would
    double-write its state) or when the run has ended.
    """
    repo = _db.get_repository()
    if repo is None:
        raise RuntimeError("database unavailable")
    row = repo.get_run(run_id)
    if not row:
        raise KeyError(run_id)
    # From here on use the id as STORED for this run, never the caller's string.
    run_id = str(row["run_id"])
    if _worker_alive(_worker_pid(repo, run_id)):
        return {"run_id": run_id, "resumed": False, "reason": "already running"}
    status = str(row.get("status") or "")
    if status not in _ACTIVE_STATUSES:
        return {"run_id": run_id, "resumed": False, "reason": "run has ended" if status else "run is not active"}
    workdir = _contained_workdir(run_id, row.get("workdir"))
    workdir.mkdir(parents=True, exist_ok=True)
    try:
        opts = json.loads((workdir / _RUN_START_OPTIONS_FILENAME).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        opts = {}
    target = str(opts.get("target") or row.get("target") or "")
    pid = _spawn_worker(
        run_id, workdir, target, str(opts.get("depth") or row.get("depth") or "standard"),
        list(opts.get("scope") or [target]), list(opts.get("out_of_scope") or []),
        prompt=prompt or _resume_prompt(),
    )
    _save_worker(repo, run_id, pid)
    return {"run_id": run_id, "resumed": True, "pid": pid}


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
    """The pid recorded in ``path``.

    Reads both forms of the dashboard pid file: the plain pid written here, and
    ``pid:code-fingerprint`` written when a tool server starts the dashboard
    (core.api_server.serve). Reading only the first left `smith stop` unable to
    stop a dashboard recorded in the second.
    """
    try:
        return int(path.read_text(encoding="utf-8").strip().split(":", 1)[0])
    except Exception:
        return None


# Process checks go through psutil, not os.kill: on Windows os.kill(pid, 0)
# sends CTRL_C_EVENT (signal 0) instead of probing the pid, and there is no
# SIGKILL. psutil maps terminate/kill onto SIGTERM/SIGKILL on POSIX and
# TerminateProcess on Windows.
def _pid_alive(pid: int | None) -> bool:
    if not pid or pid <= 0:
        return False
    try:
        return psutil.Process(pid).status() != psutil.STATUS_ZOMBIE
    except (psutil.Error, OSError):
        return False


def _terminate_pid(pid: int | None) -> bool:
    if not pid or pid <= 0:
        return False
    try:
        psutil.Process(pid).terminate()
    except (psutil.Error, OSError):
        return False
    return True


def _kill_pid(pid: int) -> None:
    """Force-kill ``pid``. A process that is already gone is not an error."""
    try:
        psutil.Process(pid).kill()
    except psutil.NoSuchProcess:
        pass


def _detached_spawn_kwargs() -> dict:
    """Popen options that keep the dashboard alive after `smith start` exits.

    POSIX: a new session, so the terminal's SIGHUP does not reach it. Windows:
    no console of its own and a new process group — otherwise closing the
    terminal that ran `smith start` delivers CTRL_CLOSE_EVENT and takes the
    dashboard down with it.
    """
    if sys.platform != "win32":
        return {"start_new_session": True}
    flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
    flags |= getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
    return {"creationflags": flags}


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
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        **_detached_spawn_kwargs(),
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
    source = _validate_source(payload)
    extras = _validate_extras(payload)
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
            source=source,
            extras=extras,
        )
        session_doc["worker_pid"] = worker_pid
        repo.upsert_run(run_id, session_doc, str(workdir))
        repo.save_snapshot(run_id, "session", session_doc)
        _save_worker(repo, run_id, worker_pid)
    except Exception:
        session_doc["status"] = "failed"
        repo.upsert_run(run_id, session_doc, str(workdir))
        repo.save_snapshot(run_id, "session", session_doc)
        _stop_run_tooling(run_id)
        shutil.rmtree(workdir, ignore_errors=True)
        raise
    problem = _worker_startup_problem(run_id, worker_pid, workdir)
    if problem:
        # Keep the workdir: its worker.log is the evidence of what went wrong.
        session_doc["status"] = "failed"
        repo.upsert_run(run_id, session_doc, str(workdir))
        repo.save_snapshot(run_id, "session", session_doc)
        _stop_run_tooling(run_id)
        raise WorkerStartError(problem)
    return {
        "run_id": run_id,
        "status": "running",
        "dashboard_url": f"{_dashboard_base_url()}/#k={token}",
        "token": token,
    }


def list_runs() -> list[dict]:
    rows = _db.list_runs()
    repo = _db.get_repository()

    def _status(row: dict) -> str:
        # An open run whose agent has stopped is shown as "idle": it waits for the
        # operator (an instruction or Resume). Derived on read, never written — the
        # run's own tool server owns the stored status.
        status = str(row.get("status") or "")
        if repo is not None and status in _ACTIVE_STATUSES and status != "starting":
            if not _worker_alive(_worker_pid(repo, str(row.get("run_id")))):
                return "idle"
        return status

    return [
        {
            "run_id": row.get("run_id"),
            "target": row.get("target"),
            "status": _status(row),
            "depth": row.get("depth"),
            "workdir": row.get("workdir"),
            "created_at": row.get("created_at"),
            "updated_at": row.get("updated_at"),
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
    # The agent's own children go too. On Windows the worker pid is the client's
    # .cmd shim (cmd.exe) and the agent is its child: stopping only the shim
    # would leave the agent testing a target the operator just told it to stop.
    children = _worker_children(worker_pid)
    if not _terminate_pid(worker_pid):
        return errors
    for child in children:
        _terminate_pid(child)
    deadline = time.time() + 5
    while _pid_alive(worker_pid) and time.time() < deadline:
        time.sleep(0.1)
    for pid in [worker_pid, *children]:
        if not _pid_alive(pid):
            continue
        try:
            _kill_pid(pid)
        except (psutil.Error, OSError) as exc:
            errors.append(f"worker {run_id}: {exc}")
    _WORKER_PROCS.pop(worker_pid, None)
    return errors


def _worker_children(pid: int) -> list[int]:
    """Pids of every process the worker started (empty if it is gone)."""
    try:
        children = psutil.Process(pid).children(recursive=True)
    except (psutil.Error, OSError):
        return []
    if not isinstance(children, (list, tuple)):
        return []
    return [int(c.pid) for c in children if isinstance(getattr(c, "pid", None), int)]


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
    """End the run now: stop its agent and tooling and mark it stopped."""
    return _end_run(run_id, "stopped", "operator_stop")


def complete_run(run_id: str, notes: str = "") -> dict:
    """The operator completes the run: its agent stops and it is marked complete.

    The dashboard's Complete button used to finalise the platform process's own
    (repo-root) session instead, so a platform scan stayed open and came back as
    idle on the next refresh.
    """
    return _end_run(run_id, "complete", "operator_complete", notes)


def _end_run(run_id: str, status: str, stop_reason: str, notes: str = "") -> dict:
    repo = _db.get_repository()
    if repo is None:
        raise RuntimeError("database unavailable")
    row = repo.get_run(run_id) or {}
    session_doc = repo.load_snapshot(run_id, "session") or {"run_id": run_id}
    cleanup_errors = []
    cleanup_errors.extend(_stop_worker(run_id, _worker_pid(repo, run_id)))
    cleanup_errors.extend(_stop_run_tooling(run_id))
    ended = {"status": status, "stop_reason": stop_reason,
             "finished": datetime.now(timezone.utc).isoformat()}
    if notes:
        ended["notes"] = notes[:_NOTES_MAX_LENGTH]
    session_doc.update(ended)
    session_doc["cleanup_errors"] = cleanup_errors
    # The run's tool server rewrites the session snapshot without a workdir, so
    # take it from the run row — writing "" here would orphan the run's files.
    workdir = str(row.get("workdir") or session_doc.get("workdir") or "")
    repo.upsert_run(run_id, session_doc, workdir)
    repo.save_snapshot(run_id, "session", session_doc)
    _write_run_session_file(run_id, workdir, ended)
    result = {"run_id": run_id, "status": status}
    if cleanup_errors:
        # Details (process and docker error text) stay in the stored session and
        # the server log; callers only learn that cleanup was incomplete.
        _LOG.warning("end run %s (%s): cleanup incomplete: %s", run_id, status, cleanup_errors)
        result["cleanup_errors"] = cleanup_errors
    return result


def _write_run_session_file(run_id: str, recorded_workdir: str, fields: dict) -> None:
    """Bring the run's own session.json in line with how the run ended.

    The run's tool server wrote that file and is gone by now. Exports and a later
    "resume a prior engagement" read it, and would otherwise see a scan still
    marked as running. Best effort: a run without the file is left alone.
    """
    try:
        path = _contained_workdir(run_id, recorded_workdir or None) / _paths.SESSION_FILE.name
        doc = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(doc, dict):
            return
        doc.update(fields)
        path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    except (OSError, ValueError):
        pass


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


def apply_database_url_default() -> None:
    """Point this process at the control-plane database `smith start` uses.

    For the `smith` CLI process only: without it, `smith status` in a fresh
    shell (no SMITH_DATABASE_URL exported) reports the database unavailable
    while the Postgres container `smith start` brought up is healthy. Not done
    inside control_plane_status() so reading status never flips the database on
    for a long-lived process (dashboard, MCP server, tests).
    """
    os.environ.setdefault("SMITH_DATABASE_URL", _ensure_database_url())


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
