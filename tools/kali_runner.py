"""
Kali container lifecycle
========================
Manages the persistent kali-mcp Docker container:
  - image / container existence checks
  - start (with health-poll)
  - command execution via the official kali-server-mcp HTTP API
  - stop

Used exclusively by mcp_server.py; not a Tool registry entry.
"""
from __future__ import annotations

import asyncio
import os
import shlex

from tools.docker_cli import docker_executable

KALI_IMAGE     = "pentest-agent/kali-mcp"
KALI_CONTAINER = "pentest-kali"
KALI_PORT      = 5001          # host port → container port 5000
KALI_API       = f"http://localhost:{KALI_PORT}"

# Prevents concurrent callers from racing to create the same container.
_start_lock = asyncio.Lock()

import pathlib as _pathlib
import secrets as _secrets

_REPO_ROOT = _pathlib.Path(__file__).resolve().parents[1]
_GUARD_SRC = _REPO_ROOT / "tools" / "kali" / "api_guard.py"
_TOKEN_FILE = _REPO_ROOT / "logs" / ".kali_api_token"
# Session artifacts (transform/redteam payloads, tool output) are mounted READ-ONLY at
# /artifacts so a Kali batch runner can read engine payloads by id without a temporary
# HTTP server: /artifacts/<artifact_id>.txt.
_ARTIFACTS_DIR = _REPO_ROOT / "artifacts"
KALI_ARTIFACTS_MOUNT = "/artifacts"
# kali-server-mcp runs loopback-only inside the container on this port; only the
# in-container guard (published on :5000) can reach it.
_KALI_UPSTREAM_PORT = "5555"


def _kali_token() -> str:
    """Shared secret between the MCP and the in-container API guard, persisted (0600) so
    both agree across restarts. Fail-open ('') so a filesystem hiccup never breaks Kali —
    the guard then runs open and logs a warning."""
    try:
        if _TOKEN_FILE.exists():
            existing = _TOKEN_FILE.read_text().strip()
            if existing:
                return existing
        token = _secrets.token_hex(32)
        _TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
        _TOKEN_FILE.write_text(token)
        try:
            _TOKEN_FILE.chmod(0o600)
        except OSError:
            pass
        return token
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# State checks
# ---------------------------------------------------------------------------

async def image_exists() -> bool:
    proc = await asyncio.create_subprocess_exec(
        docker_executable(), "image", "inspect", KALI_IMAGE,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await proc.wait()
    return proc.returncode == 0


async def container_running() -> bool:
    proc = await asyncio.create_subprocess_exec(
        docker_executable(), "inspect", "--format={{.State.Running}}", KALI_CONTAINER,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await proc.communicate()
    return stdout.strip() == b"true"


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

def _forward_ai_keys(environ) -> list[str]:
    """docker ``-e`` flags for the AI API keys forwarded into the Kali container. AITEST_ANTHROPIC_API_KEY
    (kept out of Claude Code's ANTHROPIC_API_KEY so it can't bill the Smith agent) is forwarded AS
    ANTHROPIC_API_KEY for the in-container tools; a bare ANTHROPIC_API_KEY (SMITH_USE_API_KEY=yes / legacy)
    overrides it when both are set."""
    fwd: dict[str, str] = {}
    for src, dst in (("OPENAI_API_KEY", "OPENAI_API_KEY"),
                     ("AITEST_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY"),
                     ("ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY"),
                     ("AZURE_OPENAI_API_KEY", "AZURE_OPENAI_API_KEY")):
        if environ.get(src):
            fwd[dst] = environ[src]
    return [x for dst, val in fwd.items() for x in ("-e", f"{dst}={val}")]


async def ensure_running() -> tuple[bool, str]:
    """
    Start the Kali container if it isn't running yet.
    Returns (success, message).
    The container persists until stop() is called or the Docker daemon restarts.
    """
    import aiohttp

    async with _start_lock:
        if await container_running():
            return True, "already running"

        if not await image_exists():
            return False, (
                f"Image '{KALI_IMAGE}' not found. Build it first:\n"
                f"  docker build -t {KALI_IMAGE} ./tools/kali/"
            )

        try:
            _ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)   # else docker creates it root-owned
        except OSError:
            pass
        # Forward AI API keys into the container (see _forward_ai_keys).
        env_flags: list[str] = _forward_ai_keys(os.environ)

        _token = _kali_token()
        # Opt-in extra reverse-shell listener ports (e.g. "443,80,53"), gated on
        # SMITH_EXTRA_LISTENER_PORTS — EMPTY BY DEFAULT so local/macOS runs are
        # unchanged; the Codespace sets it so a shell forced onto a common egress
        # port is catchable at <tailnet-ip>:<port>. Published on 0.0.0.0 like the
        # tunnel ports (targets must reach them); the loopback-only command API is
        # unaffected. A clash (e.g. :53 vs a host resolver) is handled by the
        # retry-without-extras fallback below, so it can never sink Kali startup.
        _extra_ports: list[str] = []
        for _raw in os.environ.get("SMITH_EXTRA_LISTENER_PORTS", "").split(","):
            _raw = _raw.strip()
            if _raw.isdigit() and 0 < int(_raw) < 65536:
                _extra_ports += ["-p", f"{_raw}:{_raw}"]

        def _run_argv(extra: list[str]) -> list[str]:
            return [
                docker_executable(), "run", "-d",
                "--name", KALI_CONTAINER,
                # SECURITY: publish the command API to LOOPBACK ONLY. It is unauthenticated
                # root RCE — on 0.0.0.0 any host on the LAN could drive it. The MCP reaches it
                # at localhost:5001; the LAN cannot.
                "-p", f"127.0.0.1:{KALI_PORT}:5000",
                # Tunnel/listener ports stay on 0.0.0.0 — targets must reach them for
                # reverse tunnels / file transfer during a pentest (that is their purpose).
                "-p", "1080:1080",          # SOCKS5 proxy (chisel reverse tunnel)
                "-p", "8888:8888",          # chisel server listener
                "-p", "8889:8889",          # python HTTP server (file transfer to targets)
                "-p", "11601:11601",        # ligolo-ng proxy listener
                *extra,                     # opt-in reverse-shell listener ports
                "--rm",
                "--cap-add=NET_RAW",
                "--cap-add=NET_ADMIN",
                "--device=/dev/net/tun:/dev/net/tun",
                "--add-host=host.docker.internal:host-gateway",
                # Front the API with the loopback auth guard (token + Host allowlist) so a local
                # process or a DNS-rebinding page that reaches loopback still can't drive it. The
                # guard is MOUNTED so this is live without an image rebuild; the Dockerfile bakes
                # the same guard for clean builds.
                "-v", f"{_GUARD_SRC}:/usr/local/bin/kali-api-guard:ro",
                # Session artifacts, read-only (see KALI_ARTIFACTS_MOUNT).
                "-v", f"{_ARTIFACTS_DIR}:{KALI_ARTIFACTS_MOUNT}:ro",
                "-e", f"KALI_API_TOKEN={_token}",
                "-e", f"KALI_UPSTREAM_PORT={_KALI_UPSTREAM_PORT}",
                "-e", "KALI_GUARD_PORT=5000",
                *env_flags,
                KALI_IMAGE,
                # Override CMD: kali-server-mcp bound LOOPBACK-only inside the container; the
                # guard listens on the published :5000 and forwards to it after auth.
                "sh", "-c",
                f"kali-server-mcp --ip 127.0.0.1 --port {_KALI_UPSTREAM_PORT} & "
                "exec python3 /usr/local/bin/kali-api-guard",
            ]

        async def _docker_run(argv: list[str]) -> tuple[int, str]:
            p = await asyncio.create_subprocess_exec(
                *argv, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
            )
            _, err = await p.communicate()
            return (p.returncode or 0), err.decode().strip()

        rc, err = await _docker_run(_run_argv(_extra_ports))
        if rc != 0 and _extra_ports:
            # A published extra port likely clashed with a host listener (e.g. :53).
            # Don't let that sink Kali — retry with only the fixed ports.
            print(f"[kali] extra listener ports failed to publish ({err}); "
                  "retrying without SMITH_EXTRA_LISTENER_PORTS", flush=True)
            rc, err = await _docker_run(_run_argv([]))
        if rc != 0:
            return False, f"docker run failed: {err}"

    # Poll /health until the Flask server is ready (up to 30 s)
    for _ in range(30):
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(
                    f"{KALI_API}/health",
                    headers={"X-Kali-Token": _kali_token()},
                    timeout=aiohttp.ClientTimeout(total=1),
                ) as r:
                    if r.status == 200:
                        await _seed_curl_defaults()
                        return True, "started"
        except Exception:
            pass
        await asyncio.sleep(1)

    return False, "container started but /health never responded — check: docker logs pentest-kali"


async def _seed_curl_defaults() -> None:
    """Write /root/.curlrc into the running container so EVERY curl is bounded by default
    (connect-timeout 5s, max-time 30s). A hung request then can't silently block a tool
    call for minutes. Runtime seed → applies without an image rebuild; the Dockerfile
    bakes the same file for clean rebuilds. Best-effort — never fail container startup."""
    try:
        proc = await asyncio.create_subprocess_exec(
            docker_executable(), "exec", KALI_CONTAINER, "sh", "-c",
            "printf 'connect-timeout = 5\\nmax-time = 30\\n' > /root/.curlrc",
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()
    except Exception:
        pass


async def stop() -> str:
    proc = await asyncio.create_subprocess_exec(
        docker_executable(), "stop", KALI_CONTAINER,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    if proc.returncode == 0:
        return f"Container '{KALI_CONTAINER}' stopped."
    return f"Could not stop container: {stderr.decode().strip()}"


# ---------------------------------------------------------------------------
# Command execution
# ---------------------------------------------------------------------------

def _host_rewrite(command: str) -> str:
    """Rewrite localhost/127.0.0.1 → host.docker.internal so tools reach the host."""
    command = command.replace("localhost", "host.docker.internal")
    command = command.replace("127.0.0.1", "host.docker.internal")
    return command


def _force_bash(command: str) -> str:
    """Wrap the command in `bash -c` so bash-only syntax works.

    kali-server-mcp executes commands via /bin/sh, which on Kali/Debian is
    dash — it does NOT support `[[ ]]`, arrays, `<(...)`, brace expansion,
    `==` in test, and other bashisms. Agents routinely produce bash-shaped
    one-liners, and without this wrapper every such command hits
    `[[: not found` and silently returns a partial or empty result.

    The command is quoted with `shlex.quote` so inner quotes, `$`, and
    backslashes survive intact. Already-wrapped commands (`bash -c '...'`)
    end up double-wrapped, which is harmless: the outer bash invokes the
    inner bash.
    """
    if not command.strip():
        return command
    return f"bash -c {shlex.quote(command)}"


async def exec_command(command: str, timeout: int = 600) -> str:
    """
    Run a shell command via the kali-server-mcp HTTP API.
    Auto-starts the container if it isn't already running.
    localhost/127.0.0.1 are transparently rewritten to host.docker.internal.
    Commands are wrapped in `bash -c` so bashisms like `[[`, arrays, and
    process substitution work (the upstream /bin/sh is dash, which does not
    support any of these).
    """
    command = _host_rewrite(command)
    command = _force_bash(command)
    import aiohttp

    ok, msg = await ensure_running()
    if not ok:
        return msg

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{KALI_API}/api/command",
                json={"command": command, "timeout": timeout},
                headers={"X-Kali-Token": _kali_token()},
                timeout=aiohttp.ClientTimeout(total=timeout + 30),
            ) as resp:
                data      = await resp.json()
                stdout    = data.get("stdout", "")
                stderr    = data.get("stderr", "")
                timed_out = data.get("timed_out", False)
                output    = (stdout + "\n" + stderr).strip()
                if timed_out:
                    output = f"[partial — command timed out]\n{output}"
                return output or "[no output]"
    except BaseException as exc:
        return f"Error calling kali API: {type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# File delivery + background jobs
# ---------------------------------------------------------------------------

async def put_file(path: str, data: bytes) -> str | None:
    """Write ``data`` to absolute ``path`` inside the container (via ``docker exec -i``
    + stdin, so content never touches a shell command line). Returns an error string,
    or None on success."""
    if not path.startswith("/") or "\x00" in path:
        return f"invalid container path '{path}' (must be absolute)"
    ok, msg = await ensure_running()
    if not ok:
        return msg
    q = shlex.quote(path)
    proc = await asyncio.create_subprocess_exec(
        docker_executable(), "exec", "-i", KALI_CONTAINER, "sh", "-c",
        f'mkdir -p "$(dirname {q})" && cat > {q}',
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
    )
    _, err = await proc.communicate(data)
    if proc.returncode != 0:
        return f"failed to write {path}: {err.decode(errors='replace').strip()}"
    return None


_JOB_DIR = "/tmp/smith-jobs"


def job_paths(job_id: str) -> tuple[str, str]:
    return f"{_JOB_DIR}/{job_id}.log", f"{_JOB_DIR}/{job_id}.rc"


def background_command(command: str, job_id: str) -> str:
    """Shell that detaches ``command`` (nohup, own session) writing output to
    <id>.log and its exit code to <id>.rc, and returns immediately."""
    log_f, rc_f = job_paths(job_id)
    inner = f"bash -c {shlex.quote(command)} > {log_f} 2>&1; echo $? > {rc_f}"
    return (f"mkdir -p {_JOB_DIR} && nohup setsid sh -c {shlex.quote(inner)} "
            f"> /dev/null 2>&1 < /dev/null & echo started job {job_id}")


def poll_command(job_id: str, tail_bytes: int = 6000) -> str:
    log_f, rc_f = job_paths(job_id)
    return (f"if [ -f {rc_f} ]; then echo \"__JOB_STATUS__ done rc=$(cat {rc_f})\"; "
            f"elif [ -f {log_f} ]; then echo '__JOB_STATUS__ running'; "
            f"else echo '__JOB_STATUS__ unknown'; fi; "
            f"[ -f {log_f} ] && tail -c {int(tail_bytes)} {log_f}")
