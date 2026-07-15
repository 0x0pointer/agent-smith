"""
Metasploit container lifecycle
==============================
Manages a persistent Metasploit Framework Docker container:
  - image / container existence checks
  - start (with health-poll)
  - command execution via HTTP API
  - stop

Uses the official metasploitframework/metasploit-framework image
with a thin Flask API wrapper for command execution.
"""
from __future__ import annotations

import asyncio
import os

from tools.docker_cli import docker_executable

MSF_IMAGE     = "pentest-agent/metasploit"
MSF_CONTAINER = "pentest-metasploit"
MSF_PORT      = 5002          # host port → container port 5000
MSF_API       = f"http://localhost:{MSF_PORT}"

# Prevents concurrent callers from racing to create the same container.
_start_lock = asyncio.Lock()

import pathlib as _pathlib
import secrets as _secrets

_REPO_ROOT = _pathlib.Path(__file__).resolve().parents[1]
_SERVER_SRC = _REPO_ROOT / "tools" / "metasploit" / "server.py"
_SECRET_FILE = _REPO_ROOT / "logs" / ".msf_api_secret"


def _msf_secret() -> str:
    """Shared secret for the Metasploit API, persisted (0600) so the MCP and container agree
    across restarts. Fail-open ('') so a filesystem hiccup never breaks MSF — loopback + the
    Host allowlist still protect the endpoint."""
    try:
        if _SECRET_FILE.exists():
            existing = _SECRET_FILE.read_text().strip()
            if existing:
                return existing
        token = _secrets.token_hex(32)
        _SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
        _SECRET_FILE.write_text(token)
        try:
            _SECRET_FILE.chmod(0o600)
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
        docker_executable(), "image", "inspect", MSF_IMAGE,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await proc.wait()
    return proc.returncode == 0


async def container_running() -> bool:
    proc = await asyncio.create_subprocess_exec(
        docker_executable(), "inspect", "--format={{.State.Running}}", MSF_CONTAINER,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await proc.communicate()
    return stdout.strip() == b"true"


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

async def ensure_running() -> tuple[bool, str]:
    """
    Start the Metasploit container if it isn't running yet.
    Returns (success, message).
    """
    import aiohttp

    async with _start_lock:
        if await container_running():
            return True, "already running"

        if not await image_exists():
            return False, (
                f"Image '{MSF_IMAGE}' not found. Build it first:\n"
                f"  docker build -t {MSF_IMAGE} ./tools/metasploit/"
            )

        _secret = _msf_secret()
        proc = await asyncio.create_subprocess_exec(
            docker_executable(), "run", "-d",
            "--name", MSF_CONTAINER,
            # SECURITY: the command API is unauthenticated root RCE — publish it to LOOPBACK
            # ONLY (was 0.0.0.0). The MCP reaches it at localhost:5002; the LAN cannot.
            "-p", f"127.0.0.1:{MSF_PORT}:5000",
            # Handler/proxy ports stay on 0.0.0.0 — payloads/targets must reach them.
            "-p", "4444:4444",          # meterpreter handler
            "-p", "4445:4445",          # secondary handler
            "-p", "1081:1081",          # MSF socks_proxy module
            "--rm",
            "--cap-add=NET_RAW",
            "--cap-add=NET_ADMIN",
            "--add-host=host.docker.internal:host-gateway",
            # Mount the hardened server (Host allowlist + json-only) so it's live without an
            # image rebuild; set the shared secret it enforces on /api/command.
            "-v", f"{_SERVER_SRC}:/opt/server.py:ro",
            "-e", f"MSF_API_SECRET={_secret}",
            MSF_IMAGE,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            return False, f"docker run failed: {stderr.decode().strip()}"

    # Poll /health until the server is ready (up to 60 s — MSF is slow to start)
    for _ in range(60):
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(
                    f"{MSF_API}/health",
                    headers={"X-API-Secret": _msf_secret()},
                    timeout=aiohttp.ClientTimeout(total=2),
                ) as r:
                    if r.status == 200:
                        return True, "started"
        except Exception:
            pass
        await asyncio.sleep(1)

    return False, "container started but /health never responded — check: docker logs pentest-metasploit"


async def stop() -> str:
    proc = await asyncio.create_subprocess_exec(
        docker_executable(), "stop", MSF_CONTAINER,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    if proc.returncode == 0:
        return f"Container '{MSF_CONTAINER}' stopped."
    return f"Could not stop container: {stderr.decode().strip()}"


# ---------------------------------------------------------------------------
# Command execution
# ---------------------------------------------------------------------------

def _host_rewrite(command: str) -> str:
    """Rewrite localhost/127.0.0.1 → host.docker.internal so tools reach the host."""
    command = command.replace("localhost", "host.docker.internal")
    command = command.replace("127.0.0.1", "host.docker.internal")
    return command


async def exec_command(command: str, timeout: int = 900) -> str:  # NOSONAR
    """
    Run a shell command in the Metasploit container via HTTP API.
    Auto-starts the container if it isn't already running.
    """
    command = _host_rewrite(command)
    import aiohttp

    ok, msg = await ensure_running()
    if not ok:
        return msg

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{MSF_API}/api/command",
                json={"command": command},
                headers={"X-API-Secret": _msf_secret()},
                timeout=aiohttp.ClientTimeout(total=timeout + 5),
            ) as resp:
                data      = await resp.json()
                stdout    = data.get("stdout", "")
                stderr    = data.get("stderr", "")
                timed_out = data.get("timed_out", False)
                output    = (stdout + "\n" + stderr).strip()
                if timed_out:
                    output = f"[partial — command timed out]\n{output}"
                return output or "[no output]"
    except Exception as exc:
        return f"Error calling Metasploit API: {type(exc).__name__}: {exc}"
