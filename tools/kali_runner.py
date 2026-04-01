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

KALI_IMAGE     = "pentest-agent/kali-mcp"
KALI_CONTAINER = "pentest-kali"
KALI_PORT      = 5001          # host port → container port 5000
KALI_API       = f"http://localhost:{KALI_PORT}"

# Prevents concurrent callers from racing to create the same container.
_start_lock = asyncio.Lock()


# ---------------------------------------------------------------------------
# State checks
# ---------------------------------------------------------------------------

async def image_exists() -> bool:
    proc = await asyncio.create_subprocess_exec(
        "docker", "image", "inspect", KALI_IMAGE,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await proc.wait()
    return proc.returncode == 0


async def container_running() -> bool:
    proc = await asyncio.create_subprocess_exec(
        "docker", "inspect", "--format={{.State.Running}}", KALI_CONTAINER,
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

        # Forward AI API keys from host environment into the container
        _AI_ENV_KEYS = ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "AZURE_OPENAI_API_KEY")
        env_flags: list[str] = []
        for key in _AI_ENV_KEYS:
            val = os.environ.get(key)
            if val:
                env_flags += ["-e", f"{key}={val}"]

        proc = await asyncio.create_subprocess_exec(
            "docker", "run", "-d",
            "--name", KALI_CONTAINER,
            "-p", f"{KALI_PORT}:5000",
            "-p", "1080:1080",          # SOCKS5 proxy (chisel reverse tunnel)
            "-p", "8888:8888",          # chisel server listener
            "-p", "8889:8889",          # python HTTP server (file transfer to targets)
            "-p", "11601:11601",        # ligolo-ng proxy listener
            "--rm",
            "--cap-add=NET_RAW",
            "--cap-add=NET_ADMIN",
            "--device=/dev/net/tun:/dev/net/tun",
            "--add-host=host.docker.internal:host-gateway",
            *env_flags,
            KALI_IMAGE,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            return False, f"docker run failed: {stderr.decode().strip()}"

    # Poll /health until the Flask server is ready (up to 30 s)
    for _ in range(30):
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(
                    f"{KALI_API}/health",
                    timeout=aiohttp.ClientTimeout(total=1),
                ) as r:
                    if r.status == 200:
                        return True, "started"
        except Exception:
            pass
        await asyncio.sleep(1)

    return False, "container started but /health never responded — check: docker logs pentest-kali"


async def stop() -> str:
    proc = await asyncio.create_subprocess_exec(
        "docker", "stop", KALI_CONTAINER,
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


async def exec_command(command: str, timeout: int = 600) -> str:
    """
    Run a shell command via the kali-server-mcp HTTP API.
    Auto-starts the container if it isn't already running.
    localhost/127.0.0.1 are transparently rewritten to host.docker.internal.
    """
    command = _host_rewrite(command)
    import aiohttp

    ok, msg = await ensure_running()
    if not ok:
        return msg

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{KALI_API}/api/command",
                json={"command": command},
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
    except BaseException as exc:
        return f"Error calling kali API: {type(exc).__name__}: {exc}"
