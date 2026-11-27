"""
Shared per-run container helpers
================================
The Kali / Metasploit / MobSF runners each manage a persistent tool container.
In multi-run mode (``SMITH_RUN_ID`` set, see :mod:`core.run_context`) every run
keys its container + Docker network by ``run_id`` and resolves an ephemeral host
port after start, so concurrent runs don't collide; in single-run mode the fixed
names/ports are kept.

That logic was byte-identical across the three ``*_runner`` modules (bar the tool
label and default port), so it lives here once. Each runner keeps a thin
module-level surface (``container_name()`` / ``network_name()`` / ``api_url()`` /
``_RUN_API_PORTS``) that delegates to these functions.

``docker_exec`` is passed in by the caller (its own ``docker_executable``
reference) rather than captured here, so a test that monkeypatches the runner's
``docker_executable`` still steers these calls.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable

from core import run_context as _run_context
from tools.docker_cli import docker_executable


def container_name(tool: str, default: str) -> str:
    """Run-scoped container name in multi-run mode, else the fixed default."""
    return _run_context.container_name(tool) if _run_context.multi_run_mode() else default


def network_name() -> str:
    """Run-scoped Docker network in multi-run mode, else the shared ``smith`` net."""
    return _run_context.docker_network_name() if _run_context.multi_run_mode() else "smith"


def network_args() -> list[str]:
    """``--network <run-net>`` flags for ``docker run`` (empty in single-run mode)."""
    return ["--network", network_name()] if _run_context.multi_run_mode() else []


def remember_api_port(api_ports: dict[str, int], port: int) -> None:
    """Record the resolved host API port for the current run."""
    api_ports[_run_context.run_id()] = int(port)


def api_url(api_ports: dict[str, int], default_port: int, default_url: str) -> str:
    """Base URL of the container's API for the current run."""
    if _run_context.multi_run_mode():
        return f"http://127.0.0.1:{api_ports.get(_run_context.run_id(), default_port)}"
    return default_url


def listener_publish_arg(port: int) -> str:
    """``-p`` arg for a tunnel/handler port: ephemeral host port in multi-run mode."""
    return f"0.0.0.0::{port}" if _run_context.multi_run_mode() else f"{port}:{port}"


def loopback_publish_arg(default_port: int, container_port: int) -> str:
    """``-p`` arg for a LOOPBACK-only API port: ephemeral host port in multi-run mode."""
    return (f"127.0.0.1::{container_port}" if _run_context.multi_run_mode()
            else f"127.0.0.1:{default_port}:{container_port}")


def host_rewrite(command: str) -> str:
    """Rewrite localhost/127.0.0.1 → host.docker.internal so tools reach the host."""
    command = command.replace("localhost", "host.docker.internal")
    command = command.replace("127.0.0.1", "host.docker.internal")
    return command


async def ensure_network(docker_exec: Callable[[], str] = docker_executable) -> None:
    """Create the run's Docker network if it doesn't exist yet (no-op single-run)."""
    if not _run_context.multi_run_mode():
        return
    inspect_proc = await asyncio.create_subprocess_exec(
        docker_exec(), "network", "inspect", network_name(),
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await inspect_proc.wait()
    if inspect_proc.returncode == 0:
        return
    create_proc = await asyncio.create_subprocess_exec(
        docker_exec(), "network", "create", network_name(),
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await create_proc.wait()


async def discover_host_port(
    container: str,
    container_port: int,
    default_port: int,
    docker_exec: Callable[[], str] = docker_executable,
) -> int:
    """Read the ephemeral host port Docker assigned to ``container_port`` (multi-run)."""
    if not _run_context.multi_run_mode():
        return default_port
    proc = await asyncio.create_subprocess_exec(
        docker_exec(), "port", container, f"{container_port}/tcp",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await proc.communicate()
    try:
        return int(stdout.decode().strip().rsplit(":", 1)[1])
    except Exception:
        return default_port


async def stop(container: str, docker_exec: Callable[[], str] = docker_executable) -> str:
    """Stop the given tool container; shared by all three runners' ``stop()``."""
    proc = await asyncio.create_subprocess_exec(
        docker_exec(), "stop", container,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    if proc.returncode == 0:
        return f"Container '{container}' stopped."
    return f"Could not stop container: {stderr.decode().strip()}"
