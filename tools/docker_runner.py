from __future__ import annotations

import asyncio
import os

DEFAULT_TIMEOUT = 600
PULL_TIMEOUT = 300  # 5 min max for pulling a single image

_pulled_images: set[str] = set()


async def image_exists(image: str) -> bool:
    """Check if a Docker image exists locally (no pull)."""
    proc = await asyncio.create_subprocess_exec(
        "docker", "image", "inspect", image,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await proc.wait()
    return proc.returncode == 0


async def _ensure_image(image: str) -> None:
    """Pull an image if it hasn't been pulled this session."""
    if image in _pulled_images:
        return
    if await image_exists(image):
        _pulled_images.add(image)
        return
    pull = await asyncio.create_subprocess_exec(
        "docker", "pull", image,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            pull.communicate(), timeout=PULL_TIMEOUT,
        )
    except asyncio.TimeoutError:
        pull.kill()
        await pull.communicate()
        raise RuntimeError(
            f"Timed out pulling Docker image '{image}' after {PULL_TIMEOUT}s. "
            f"Check your network or pre-pull with: docker pull {image}"
        )
    if pull.returncode != 0:
        msg = stderr.decode(errors="replace").strip() or stdout.decode(errors="replace").strip()
        raise RuntimeError(
            f"Failed to pull Docker image '{image}': {msg}. "
            f"If this is a private image, run 'docker login ghcr.io' first."
        )
    _pulled_images.add(image)


async def run_container(
    image: str,
    args: list[str],
    timeout: int = DEFAULT_TIMEOUT,
    mount_path: str | None = None,
    extra_volumes: list[tuple[str, str]] | None = None,
    env_vars: dict[str, str] | None = None,
) -> tuple[str, str, int]:
    """
    Run a Docker container and return (stdout, stderr, exit_code).
    Raises asyncio.TimeoutError if the container exceeds the timeout.
    extra_volumes: list of (host_path, container_path) tuples for additional -v mounts.
    env_vars: environment variables to inject into the container via -e flags.
    """
    await _ensure_image(image)
    cmd = ["docker", "run", "--rm", "--network=host", "--memory=2g", "--cpus=1.5"]

    for key, val in (env_vars or {}).items():
        cmd += ["-e", f"{key}={val}"]

    if mount_path:
        abs_path = os.path.abspath(mount_path)
        cmd += ["-v", f"{abs_path}:/target:ro"]

    for host_path, container_path in (extra_volumes or []):
        abs_host = os.path.abspath(os.path.expanduser(host_path))
        os.makedirs(abs_host, exist_ok=True)
        cmd += ["-v", f"{abs_host}:{container_path}"]

    cmd.append(image)
    cmd += args

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        raise

    return (
        stdout.decode(errors="replace"),
        stderr.decode(errors="replace"),
        proc.returncode or 0,
    )
