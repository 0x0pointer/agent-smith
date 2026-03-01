from __future__ import annotations

import asyncio
import os

DEFAULT_TIMEOUT = 120


async def run_container(
    image: str,
    args: list[str],
    timeout: int = DEFAULT_TIMEOUT,
    mount_path: str | None = None,
) -> tuple[str, str, int]:
    """
    Run a Docker container and return (stdout, stderr, exit_code).
    Raises asyncio.TimeoutError if the container exceeds the timeout.
    """
    cmd = ["docker", "run", "--rm", "--network=host"]

    if mount_path:
        abs_path = os.path.abspath(mount_path)
        cmd += ["-v", f"{abs_path}:/target:ro"]

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
