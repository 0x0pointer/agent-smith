"""
Container infrastructure
========================
Kali container lifecycle management and Docker image pre-fetching.
"""
import asyncio

from core import logger as log
from mcp_server._app import mcp


@mcp.tool()
async def start_kali() -> str:
    """
    Explicitly start the Kali container and wait for it to be ready.
    kali_exec does this automatically, but call this first to pre-warm
    the container before a scan session.
    """
    from tools import kali_runner
    log.tool_call("start_kali", {})
    ok, msg = await kali_runner.ensure_running()
    result  = (
        f"Kali container ready at {kali_runner.KALI_API} ({msg})"
        if ok else f"Failed to start Kali container: {msg}"
    )
    log.tool_result("start_kali", result)
    return result


@mcp.tool()
async def stop_kali() -> str:
    """Stop and remove the Kali container. Call this to clean up after a session."""
    from tools import kali_runner
    log.tool_call("stop_kali", {})
    result = await kali_runner.stop()
    log.tool_result("stop_kali", result)
    return result


@mcp.tool()
async def pull_images() -> str:
    """
    Pull all lightweight tool images from Docker Hub.
    Run once on first setup so scans don't stall on image downloads.
    The Kali image is not pulled here — build it separately:
      docker build -t pentest-agent/kali-mcp ./tools/kali/
    """
    from tools import REGISTRY
    log.tool_call("pull_images", {})
    images = [tool.image for tool in REGISTRY.values() if not tool.needs_mount]
    seen: set[str] = set()
    unique = [img for img in images if not (img in seen or seen.add(img))]  # type: ignore[func-returns-value]
    lines: list[str] = []
    for image in unique:
        proc = await asyncio.create_subprocess_exec(
            "docker", "pull", image,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await proc.communicate()
        status = "ok" if proc.returncode == 0 else "FAILED"
        lines.append(f"[{status}] {image}")
    result = "\n".join(lines)
    log.tool_result("pull_images", result)
    return result
