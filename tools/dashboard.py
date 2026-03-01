"""
Dashboard server
================
Spawns a python3 -m http.server process that serves the repo root,
making dashboard.html and findings.json accessible from a browser.

Used exclusively by mcp_server.py; not a Tool registry entry.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

_REPO_DIR = Path(__file__).parent.parent

_proc: "asyncio.subprocess.Process | None" = None


async def serve(port: int = 8080) -> str:
    """
    Start the HTTP server (idempotent — safe to call multiple times).
    Returns the full dashboard URL.
    """
    global _proc

    if _proc is not None and _proc.returncode is None:
        return f"http://localhost:{port}/dashboard.html"

    _proc = await asyncio.create_subprocess_exec(
        "python3", "-m", "http.server", str(port),
        "--directory", str(_REPO_DIR),
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await asyncio.sleep(0.8)

    if _proc.returncode is not None:
        return f"ERROR: failed to start dashboard server on port {port}"

    return f"http://localhost:{port}/dashboard.html"
