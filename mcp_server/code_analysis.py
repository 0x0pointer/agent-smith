"""
Code analysis tools
===================
Static analysis and secret scanning for local codebases.
"""
import os

from mcp_server._app import mcp, _run


@mcp.tool()
async def run_semgrep(path: str = "/target", flags: str = "") -> str:
    """Static code analysis on mounted codebase. Args: path, flags."""
    return await _run("semgrep", path=path, flags=flags)


@mcp.tool()
async def run_trufflehog(path: str = "/target", flags: str = "") -> str:
    """Secret/credential scanner on mounted codebase. Args: path, flags."""
    return await _run("trufflehog", path=path, flags=flags)


@mcp.tool()
async def set_codebase_target(path: str) -> str:
    """Set the local codebase path that run_semgrep and run_trufflehog will mount."""
    from core import logger as log
    abs_path = os.path.abspath(path)
    if not os.path.isdir(abs_path):
        return f"Error: '{abs_path}' is not a directory"
    os.environ["PENTEST_TARGET_PATH"] = abs_path
    log.note(f"codebase target → {abs_path}")
    return f"Codebase target set to: {abs_path}"
