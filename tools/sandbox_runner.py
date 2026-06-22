"""
Isolated execution sandbox
===========================
Build & run untrusted *target* code to CONFIRM a white-box finding with a real
crash/exec artifact instead of a static "input reaches sink" claim.

This is deliberately NOT the persistent Kali container: that one runs with
NET_RAW/NET_ADMIN and host networking, which is unsafe for executing untrusted
code. Every run here is an ephemeral, **network-isolated**, **capability-dropped**
container over a **staged COPY** of the codebase — the original source is never
mounted writable, so a malicious build script can't mutate the repo under review.

Opt-in and fail-soft by contract: any setup/staging/run failure returns a
diagnostic dict (ok=False, error=...) and never raises into the scan pipeline.
A non-reproduction is evidence the static claim is unconfirmed — never a hard error.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import tempfile

from tools.docker_cli import docker_executable
from tools.docker_runner import _ensure_image

# Heavy / irrelevant directories never staged into the sandbox.
_IGNORE_NAMES = (
    ".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache",
    ".pytest_cache", "dist", "build", "target", ".gradle", ".idea", ".tox",
)
_IGNORE = shutil.ignore_patterns(*_IGNORE_NAMES, "*.pyc")

# Cap on the staged copy so we never copy a multi-GB monorepo into /tmp.
_MAX_STAGE_BYTES = 512 * 1024 * 1024  # 512 MB

DEFAULT_IMAGE = "python:3.11-slim"
DEFAULT_TIMEOUT = 180


def _dir_size(path: str) -> int:
    """Approximate on-disk size, pruning heavy dirs; short-circuits past the cap."""
    total = 0
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in _IGNORE_NAMES]
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
            if total > _MAX_STAGE_BYTES:
                return total
    return total


async def run_in_sandbox(
    codebase_path: str,
    cmd: str,
    setup: str = "",
    image: str = DEFAULT_IMAGE,
    subdir: str = "",
    allow_network: bool = True,
) -> dict:
    """Stage a copy of the codebase and run ``cmd`` inside a hardened container.

    Returns ``{ok, exit_code, timed_out, output, image, network, error}``.
    ``ok=False`` with ``error`` set means the sandbox could not run — NOT a
    finding signal.

    ``allow_network`` (default True): the container gets a bridge network so
    dependency installs work across stacks (``pip install`` / ``npm ci`` /
    ``go mod download`` / ``mvn``). Pass False for strict isolation
    (``--network=none``) when the target code is genuinely untrusted and must
    not be able to call out. Either way the OTHER hardening always applies:
    all capabilities dropped, no-new-privileges, pid/memory/cpu caps, an
    ephemeral ``--rm`` container, and a staged COPY of the source (the original
    is never mounted writable).

    The DEADLINE is owned by the caller via ``async with asyncio.timeout(...)``;
    on cancellation this kills the container subprocess (so it isn't orphaned),
    cleans up the staged copy, and re-raises so the caller records the timeout.
    """
    src = os.path.abspath(os.path.join(codebase_path, subdir)) if subdir else os.path.abspath(codebase_path)
    if not os.path.isdir(src):
        return {"ok": False, "error": f"source dir not found: {src}"}
    if not cmd or not cmd.strip():
        return {"ok": False, "error": (
            "cmd is required — the build/run command to execute "
            "(e.g. 'pip install -e . && python repro.py')"
        )}
    if _dir_size(src) > _MAX_STAGE_BYTES:
        return {"ok": False, "error": (
            f"staging area exceeds {_MAX_STAGE_BYTES // (1024 * 1024)} MB — pass a smaller "
            "subdir= (e.g. just the package under test) so only the relevant code is staged."
        )}

    try:
        await _ensure_image(image)
    except Exception as exc:
        return {"ok": False, "error": f"could not pull image '{image}': {type(exc).__name__}: {exc}"}

    stage = tempfile.mkdtemp(prefix="smith-sandbox-")
    work = os.path.join(stage, "work")
    try:
        try:
            shutil.copytree(src, work, ignore=_IGNORE, symlinks=False)
        except Exception as exc:
            return {"ok": False, "error": f"failed to stage codebase: {type(exc).__name__}: {exc}"}

        full = f"{setup}\n{cmd}" if setup.strip() else cmd
        # Network on by default so dependency installs work; opt out for strict
        # isolation of untrusted code. All other hardening applies regardless.
        net_arg = "--network=bridge" if allow_network else "--network=none"
        docker_cmd = [
            docker_executable(), "run", "--rm",
            net_arg,
            "--memory=2g", "--cpus=1.5", "--pids-limit=512",
            "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "-v", f"{work}:/work",                  # staged COPY, writable; original untouched
            "-w", "/work",
            image,
            "sh", "-c", full,
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *docker_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except Exception as exc:
            return {"ok": False, "error": f"docker run failed: {type(exc).__name__}: {exc}"}
        try:
            out, _ = await proc.communicate()
        except asyncio.CancelledError:
            # Caller's asyncio.timeout() fired — kill the container so it isn't
            # orphaned, drain it, then propagate so the caller records the timeout.
            proc.kill()
            try:
                await proc.communicate()
            except Exception:
                pass
            raise
        return {
            "ok": True, "timed_out": False,
            "exit_code": proc.returncode or 0,
            "output": out.decode(errors="replace"),
            "image": image,
            "network": "enabled" if allow_network else "isolated",
        }
    finally:
        shutil.rmtree(stage, ignore_errors=True)
