"""
Garak runner — standalone ephemeral container
==============================================
Runs NVIDIA Garak's REST-generator probes in a dedicated `pentest-agent/garak`
image (built from tools/garak/Dockerfile), one ephemeral `docker run --rm` per
scan. Moved out of the Kali image so Kali stays lean and garak is versioned
independently.

Why a dedicated runner (not the generic Tool/`_run` path):
  * garak needs a config file IN (the REST-generator JSON) and a report file OUT
    (report.jsonl) — the stdout-only Tool path can't do that.
  * a per-call /work bind mount carries the config in and the report out.
  * a PERSISTENT model/data cache is bind-mounted so garak's HuggingFace model
    downloads survive across ephemeral runs instead of re-downloading each time.
  * memory is raised above the generic 2 GB cap (torch/ML detectors need it).

Hardening is preserved: --cap-drop=ALL, --security-opt=no-new-privileges,
--pids-limit, --rm.
"""
from __future__ import annotations

import asyncio
import json
import os
import shlex
import shutil
import tempfile
from pathlib import Path

from core import logger as log
from core import paths as _paths
from tools.docker_cli import docker_executable

GARAK_IMAGE = "pentest-agent/garak"
_BUILD_CONTEXT = str(Path(__file__).resolve().parent / "garak")
_BUILD_TIMEOUT = int(os.environ.get("SMITH_GARAK_BUILD_TIMEOUT", "1800"))  # torch build is slow
_MEMORY = os.environ.get("SMITH_GARAK_MEMORY", "4g")   # ML detectors need > the generic 2g cap

# AI keys garak's generators/scorers may use. "SRC:DST" forwards SRC's value
# under the name DST (same convention as _app._run / kali_runner._forward_ai_keys):
# the anthropic AI-testing key lives in .env as AITEST_ANTHROPIC_API_KEY so an
# interactive `claude` can't bill it, and is re-exposed here as ANTHROPIC_API_KEY.
_AI_KEY_SPECS = [
    "OPENAI_API_KEY",
    "AITEST_ANTHROPIC_API_KEY:ANTHROPIC_API_KEY",
    "ANTHROPIC_API_KEY",
    "AZURE_OPENAI_API_KEY",
]


def _ai_env_flags() -> list[str]:
    flags: list[str] = []
    seen: set[str] = set()
    for spec in _AI_KEY_SPECS:
        src, _, dst = spec.partition(":")
        dst = dst or src
        if src in os.environ and dst not in seen:
            flags += ["-e", f"{dst}={os.environ[src]}"]
            seen.add(dst)
    return flags


def _cache_dir() -> str:
    """Host dir bind-mounted at /root/.cache so garak's HuggingFace model and
    dataset downloads persist across ephemeral runs (avoids re-downloading)."""
    d = _paths.LOGS_DIR.parent / ".cache" / "garak"
    d.mkdir(parents=True, exist_ok=True)
    return str(d)


async def image_exists() -> bool:
    proc = await asyncio.create_subprocess_exec(
        docker_executable(), "image", "inspect", GARAK_IMAGE,
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
    )
    await proc.communicate()
    return proc.returncode == 0


async def ensure_image() -> tuple[bool, str]:
    """Ensure the garak image exists; auto-build from tools/garak/ on first use.

    Unlike kali/metasploit (built by the installer, runner only checks), garak
    has no persistent container to start — so first use builds the image if it's
    absent. Disable with SMITH_GARAK_AUTOBUILD=0 (then it errors with the manual
    build command instead)."""
    if await image_exists():
        return True, "present"
    if os.environ.get("SMITH_GARAK_AUTOBUILD", "1") == "0":
        return False, (f"Image '{GARAK_IMAGE}' not found and autobuild is disabled. "
                       f"Build it: docker build -t {GARAK_IMAGE} ./tools/garak/")
    log.note(f"garak: image '{GARAK_IMAGE}' not found — building from {_BUILD_CONTEXT} "
             f"(first use; torch download, several minutes)")
    proc = await asyncio.create_subprocess_exec(
        docker_executable(), "build", "-t", GARAK_IMAGE, _BUILD_CONTEXT,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=_BUILD_TIMEOUT)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return False, (f"Timed out building '{GARAK_IMAGE}' after {_BUILD_TIMEOUT}s. "
                       f"Build manually: docker build -t {GARAK_IMAGE} ./tools/garak/")
    if proc.returncode != 0:
        tail = out.decode(errors="replace")[-1000:]
        return False, (f"Failed to build '{GARAK_IMAGE}': …{tail}. "
                       f"Build manually: docker build -t {GARAK_IMAGE} ./tools/garak/")
    log.note(f"garak: image '{GARAK_IMAGE}' built OK")
    return True, "built"


async def run_garak(rest_config: dict, probes: str, flags: str = "", timeout: int = 900) -> str:
    """Run garak REST-generator probes ephemerally.

    Writes `rest_config` into a per-call /work mount, runs the selected probes,
    and tails the structured report.jsonl back after a marker (the AI summarizer
    parses from that marker). Returns raw stdout; a build/availability failure is
    returned as a bracketed message so the caller degrades gracefully.
    """
    ok, msg = await ensure_image()
    if not ok:
        return (f"[garak unavailable: {msg}] "
                f"AI red-team can still proceed via the transform() payload tool + manual http().")

    workdir = tempfile.mkdtemp(prefix="smith_garak_")
    try:
        (Path(workdir) / "garak_rest.json").write_text(json.dumps(rest_config), encoding="utf-8")
        garak_cmd = (
            f"garak --target_type rest -G /work/garak_rest.json "
            f"--probes {shlex.quote(probes)} --report_prefix /work/run"
        )
        if flags:
            garak_cmd += f" {shlex.join(shlex.split(flags))}"
        garak_cmd += "; echo '=== GARAK REPORT JSONL ==='; tail -n 300 /work/run.report.jsonl 2>/dev/null"

        cmd = [
            docker_executable(), "run", "--rm",
            # Bridge network + host-gateway alias so a target on the host is
            # reachable as host.docker.internal on BOTH macOS and Linux (the
            # handler rewrites localhost/127.0.0.1 → host.docker.internal).
            # --network=host does NOT reach host localhost on Docker Desktop
            # (macOS), so we don't use it here.
            "--add-host=host.docker.internal:host-gateway",
            "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=512",
            f"--memory={_MEMORY}", "--cpus=2",
            "-v", f"{os.path.abspath(workdir)}:/work",
            "-v", f"{_cache_dir()}:/root/.cache",
            *_ai_env_flags(),
            GARAK_IMAGE, "sh", "-c", garak_cmd,
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            raise
        return stdout.decode(errors="replace") or stderr.decode(errors="replace")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
