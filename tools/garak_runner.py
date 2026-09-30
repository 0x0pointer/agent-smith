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
import re
import shlex
import shutil
import tempfile
import uuid
from pathlib import Path

from core import logger as log
from core import paths as _paths
from tools.docker_cli import docker_executable

GARAK_IMAGE = "pentest-agent/garak"
_BUILD_CONTEXT = str(Path(__file__).resolve().parent / "garak")
_BUILD_TIMEOUT = int(os.environ.get("SMITH_GARAK_BUILD_TIMEOUT", "1800"))  # torch build is slow
_MEMORY = os.environ.get("SMITH_GARAK_MEMORY", "4g")   # ML detectors need > the generic 2g cap
# garak's REST generator supports request parallelism; use it so a thorough probe
# set finishes inside the tool timeout instead of overrunning it (1 disables).
_PARALLEL = max(1, int(os.environ.get("SMITH_GARAK_PARALLEL", "8")))
# How often (seconds) to push the growing report to the dashboard during a run.
_PROGRESS_SECS = max(3, int(os.environ.get("SMITH_GARAK_PROGRESS_SECS", "15")))

_EVAL_RE = re.compile(r'"entry_type":\s*"eval"')

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


_PROBE_LIST_CACHE: dict = {}   # per-process cache of `garak --list_probes` raw output


async def list_probes() -> str:
    """Raw `garak --list_probes` output from the image, for probe-name validation
    (garak 0.15 ABORTS the whole run on any unknown probe). Cached per process;
    returns '' if the image is unavailable or the call fails (caller then skips
    validation and runs as-is)."""
    if "raw" in _PROBE_LIST_CACHE:
        return _PROBE_LIST_CACHE["raw"]
    ok, _ = await ensure_image()
    if not ok:
        _PROBE_LIST_CACHE["raw"] = ""
        return ""
    raw = ""
    try:
        proc = await asyncio.create_subprocess_exec(
            docker_executable(), "run", "--rm", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", GARAK_IMAGE,
            "sh", "-c", "garak --list_probes",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        raw = out.decode(errors="replace")
    except Exception:
        raw = ""
    _PROBE_LIST_CACHE["raw"] = raw
    return raw


def _report_block(workdir: str, note: str = "") -> str:
    """Build the '=== GARAK REPORT JSONL ===' block from the HOST side of the /work
    mount — every eval line plus a short tail — mirroring the in-container grep+tail.
    So a PARTIAL (mid-run) or a TIMED-OUT report parses exactly like a completed run
    through record_garak_from_raw / _autofile_garak_findings. Reads the whole file, so
    callers on the event loop MUST offload it to a thread (asyncio.to_thread)."""
    try:
        text = (Path(workdir) / "run.report.jsonl").read_text(errors="replace")
    except Exception:
        text = ""
    lines = text.splitlines()
    evals = [ln for ln in lines if _EVAL_RE.search(ln)]
    parts = ([note] if note else []) + ["=== GARAK REPORT JSONL ==="] + evals + lines[-20:]
    return "\n".join(parts)


def _read_new_evals(path: str, state: dict) -> str:
    """INCREMENTAL, thread-safe report tail for live streaming: read only the bytes
    appended since the last call (state['pos']), accumulate any eval lines into
    state['evals'], and return the current report block — or '' if nothing new.

    Reading only the delta (not re-reading the whole growing report every tick) and
    running this in a worker thread is what keeps a large, actively-written report
    from starving the event loop — which previously delayed run_garak's own timeout
    so a run could never be reaped. state = {'pos': int, 'carry': bytes, 'evals': list}."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return ""
    if size <= state["pos"]:
        return ""                              # nothing appended (or truncated/rotated)
    try:
        with open(path, "rb") as f:
            f.seek(state["pos"])
            chunk = f.read()
            state["pos"] = f.tell()
    except OSError:
        return ""
    data = state["carry"] + chunk
    nl = data.rfind(b"\n")
    if nl == -1:                               # no complete line yet — keep buffering
        state["carry"] = data
        return ""
    complete, state["carry"] = data[:nl], data[nl + 1:]
    new = [ln for ln in complete.decode("utf-8", "replace").split("\n") if _EVAL_RE.search(ln)]
    if not new:
        return ""
    state["evals"].extend(new)
    return "=== GARAK REPORT JSONL ===\n" + "\n".join(state["evals"])


def _build_garak_cmd(probes: str, flags: str) -> str:
    """The in-container `sh -c` string: run the probes, then append the report block."""
    cmd = (f"garak --target_type rest -G /work/garak_rest.json "
           f"--probes {shlex.quote(probes)} --report_prefix /work/run")
    if _PARALLEL > 1:                       # REST parallelism → thorough set fits the timeout
        cmd += f" --parallel_attempts {_PARALLEL}"
    if flags:
        cmd += f" {shlex.join(shlex.split(flags))}"
    # Extract EVERY eval entry with grep (regardless of report size) then a short
    # tail for human context. A plain `tail -n N` silently DROPS the eval lines on
    # large runs — the many attempt lines push the (few) eval lines out of the tail
    # window, which then reads as "0 eval entries / model resisted".
    cmd += (
        "; echo '=== GARAK REPORT JSONL ==='"
        "; grep -E '\"entry_type\": ?\"eval\"' /work/run.report.jsonl 2>/dev/null"
        "; tail -n 20 /work/run.report.jsonl 2>/dev/null"
    )
    return cmd


async def _kill_container(name: str) -> None:
    """Best-effort `docker kill` so a timed-out run doesn't orphan a container that
    keeps probing the target and writing a report nobody reads (killing the local
    `docker run` client alone does NOT stop the container the daemon started)."""
    try:
        p = await asyncio.create_subprocess_exec(
            docker_executable(), "kill", name,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        await asyncio.wait_for(p.communicate(), timeout=15)
    except Exception:
        pass


async def _stream_progress(workdir: str, on_progress, interval: int) -> None:
    """Push newly-appended eval rows to `on_progress` every `interval`s so the AI
    Red Team dashboard fills in probe-by-probe instead of only when the run ends.

    The file read/parse runs in a worker THREAD (asyncio.to_thread) and is
    INCREMENTAL (only the delta since last tick), so a large, actively-written
    report can never block the event loop — which is what previously delayed
    run_garak's own timeout and left runs un-reaped. Cancelled when the run exits."""
    path = str(Path(workdir) / "run.report.jsonl")
    state = {"pos": 0, "carry": b"", "evals": []}
    try:
        while True:
            await asyncio.sleep(interval)
            block = await asyncio.to_thread(_read_new_evals, path, state)
            if block:
                try:
                    on_progress(block)
                except Exception:
                    pass
    except asyncio.CancelledError:
        raise


async def run_garak(rest_config: dict, probes: str, flags: str = "", timeout: int = 900,
                    on_progress=None) -> str:
    """Run garak REST-generator probes ephemerally.

    Writes `rest_config` into a per-call /work mount, runs the selected probes, and
    returns garak's stdout with the structured report appended after a marker (the
    AI summarizer parses from that marker). A build/availability failure is returned
    as a bracketed message so the caller degrades gracefully.

    on_progress: optional callback(str) invoked every _PROGRESS_SECS with the current
    report block, so the dashboard updates DURING the run, not only at the end. On
    timeout the container is REAPED and the PARTIAL report is RETURNED (not raised),
    so partial results still reach the model and the dashboard.
    """
    ok, msg = await ensure_image()
    if not ok:
        return (f"[garak unavailable: {msg}] "
                f"AI red-team can still proceed via the transform() payload tool + manual http().")

    workdir = tempfile.mkdtemp(prefix="smith_garak_")
    cname = f"smith_garak_{uuid.uuid4().hex[:12]}"
    progress_task = None
    try:
        (Path(workdir) / "garak_rest.json").write_text(json.dumps(rest_config), encoding="utf-8")
        cmd = [
            docker_executable(), "run", "--rm", "--name", cname,
            # host-gateway alias so a target on the host is reachable as
            # host.docker.internal on macOS + Linux (handler rewrites localhost →
            # host.docker.internal; --network=host can't reach host localhost on
            # Docker Desktop, so we don't use it).
            "--add-host=host.docker.internal:host-gateway",
            "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=512",
            f"--memory={_MEMORY}", "--cpus=2",
            "-v", f"{os.path.abspath(workdir)}:/work",
            "-v", f"{_cache_dir()}:/root/.cache",
            *_ai_env_flags(),
            GARAK_IMAGE, "sh", "-c", _build_garak_cmd(probes, flags),
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        if on_progress:
            progress_task = asyncio.create_task(_stream_progress(workdir, on_progress, _PROGRESS_SECS))
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            await _kill_container(cname)          # reap the orphan before we give up on it
            proc.kill()
            try:
                await asyncio.wait_for(proc.communicate(), timeout=10)
            except Exception:
                pass
            note = f"[garak timed out after {timeout}s — partial results below]"
            return await asyncio.to_thread(_report_block, workdir, note)
        return stdout.decode(errors="replace") or stderr.decode(errors="replace")
    finally:
        if progress_task:
            progress_task.cancel()
            try:
                await progress_task
            except BaseException:
                pass
        shutil.rmtree(workdir, ignore_errors=True)
