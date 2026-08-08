"""
MobSF container lifecycle + REST client
=======================================
Manages a persistent Mobile-Security-Framework container and drives its static
analysis over the REST API:
  - image / container existence checks
  - start (with health-poll — MobSF's Django app is slow to boot)
  - analyze(path): upload the APK/IPA/APPX/zip bytes, run the scan, fetch the
    structured JSON report
  - stop

Unlike the Kali/Metasploit runners (which shell-exec over an HTTP command API),
MobSF is driven by its own REST endpoints and needs the BINARY inside it. We
stream the file bytes as a multipart upload (POST /api/v1/upload) rather than
bind-mounting — the container never sees the host FS. Every call carries the
API key (MobSF returns 401 without it); we inject a fixed key via `-e
MOBSF_API_KEY=` at run time and send the same value as the Authorization header.
"""
from __future__ import annotations

import asyncio
import os

from core import paths as _paths
from tools.docker_cli import docker_executable

# Use the official MobSF image directly — we don't customise it, so there's no
# wrapper Dockerfile to build (and none whose base-image root user to flag).
# Auto-pulled on first use. Pin — update explicitly (and CVE-scan the new tag).
MOBSF_IMAGE     = "opensecurity/mobile-security-framework-mobsf:v4.4.6"
MOBSF_CONTAINER = "pentest-mobsf"
MOBSF_PORT      = 5003          # host port → container port 8000
MOBSF_API       = f"http://localhost:{MOBSF_PORT}"

# API key: injected into the container at run time (-e) and sent on every REST
# call. Overridable via SMITH_MOBSF_API_KEY. When unset, a RANDOM key is minted
# per install and persisted 0600 to logs/mobsf.key (gitignored) — so it survives
# process restarts and stays in sync with a reused container, without shipping a
# hardcoded, git-committed default secret (which any repo reader would know).
def _resolve_api_key() -> str:
    env = os.environ.get("SMITH_MOBSF_API_KEY")
    if env:
        return env
    import secrets

    key_file = _paths.LOGS_DIR / "mobsf.key"
    try:
        existing = key_file.read_text().strip()
        if existing:
            return existing
    except OSError:
        pass
    key = secrets.token_hex(24)
    try:
        _paths.LOGS_DIR.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(key_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, key.encode())
        finally:
            os.close(fd)
    except OSError:
        pass  # fall back to the in-memory key for this process
    return key


API_KEY = _resolve_api_key()

# Static scans of a large APK/IPA can take minutes — give the scan call plenty of
# headroom. The MCP client transport timeout must exceed this.
SCAN_TIMEOUT = int(os.environ.get("SMITH_MOBSF_SCAN_TIMEOUT", "600"))

_start_lock = asyncio.Lock()


def _read_bytes(path: str) -> bytes:
    """Blocking file read — kept a plain sync function so async callers run it via
    asyncio.to_thread (no blocking open() inside an async body — S7493)."""
    with open(path, "rb") as fh:
        return fh.read()


# ---------------------------------------------------------------------------
# State checks
# ---------------------------------------------------------------------------

async def image_exists() -> bool:
    proc = await asyncio.create_subprocess_exec(
        docker_executable(), "image", "inspect", MOBSF_IMAGE,
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
    )
    await proc.wait()
    return proc.returncode == 0


async def container_running() -> bool:
    proc = await asyncio.create_subprocess_exec(
        docker_executable(), "inspect", "--format={{.State.Running}}", MOBSF_CONTAINER,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await proc.communicate()
    return stdout.strip() == b"true"


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

async def ensure_running() -> tuple[bool, str]:
    """Start the MobSF container if it isn't running yet. Returns (ok, message)."""
    import aiohttp

    async with _start_lock:
        if await container_running():
            return True, "already running"
        if not await image_exists():
            # Public image — pull it (large; no build step). docker run would
            # auto-pull too, but an explicit pull keeps the health-poll honest.
            pull = await asyncio.create_subprocess_exec(
                docker_executable(), "pull", MOBSF_IMAGE,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
            )
            _, perr = await pull.communicate()
            if pull.returncode != 0:
                return False, (
                    f"could not pull {MOBSF_IMAGE}: {perr.decode().strip()} — "
                    f"check Docker/network, or run: docker pull {MOBSF_IMAGE}"
                )
        proc = await asyncio.create_subprocess_exec(
            docker_executable(), "run", "-d",
            "--name", MOBSF_CONTAINER,
            "-p", f"{MOBSF_PORT}:8000",
            "-e", f"MOBSF_API_KEY={API_KEY}",
            "--rm",
            MOBSF_IMAGE,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            return False, f"docker run failed: {stderr.decode().strip()}"

    # Poll the MobSF home page until Django is serving (up to 90 s — slow boot).
    for _ in range(90):
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(MOBSF_API + "/", timeout=aiohttp.ClientTimeout(total=2)) as r:
                    if r.status == 200:
                        return True, "started"
        except Exception:
            pass
        await asyncio.sleep(1)
    return False, "container started but home page never responded — check: docker logs pentest-mobsf"


async def stop() -> str:
    proc = await asyncio.create_subprocess_exec(
        docker_executable(), "stop", MOBSF_CONTAINER,
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    if proc.returncode == 0:
        return f"Container '{MOBSF_CONTAINER}' stopped."
    return f"Could not stop container: {stderr.decode().strip()}"


# ---------------------------------------------------------------------------
# Analysis (upload → scan → report)
# ---------------------------------------------------------------------------

def _headers() -> dict:
    return {"Authorization": API_KEY}


async def analyze(file_path: str) -> dict:
    """Upload a mobile binary, run the static scan, and return the JSON report.

    Returns {ok, hash, scan_type, file_name, report} on success, or
    {ok: False, error} on any failure.
    """
    import aiohttp

    if not os.path.isfile(file_path):
        return {"ok": False, "error": f"file not found: {file_path}"}

    ok, msg = await ensure_running()
    if not ok:
        return {"ok": False, "error": msg}

    try:
        # Read via a thread (module-level sync helper) so this async function
        # never blocks the event loop on file I/O (S7493).
        file_bytes = await asyncio.to_thread(_read_bytes, file_path)
    except OSError as exc:
        return {"ok": False, "error": f"could not read {file_path}: {exc}"}

    try:
        async with aiohttp.ClientSession(headers=_headers()) as session:
            # 1. upload the bytes (multipart) — the container never touches the host FS
            form = aiohttp.FormData()
            form.add_field("file", file_bytes,
                           filename=os.path.basename(file_path),
                           content_type="application/octet-stream")
            async with session.post(MOBSF_API + "/api/v1/upload", data=form,
                                    timeout=aiohttp.ClientTimeout(total=120)) as r:
                if r.status == 401:
                    return {"ok": False, "error": "MobSF 401 — API key rejected"}
                up = await r.json()
            file_hash = up.get("hash")
            if not file_hash:
                return {"ok": False, "error": f"upload failed: {up}"}

            # 2. run the scan (blocking; can take minutes on a large binary)
            async with session.post(MOBSF_API + "/api/v1/scan",
                                    data={"hash": file_hash},
                                    timeout=aiohttp.ClientTimeout(total=SCAN_TIMEOUT)) as r:
                await r.read()  # ensure the scan completes before we fetch the report

            # 3. fetch the structured JSON report
            async with session.post(MOBSF_API + "/api/v1/report_json",
                                    data={"hash": file_hash},
                                    timeout=aiohttp.ClientTimeout(total=120)) as r:
                report = await r.json()

        return {"ok": True, "hash": file_hash,
                "scan_type": up.get("scan_type"), "file_name": up.get("file_name"),
                "report": report}
    except Exception as exc:  # noqa: BLE001 — surface any transport/JSON error to the caller
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def summarize(report: dict) -> dict:
    """Condense a MobSF report to the MASVS-relevant summary (the `appsec` section
    plus headline metadata) — keeps the huge raw report out of the context window."""
    appsec = report.get("appsec", {}) if isinstance(report, dict) else {}
    buckets = {k: len(appsec.get(k, []) or []) for k in ("high", "warning", "info", "secure", "hotspot")}
    return {
        "app": report.get("app_name") or report.get("file_name"),
        "package": report.get("package_name") or report.get("bundle_id"),
        "security_score": (report.get("appsec", {}) or {}).get("security_score"),
        "finding_counts": buckets,
        "high": appsec.get("high", []),
        "warning": appsec.get("warning", []),
    }
