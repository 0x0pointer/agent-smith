"""
ZAP Client Spider runner — standalone ephemeral container (issue #184)
======================================================================
Runs the OWASP ZAP **Client Spider** (ZAP 2.16+) for endpoint DISCOVERY via the
official ZAP image, replacing the discontinued `zap-cli` AJAX-spider path.

Why the official image (not Kali / the generic Tool path):
  * the Client Spider drives a REAL Firefox with ZAP's browser extension — only the
    full `ghcr.io/zaproxy/zaproxy:stable` image ships Firefox + the Client Side
    Integration add-on (`:bare` cannot run it).
  * `zap-baseline.py` is PASSIVE — it spiders (now via the Client Spider with
    `-j --client-spider`) and runs passive rules only; it fires NO active-attack
    payloads, so it adds no scan noise. We use it purely for discovery.
  * a per-call /zap/wrk bind mount carries the hook IN and the discovered-URL list
    + JSON report OUT (the stdout-only Tool path can't do that).

Two-pass usage (driven by the spider handler):
  * black-box pass: run_client_spider(target)                 — anonymous crawl.
  * authenticated pass: run_client_spider(target, auth=...)   — session injected
    into every request via a Replacer REQ_HEADER rule (see tools/zap/client_spider_hook.py),
    so the DOM-aware spider reaches the app behind the login.

Exit codes (zap-baseline.py): 0 = ran, no FAIL alerts; 1 = ran, FAIL alert(s);
2 = ran, WARN only; 3 = FAILED TO RUN (ZAP didn't start / target unreachable).
So {0,1,2} = "ran", 3 = failure.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from core import logger as log
from tools.docker_cli import docker_executable

# Official ZAP image. Pinned by digest for reproducible, supply-chain-safe runs
# (override with SMITH_ZAP_IMAGE). :stable ships Firefox + the Client Side
# Integration add-on needed for the Client Spider; :bare does not.
ZAP_IMAGE = os.environ.get(
    "SMITH_ZAP_IMAGE",
    "ghcr.io/zaproxy/zaproxy@sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef",
)
_HOOK_SRC = Path(__file__).resolve().parent / "zap" / "client_spider_hook.py"
_MEMORY = os.environ.get("SMITH_ZAP_MEMORY", "4g")      # ZAP JVM + a real Firefox
_SHM = os.environ.get("SMITH_ZAP_SHM", "2g")            # Firefox crashes on a tiny /dev/shm
_PULL_TIMEOUT = int(os.environ.get("SMITH_ZAP_PULL_TIMEOUT", "600"))

_image_ready = False


def _host_rewrite(url: str) -> str:
    """localhost/127.0.0.1 → host.docker.internal so a target on the host is
    reachable from the container (Docker Desktop can't reach host-localhost via
    --network=host; we add --add-host=host.docker.internal:host-gateway instead)."""
    return (url.replace("://localhost", "://host.docker.internal")
               .replace("://127.0.0.1", "://host.docker.internal"))


def _auth_env(auth: dict | None) -> dict[str, str]:
    """Turn a {headers, cookies} auth dict (from spider._spider_discovery_auth) into
    the env the hook reads: SMITH_ZAP_AUTH_HEADER (the Authorization value) and
    SMITH_ZAP_AUTH_COOKIE (a `name=value; ...` cookie string)."""
    env: dict[str, str] = {}
    if not auth:
        return env
    hdr = (auth.get("headers") or {}).get("Authorization")
    if hdr:
        env["SMITH_ZAP_AUTH_HEADER"] = str(hdr)
    cookies = auth.get("cookies") or {}
    if cookies:
        env["SMITH_ZAP_AUTH_COOKIE"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    return env


async def _image_exists() -> bool:
    proc = await asyncio.create_subprocess_exec(
        docker_executable(), "image", "inspect", ZAP_IMAGE,
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
    )
    await proc.wait()
    return proc.returncode == 0


async def ensure_image() -> tuple[bool, str]:
    """Ensure the ZAP image is present; pull it on first use (large, ~1.8 GB).
    Fail-soft: returns (False, reason) so the caller degrades instead of raising."""
    global _image_ready
    if _image_ready or await _image_exists():
        _image_ready = True
        return True, "present"
    log.note(f"zap: image '{ZAP_IMAGE}' not found — pulling (large, first use only)")
    proc = await asyncio.create_subprocess_exec(
        docker_executable(), "pull", ZAP_IMAGE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=_PULL_TIMEOUT)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return False, f"timed out pulling '{ZAP_IMAGE}' after {_PULL_TIMEOUT}s"
    if proc.returncode != 0:
        return False, f"failed to pull '{ZAP_IMAGE}': {out.decode(errors='replace').strip()[-300:]}"
    _image_ready = True
    return True, "pulled"


def _reap(cname: str) -> None:
    try:
        subprocess.Popen([docker_executable(), "kill", cname],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


async def run_client_spider(target: str, minutes: int = 5, auth: dict | None = None,
                            timeout: int = 1800) -> dict:
    """Run the ZAP Client Spider against `target` for up to `minutes`, optionally
    authenticated. Returns a dict:
        {ok, exit_code, urls: [str], alert_count, note}
    `ok` is True when ZAP RAN (exit 0/1/2), False when it failed to run (exit 3) or
    was unavailable — in which case `note` says why and `urls` is empty. Never raises."""
    ok, msg = await ensure_image()
    if not ok:
        return {"ok": False, "exit_code": None, "urls": [], "alert_count": 0,
                "note": f"[zap unavailable: {msg}]"}

    workdir = tempfile.mkdtemp(prefix="smith_zap_")
    cname = f"smith_zap_{uuid.uuid4().hex[:12]}"
    try:
        # The container runs as uid 1000 (user `zap`) and writes reports to /zap/wrk —
        # make the host mount world-writable so those writes land on the host.
        os.chmod(workdir, 0o777)
        shutil.copy(_HOOK_SRC, Path(workdir) / "hook.py")

        safe_target = _host_rewrite(target)
        env_flags: list[str] = []
        for k, v in _auth_env(auth).items():
            env_flags += ["-e", f"{k}={v}"]

        cmd = [
            docker_executable(), "run", "--rm", "--name", cname,
            "--add-host=host.docker.internal:host-gateway",
            "--security-opt=no-new-privileges",
            f"--memory={_MEMORY}", f"--shm-size={_SHM}", "--cpus=2",
            "-v", f"{os.path.abspath(workdir)}:/zap/wrk:rw",
            *env_flags,
            ZAP_IMAGE,
            "zap-baseline.py", "-t", safe_target,
            "-j", "--client-spider", "-m", str(max(1, minutes)),
            "-J", "report.json", "--hook=/zap/wrk/hook.py",
            "-I",   # do not return a non-zero exit just because of warnings (we read exit for RUN/FAIL only)
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        )
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            _reap(cname)
            proc.kill()
            try:
                await asyncio.wait_for(proc.communicate(), timeout=10)
            except Exception:
                pass
            urls = _read_urls(workdir)   # partial crawl may still be on disk
            return {"ok": bool(urls), "exit_code": None, "urls": urls, "alert_count": 0,
                    "note": f"[zap client-spider timed out after {timeout}s — {len(urls)} URL(s) salvaged]"}

        rc = proc.returncode or 0
        urls = _read_urls(workdir)
        alert_count = _read_alert_count(workdir)
        stdout = out.decode(errors="replace")
        if rc == 3:
            tail = stdout.strip()[-800:]
            return {"ok": False, "exit_code": 3, "urls": urls, "alert_count": alert_count,
                    "note": f"[zap client-spider FAILED to run (exit 3) — ZAP did not start / target "
                            f"unreachable]\n{tail}"}
        return {"ok": True, "exit_code": rc, "urls": urls, "alert_count": alert_count,
                "note": f"[zap client-spider ran (exit {rc}) — {len(urls)} URL(s) discovered"
                        + (", authenticated" if auth else ", black-box") + "]"}
    finally:
        _reap(cname)
        shutil.rmtree(workdir, ignore_errors=True)


def _read_urls(workdir: str) -> list[str]:
    path = Path(workdir) / "urls.txt"
    try:
        return [u.strip() for u in path.read_text(encoding="utf-8", errors="replace").splitlines() if u.strip()]
    except Exception:
        return []


def _read_alert_count(workdir: str) -> int:
    """Count passive-scan alerts in the JSON report (informational only — we do NOT
    file them as findings here; the spider's job is discovery)."""
    path = Path(workdir) / "report.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return 0
    return sum(len(site.get("alerts", []) or []) for site in (data.get("site", []) or []))
