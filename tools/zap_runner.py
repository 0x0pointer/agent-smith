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

Output WITHOUT a writable host mount: ZAP runs as its own uid 1000 and will not
start under a different `--user`, so a bind-mounted host output dir would need
loose (world-writable) permissions. Instead we mount only the hook READ-ONLY and
the hook PRINTS the discovered URLs to stdout between marker lines; the runner
captures the container's stdout and parses them out. No chmod, no uid problem.

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
import os
import subprocess
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

# Must match tools/zap/client_spider_hook.py — the markers framing the URL list on stdout.
_URLS_BEGIN = "=== SMITH_ZAP_URLS_BEGIN ==="
_URLS_END = "=== SMITH_ZAP_URLS_END ==="

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


def _parse_urls(stdout: str) -> list[str]:
    """Extract the discovered URLs the hook printed to stdout, between the markers."""
    urls: list[str] = []
    inside = False
    for line in stdout.splitlines():
        s = line.strip()
        if s == _URLS_BEGIN:
            inside = True
            continue
        if s == _URLS_END:
            break
        if inside and s:
            urls.append(s)
    return urls


async def _image_exists() -> bool:
    proc = await asyncio.create_subprocess_exec(
        docker_executable(), "image", "inspect", ZAP_IMAGE,
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
    )
    await proc.wait()
    return proc.returncode == 0


async def ensure_image() -> tuple[bool, str]:
    """Ensure the ZAP image is present; pull it on first use (large, ~3.6 GB).
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
        async with asyncio.timeout(_PULL_TIMEOUT):
            out, _ = await proc.communicate()
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
        {ok, exit_code, urls: [str], note}
    `ok` is True when ZAP RAN (exit 0/1/2), False when it failed to run (exit 3) or
    was unavailable — in which case `note` says why and `urls` is empty. Never raises."""
    ok, msg = await ensure_image()
    if not ok:
        return {"ok": False, "exit_code": None, "urls": [], "note": f"[zap unavailable: {msg}]"}

    cname = f"smith_zap_{uuid.uuid4().hex[:12]}"
    env_flags: list[str] = []
    for k, v in _auth_env(auth).items():
        env_flags += ["-e", f"{k}={v}"]

    cmd = [
        docker_executable(), "run", "--rm", "--name", cname,
        "--add-host=host.docker.internal:host-gateway",
        "--security-opt=no-new-privileges",
        f"--memory={_MEMORY}", f"--shm-size={_SHM}", "--cpus=2",
        # hook mounted READ-ONLY — no writable host mount, so no loose dir perms.
        "-v", f"{os.path.abspath(_HOOK_SRC)}:/zap/hook.py:ro",
        *env_flags,
        ZAP_IMAGE,
        "zap-baseline.py", "-t", _host_rewrite(target),
        "-j", "--client-spider", "-m", str(max(1, minutes)),
        "--hook=/zap/hook.py",
        "-I",   # don't fail the run on WARN-level alerts; we read the exit code only for RUN/FAIL
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        )
    except Exception as exc:  # pragma: no cover - defensive
        return {"ok": False, "exit_code": None, "urls": [], "note": f"[zap could not start: {exc}]"}

    try:
        try:
            async with asyncio.timeout(timeout):
                out, _ = await proc.communicate()
        except asyncio.TimeoutError:
            _reap(cname)
            proc.kill()
            try:
                async with asyncio.timeout(10):
                    await proc.communicate()
            except Exception:
                pass
            return {"ok": False, "exit_code": None, "urls": [],
                    "note": f"[zap client-spider timed out after {timeout}s]"}

        rc = proc.returncode or 0
        stdout = out.decode(errors="replace")
        urls = _parse_urls(stdout)
        if rc == 3:
            tail = stdout.strip()[-800:]
            return {"ok": False, "exit_code": 3, "urls": urls,
                    "note": f"[zap client-spider FAILED to run (exit 3) — ZAP did not start / target "
                            f"unreachable]\n{tail}"}
        return {"ok": True, "exit_code": rc, "urls": urls,
                "note": f"[zap client-spider ran (exit {rc}) — {len(urls)} URL(s) discovered"
                        + (", authenticated" if auth else ", black-box") + "]"}
    finally:
        _reap(cname)
