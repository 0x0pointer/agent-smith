"""
Shared imports, module state, and tiny helpers for the scan_tools package.

Everything the individual handler groups (net / spider / code / ai / mobile /
exploit) need in common lives here so the groups don't import each other for
plumbing.
"""
import asyncio
import shlex

from core import cost as cost_tracker
from core import logger as log
from core import session as scan_session
from mcp_server._app import mcp, _clip, _ensure_dict, _record, _run


def _strip_scheme(target: str) -> str:
    """Strip the URL scheme + trailing path — models often pass URLs to host-only tools."""
    from urllib.parse import urlparse
    parsed = urlparse(target)
    if parsed.scheme and parsed.hostname:
        return parsed.hostname
    return target


def _kali_target_url(target: str) -> str:
    """Rewrite localhost/127.0.0.1 → host.docker.internal so a tool INSIDE the
    Kali container can reach a target on the host.

    kali_runner.exec_command already does this rewrite on literal command text,
    but AI-tool config files are base64-staged into the container (opaque to
    that text rewrite), so we apply it to the URL here before embedding it.
    """
    from tools.kali_runner import _host_rewrite
    return _host_rewrite(target)


def _stage_file_cmd(content: str, path: str) -> str:
    """Return a shell snippet that writes `content` to `path` inside the Kali
    container via base64 — avoids heredoc/quoting hazards through the upstream
    `bash -c` wrapper, and keeps the (possibly localhost-rewritten) URL intact.
    """
    import base64
    b64 = base64.b64encode(content.encode()).decode()
    return f"printf %s {shlex.quote(b64)} | base64 -d > {shlex.quote(path)}"


def _kali_scratch_dir() -> str:
    """A private, per-invocation scratch dir inside the (single-tenant, ephemeral)
    Kali container, under root's home rather than a world-writable temp dir.

    Avoids the predictable /tmp symlink class (Sonar python:S5443) AND prevents two
    concurrent AI scans from clobbering each other's staged config files. /root is
    writable in the kali image (garak already writes its reports under /root).
    """
    import uuid
    return f"/root/.cache/agent-smith/{uuid.uuid4().hex[:12]}"


# Headers a model can pass via options={"headers": {...}} to authenticate an AI
# scan; merged on top of a JSON Content-Type default.
def _ai_headers(options: dict) -> dict:
    hdrs = {"Content-Type": "application/json"}
    extra = options.get("headers") or {}
    if isinstance(extra, dict):
        hdrs.update({str(k): str(v) for k, v in extra.items()})
    return hdrs


def _ai_auth_headers(options: dict) -> list[str]:
    """Build a list of 'Name: value' header strings from options for AI tools."""
    headers = []
    for k, v in (options.get("headers") or {}).items():
        headers.append(f"{k}: {v}")
    if options.get("auth_header"):
        headers.append(str(options["auth_header"]))
    return headers


# Signals that unambiguously mean the spider tool failed to execute at all.
_SPIDER_HARD_FAIL_SIGNALS = ("command not found", "exec: ", "no such file or directory")


def _spider_succeeded(raw: str) -> bool:
    """Return True if the spider tool executed (even finding nothing). False = failed to run."""
    if not raw or not raw.strip():
        return False
    low = raw.lower()
    return not any(sig in low for sig in _SPIDER_HARD_FAIL_SIGNALS)
