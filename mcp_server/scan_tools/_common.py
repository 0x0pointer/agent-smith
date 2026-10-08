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


# Headers a model can pass via options={"headers": {...}} to authenticate an AI
# scan; merged on top of a JSON Content-Type default. (The kali-staging helpers
# that used to live here — _kali_target_url / _stage_file_cmd / _kali_scratch_dir
# — went away when garak moved to its own standalone image; garak now rewrites
# the target URL itself via tools.kali_runner._host_rewrite and stages its
# config into a /work mount.)
def _ai_headers(options: dict) -> dict:
    hdrs = {"Content-Type": "application/json"}
    if options.get("headers_from") == "known_assets":
        # Reuse the scan's freshest JWT + session cookies instead of a pasted dict.
        from mcp_server.redteam.transport import known_asset_headers
        hdrs.update(known_asset_headers())
    extra = options.get("headers") or {}
    if isinstance(extra, dict):
        hdrs.update({str(k): str(v) for k, v in extra.items()})
    return hdrs


# Signals that unambiguously mean the spider tool failed to execute at all.
_SPIDER_HARD_FAIL_SIGNALS = ("command not found", "exec: ", "no such file or directory")


def _spider_succeeded(raw: str) -> bool:
    """Return True if the spider tool executed (even finding nothing). False = failed to run."""
    if not raw or not raw.strip():
        return False
    low = raw.lower()
    return not any(sig in low for sig in _SPIDER_HARD_FAIL_SIGNALS)
