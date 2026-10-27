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
    """Headers for the garak/LLM transports: Content-Type + auth sourced from
    known_assets when options ask (headers_from / auth_profile), under any explicit
    options["headers"] (issue #247). Garak runs out-of-process so it can't hot-refresh
    a rotating cookie mid-run, but it is seeded with the latest known_assets cookies.
    """
    from core import auth_headers as _auth
    return _auth.resolve_headers(options, {"Content-Type": "application/json"})


# Signals that unambiguously mean the spider tool failed to execute at all.
_SPIDER_HARD_FAIL_SIGNALS = ("command not found", "exec: ", "no such file or directory")


def _spider_succeeded(raw: str) -> bool:
    """Return True if the spider tool executed (even finding nothing). False = failed to run."""
    if not raw or not raw.strip():
        return False
    low = raw.lower()
    return not any(sig in low for sig in _SPIDER_HARD_FAIL_SIGNALS)
