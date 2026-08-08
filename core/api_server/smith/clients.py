"""
Client resolution: which CLI (claude / opencode / codex) should be (re)spawned.

Installed-check + running-process check plus the four-step resolver chain that
``_detect_active_client`` walks. Resolver siblings are reached through the
package object (``_smith.<name>``); the installed/running probes and paths stay
on the parent (``_api.<name>``).
"""
from __future__ import annotations

import json

import core.api_server as _api
import core.api_server.smith as _smith

from ._common import _KNOWN_CLIENTS


def _client_installed(name: str) -> bool:
    """Check whether the named client CLI is on $PATH (cross-platform).

    The older form fell back to hardcoded macOS paths (/opt/homebrew/bin and a
    literal user home), which broke on Windows and made the function lie on
    fresh systems where the user installed the CLI via npm/cargo to a
    different prefix. shutil.which() handles ``$PATHEXT`` on Windows so an
    ``opencode.cmd`` shim is detected correctly."""
    import shutil
    if name in ("claude", "opencode", "codex"):
        return bool(shutil.which(name))
    return False


def _client_process_running(name: str) -> bool:
    """Check whether any process for the given client is currently running.

    Cross-platform via psutil — replaces the older ``pgrep -f <name>`` shell
    call which only ran on Unix. Matches against the full command line so an
    opencode wrapper running as ``node /path/to/.opencode/...`` still hits."""
    try:
        import psutil
    except ImportError:
        return False
    needle = name.lower()
    try:
        for proc in psutil.process_iter(["name", "cmdline"]):
            try:
                pname = (proc.info.get("name") or "").lower()
                if needle in pname:
                    return True
                cmd = " ".join(proc.info.get("cmdline") or []).lower()
                if needle in cmd:
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except (psutil.AccessDenied, OSError):
        return False
    return False


def _resolve_client_from_session() -> str | None:
    """Resolver step 1+2: read session.json and return whichever client
    field is populated and points at an installed CLI.

    Step 1 (authoritative): ``smith_proc.client`` set at session.start() by
    caller-detection. This is THE answer when present — once a scan
    started in opencode, watchdog respawns must use opencode.

    Step 2 (legacy / back-compat): top-level ``client`` field, for older
    sessions or out-of-band operator overrides.
    """
    try:
        sd = json.loads(_api._SESSION_FILE.read_text())
    except (OSError, ValueError):
        return None
    smith_proc = sd.get("smith_proc") if isinstance(sd, dict) else None
    if isinstance(smith_proc, dict):
        locked = (smith_proc.get("client") or "").strip().lower()
        if locked in _KNOWN_CLIENTS and _api._client_installed(locked):
            return locked
    client = (sd.get("client") or "").strip().lower() if isinstance(sd, dict) else ""
    if client in _KNOWN_CLIENTS and _api._client_installed(client):
        return client
    return None


def _resolve_client_from_smith_client_file() -> str | None:
    """Resolver step 3: read logs/smith.client (last dashboard-managed
    spawn). Global file, can drift across scans — only useful when no
    scan-locked client is present."""
    try:
        saved = _api._SMITH_CLIENT_FILE.read_text().strip().lower()
    except (OSError, ValueError):
        return None
    return saved if (saved in _KNOWN_CLIENTS and _api._client_installed(saved)) else None


def _resolve_client_from_running_process() -> str | None:
    """Resolver step 4: scan for a live process matching a known client.

    Iterates _KNOWN_CLIENTS in priority order (claude > opencode > codex)
    so the answer is deterministic when multiple clients are open.
    """
    for name in _KNOWN_CLIENTS:
        if _api._client_process_running(name) and _api._client_installed(name):
            return name
    return None


def _detect_active_client() -> str:
    """Detect which client should be used for restart.

    Resolution chain (most authoritative first); first match wins:
      1. ``_resolve_client_from_session`` — scan-locked client or legacy
         top-level field in session.json
      2. ``_resolve_client_from_smith_client_file`` — logs/smith.client
         (global, drift-prone, used only when session.json is silent)
      3. ``_resolve_client_from_running_process`` — live process scan
      4. ``"claude"`` as final default

    Operator override: the /api/restart-smith endpoint accepts
    ``{"client": "<name>"}`` in the request body, which short-circuits
    this entire chain. Use that path when intentionally switching mid-scan.
    """
    for resolver in (
        _smith._resolve_client_from_session,
        _smith._resolve_client_from_smith_client_file,
        _smith._resolve_client_from_running_process,
    ):
        client = resolver()
        if client:
            return client
    return "claude"
