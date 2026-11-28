"""
Idle scans
==========
When Smith stops on its own — the model ended its turn, the process exited, or
it hung and was killed — the scan does NOT get a fresh process spawned at it.
It goes **idle**: still open, nothing running, waiting for the operator. A
steering instruction or the dashboard's Resume button starts Smith again.

Why idle is the default: a watchdog that respawns into the same dead end burns
model budget and hides the fact that the agent decided to stop. Stopping is
information; the operator should see it and decide.

Unattended runs can opt back into automatic respawn with ``SMITH_AUTO_RESUME=1``.

The idle state is a small marker file next to ``smith.pid`` rather than a new
``session.status`` value: ``status == "running"`` is checked in dozens of places
inside the tool server to mean "this scan is open", and an idle scan is still
open. Keeping the two apart means resuming is just "start a process" with no
cross-process status hand-off.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import core.api_server as _api

from ._common import _log

# Why the agent stopped, in operator words.
REASONS = {
    "exited":  "Smith ended its turn and exited.",
    "stalled": "Smith stopped making progress and was shut down.",
    "hung":    "Smith stopped responding and was shut down.",
    "stopped": "Smith is not running.",
}


def auto_resume_enabled() -> bool:
    """True when the operator opted into automatic respawn (unattended runs)."""
    return os.environ.get("SMITH_AUTO_RESUME", "").strip().lower() in ("1", "true", "yes")


def read_idle() -> dict | None:
    """The idle marker ({since, reason, detail}) or None when the scan is not idle."""
    try:
        data = json.loads(_api._SMITH_IDLE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def mark_idle(reason: str) -> bool:
    """Record that the scan is idle. Returns True only on the transition into idle,
    so the caller can notify once instead of on every watchdog tick."""
    if read_idle() is not None:
        return False
    reason = reason if reason in REASONS else "stopped"
    payload = {"since": datetime.now(timezone.utc).isoformat(), "reason": reason, "detail": REASONS[reason]}
    try:
        _api._SMITH_IDLE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _api._SMITH_IDLE_FILE.write_text(json.dumps(payload), encoding="utf-8")
    except OSError:
        _log.exception("could not write the idle marker")
        return False
    _log.info("scan is now idle (%s) — waiting for the operator", reason)
    return True


def clear_idle() -> None:
    """Forget the idle state (Smith is running again, or the scan ended)."""
    try:
        _api._SMITH_IDLE_FILE.unlink(missing_ok=True)
    except OSError:
        pass


def process_alive() -> bool:
    """A Smith PROCESS exists right now.

    Deliberately not ``_smith_running()``: that also counts a fresh tool-log
    heartbeat, which stays "alive" for minutes after the process has gone and
    would delay showing the scan as idle.
    """
    return bool(_api._signal_pid_file_alive() or _api._signal_process_scan_finds_client())
