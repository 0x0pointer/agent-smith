"""Watchdog must NOTIFY the operator when it starts a headless Smith session.

Ricco's report: when Claude stops generating and the watchdog silently respawns headless
sessions, the operator assumes the scan is paused — they have no signal the autonomous
sessions are running. Fix: notify on every SUCCESSFUL spawn, with the pid + per-scan
respawn count in the body so each spawn is a DISTINCT notification (the notifier dedups on
(code, body) for 30 min, so a fixed body would collapse a burst of respawns into one alert).
"""
import time
from unittest.mock import MagicMock  # noqa: F401

import pytest

import core.api_server as api
import core.api_server.smith as smith
from core.api_server.smith import watchdog as wd


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.setattr(api, "_watchdog_last_restart_ts", 0.0)
    monkeypatch.setattr(api, "_watchdog_restart_count_window", [])
    monkeypatch.setattr(smith, "_watchdog_scan_restarts", 0)
    monkeypatch.setattr(smith, "_last_spawn_failure", "")


def test_successful_spawn_notifies_operator(monkeypatch):
    calls = []
    monkeypatch.setattr(smith, "_watchdog_notify",
                        lambda title, body, code: calls.append((title, body, code)))
    wd._finalize_respawn(time.time(), "opencode", ok=True, result=4242)
    assert len(calls) == 1
    _title, body, code = calls[0]
    assert code == "WATCHDOG_SESSION_STARTED"
    assert "4242" in body                 # pid surfaced so the operator can see it
    assert "headless" in body.lower()
    assert "paused" in body.lower()        # explicitly states it is NOT paused


def test_each_spawn_is_a_distinct_notification(monkeypatch):
    bodies = []
    monkeypatch.setattr(smith, "_watchdog_notify",
                        lambda title, body, code: bodies.append(body))
    wd._finalize_respawn(time.time(), "opencode", ok=True, result=100)
    wd._finalize_respawn(time.time(), "opencode", ok=True, result=200)
    assert len(bodies) == 2
    assert bodies[0] != bodies[1]          # distinct -> dedup can't silence the burst


def test_failed_spawn_still_notifies_failure(monkeypatch):
    calls = []
    monkeypatch.setattr(smith, "_watchdog_notify",
                        lambda title, body, code: calls.append(code))
    wd._finalize_respawn(time.time(), "opencode", ok=False, result="Credit balance is too low")
    assert calls == ["WATCHDOG_RESPAWN_FAILED"]   # existing failure alert unchanged
