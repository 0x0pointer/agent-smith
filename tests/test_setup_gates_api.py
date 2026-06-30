"""Dashboard API route tests for setup-gate elect/recheck (FastAPI TestClient)."""
from unittest.mock import AsyncMock

from fastapi.testclient import TestClient

import core.session as s
from core.api_server import app

client = TestClient(app)

_PING = {"run_on": "host", "verb": "ping", "args": ["-c", "1", "127.0.0.1"], "success": "exit_zero"}


def _open_ping_gate(election=None):
    s.start("http://t.test", depth="recon")
    s.open_setup_gate(
        {"id": "png", "category": "network", "requires_host": False,
         "runbook": [{"step": "ensure loopback"}], "readiness_probe": _PING},
        skill="sk",
    )
    if election:
        s.record_election("png", election)


def test_route_elect_records_choice():
    _open_ping_gate()
    r = client.post("/api/setup-gates/png/elect", json={"choice": "defer"})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True and body["gate"]["election"] == "defer"


def test_route_elect_bad_choice_400():
    _open_ping_gate()
    r = client.post("/api/setup-gates/png/elect", json={"choice": "maybe"})
    assert r.status_code == 400


def test_route_elect_unknown_gate_404():
    s.start("http://t.test", depth="recon")
    r = client.post("/api/setup-gates/ghost/elect", json={"choice": "now"})
    assert r.status_code == 404


def test_route_recheck_pass_when_elected_now():
    _open_ping_gate(election="now")
    r = client.post("/api/setup-gates/png/recheck")
    assert r.status_code == 200
    body = r.json()
    # ping passes; gate was elected_now (not deferred) so Smith is NOT woken
    assert body["ok"] and body["status"] == "ok" and body["smith_woken"] is False


def test_route_recheck_deferred_wakes_smith(monkeypatch):
    import core.api_server.routes as routes
    monkeypatch.setattr(routes, "_wake_smith_if_idle", AsyncMock(return_value=True))
    _open_ping_gate(election="defer")
    r = client.post("/api/setup-gates/png/recheck")
    body = r.json()
    assert body["ok"] and body["status"] == "ok" and body["smith_woken"] is True


def test_route_recheck_unknown_gate_404():
    s.start("http://t.test", depth="recon")
    r = client.post("/api/setup-gates/ghost/recheck")
    assert r.status_code == 404


def test_route_elect_server_error_500(monkeypatch):
    _open_ping_gate()
    monkeypatch.setattr(s, "record_election", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    r = client.post("/api/setup-gates/png/elect", json={"choice": "now"})
    assert r.status_code == 500 and r.json()["ok"] is False


def test_route_recheck_server_error_500(monkeypatch):
    import core.probe_runner as pr
    _open_ping_gate(election="now")
    monkeypatch.setattr(pr, "check_gate", AsyncMock(side_effect=RuntimeError("boom")))
    r = client.post("/api/setup-gates/png/recheck")
    assert r.status_code == 500 and r.json()["ok"] is False
