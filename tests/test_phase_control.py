"""Human-gated phase progression — typed-steer parser + /api/phase endpoints.

Phases never auto-advance; the operator drives A→B→C via a dashboard button
(/api/phase/advance) or a typed steer ("advance to phase B", "next phase")
parsed server-side in /api/steer.
"""
from fastapi.testclient import TestClient

import core.session
from core.api_server import app
from core.api_server.routes.scan_state_routes import _parse_phase_steer

client = TestClient(app)


class TestParsePhaseSteer:
    def test_advance_to_phase_b(self):
        assert _parse_phase_steer("advance to phase B") == (True, "coverage")

    def test_go_to_phase_c(self):
        assert _parse_phase_steer("go to phase c") == (True, "synthesis")

    def test_named_coverage_phase(self):
        assert _parse_phase_steer("start the coverage phase") == (True, "coverage")

    def test_named_synthesis_phase(self):
        assert _parse_phase_steer("move to synthesis phase") == (True, "synthesis")

    def test_next_phase_and_advance_phase(self):
        assert _parse_phase_steer("next phase") == (True, None)
        assert _parse_phase_steer("advance the phase") == (True, None)

    def test_normal_steer_is_not_a_phase_advance(self):
        assert _parse_phase_steer("focus on /api/users") == (False, None)
        assert _parse_phase_steer("skip rate_limit cells") == (False, None)

    def test_bare_coverage_word_is_not_an_advance(self):
        # 'coverage' unqualified by 'phase' (e.g. "go check the coverage tab") must NOT advance —
        # the word is too common to treat as an operator phase command.
        assert _parse_phase_steer("go check the coverage tab") == (False, None)


class TestPhaseEndpoints:
    def test_get_phase_defaults_exploit(self):
        core.session.start("example.com")
        body = client.get("/api/phase").json()
        assert body["phase"] == "exploit" and body["next"] == "coverage"

    def test_advance_endpoint_moves_forward(self):
        core.session.start("example.com")
        r = client.post("/api/phase/advance", json={})
        assert r.status_code == 200
        assert r.json() == {"ok": True, "from": "exploit", "to": "coverage"}
        assert client.get("/api/phase").json()["phase"] == "coverage"

    def test_advance_endpoint_explicit_target(self):
        core.session.start("example.com")
        assert client.post("/api/phase/advance", json={"target": "synthesis"}).json()["to"] == "synthesis"

    def test_advance_endpoint_rejects_backward(self):
        core.session.start("example.com")
        client.post("/api/phase/advance", json={"target": "coverage"})
        r = client.post("/api/phase/advance", json={"target": "exploit"})
        assert r.status_code == 400 and r.json()["ok"] is False

    def test_steer_routes_phase_advance(self):
        core.session.start("example.com")
        r = client.post("/api/steer", json={"message": "advance to phase B"})
        assert r.status_code == 200 and r.json().get("phase_advanced") is True
        assert client.get("/api/phase").json()["phase"] == "coverage"

    def test_steer_normal_message_does_not_advance(self):
        core.session.start("example.com")
        r = client.post("/api/steer", json={"message": "focus on /api/login SQLi"})
        assert r.status_code == 200 and not r.json().get("phase_advanced")
        assert client.get("/api/phase").json()["phase"] == "exploit"
