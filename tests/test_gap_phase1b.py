"""Phase 1 gap-analysis fixes — behavior locks (second batch).

SP-2 (JS-route params → injection cells), CH-4 (body signal → web-exploit gate),
CH-5 (second distinct identity → BOLA gate).
"""
import core.session as scan_session
from mcp_server.scan_engine.discovery import _route_params


# ── SP-2: JS-route param inference ──────────────────────────────────────────────
class TestJsRouteParams:
    def test_query_and_templated_path_params(self):
        p = _route_params("/api/users/{id}?q=1&__internal=2")
        names = {x["name"] for x in p}
        assert "q" in names            # query param → injection cells
        assert "id" in names           # templated path param → IDOR/SQLi cells
        assert "__internal" not in names  # framework-internal param skipped

    def test_numeric_segment_becomes_path_param(self):
        p = _route_params("/orders/42/items")
        assert any(x["type"] == "path" and x["value_hint"] == "integer" for x in p)

    def test_colon_style_placeholder(self):
        assert any(x["name"] == "userId" for x in _route_params("/u/:userId"))

    def test_static_route_yields_no_params(self):
        assert _route_params("/about/team") == []


# ── CH-4: response body signal → gate ───────────────────────────────────────────
class _Result:
    def __init__(self, anomalies):
        self.anomalies = anomalies
        self.evidence = {}


class TestBodySignalGate:
    def _gates(self):
        return [g["id"] for g in (scan_session.get() or {}).get("gates", [])]

    def test_werkzeug_debugger_opens_web_exploit_gate(self):
        from mcp_server.scan_engine.envelope import assets as env_assets
        scan_session._current = {"status": "running", "gates": [], "known_assets": {}}
        env_assets._trigger_body_signal_gates(
            scan_session, _Result(["Werkzeug debugger detected — potential RCE"]),
            {"url": "http://t/x"})
        assert "web_exploit_debugger" in self._gates()

    def test_sql_error_opens_web_exploit_gate(self):
        from mcp_server.scan_engine.envelope import assets as env_assets
        scan_session._current = {"status": "running", "gates": [], "known_assets": {}}
        env_assets._trigger_body_signal_gates(
            scan_session, _Result(["Possible SQL error in response"]),
            {"url": "http://t/x"})
        assert "web_exploit_sqli" in self._gates()

    def test_clean_response_opens_no_gate(self):
        from mcp_server.scan_engine.envelope import assets as env_assets
        scan_session._current = {"status": "running", "gates": [], "known_assets": {}}
        env_assets._trigger_body_signal_gates(scan_session, _Result([]), {"url": "http://t/x"})
        assert self._gates() == []


# ── CH-5: second identity → BOLA gate ───────────────────────────────────────────
class TestBolaGate:
    def _gates(self):
        return [g["id"] for g in (scan_session.get() or {}).get("gates", [])]

    def test_second_distinct_identity_opens_gate(self):
        scan_session._current = {"status": "running", "gates": [], "known_assets": {}}
        scan_session.update_known_assets("credentials", [{"username": "alice", "password": "1"}])
        assert "bola_multi_identity" not in self._gates()   # one identity — no gate
        scan_session.update_known_assets("credentials", [{"username": "bob", "password": "2"}])
        assert "bola_multi_identity" in self._gates()       # two → BOLA gate

    def test_same_identity_twice_does_not_open_gate(self):
        scan_session._current = {"status": "running", "gates": [], "known_assets": {}}
        scan_session.update_known_assets("credentials", [{"username": "alice", "password": "1"}])
        scan_session.update_known_assets("credentials", [{"username": "alice", "password": "1"}])
        assert "bola_multi_identity" not in self._gates()
