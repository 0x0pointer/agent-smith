"""Phase 1 gap-analysis fixes — behavior locks (third batch).

CH-11 (evidence-driven gates from sqlmap/nuclei), CH-8 (rate-limit capture).
"""
import core.session as scan_session
from mcp_server.scan_engine.envelope import assets as env_assets


class _Result:
    def __init__(self, evidence):
        self.evidence = evidence
        self.anomalies = []


def _gates():
    return [g["id"] for g in (scan_session.get() or {}).get("gates", [])]


# ── CH-11: gates fire from the tool's own verdict, not model wording ────────────
class TestEvidenceGates:
    def test_sqlmap_vulnerable_opens_web_exploit_gate(self):
        scan_session._current = {"status": "running", "gates": [], "known_assets": {}}
        env_assets._extract_and_persist_assets(
            "kali_sqlmap", _Result({"vulnerable": True}), {"target": "http://t/x?id=1"})
        assert "web_exploit_sqli" in _gates()

    def test_sqlmap_clean_opens_no_gate(self):
        scan_session._current = {"status": "running", "gates": [], "known_assets": {}}
        env_assets._extract_and_persist_assets(
            "kali_sqlmap", _Result({"vulnerable": False}), {"target": "http://t/x"})
        assert _gates() == []

    def test_nuclei_critical_opens_analyze_cve_gate(self):
        scan_session._current = {"status": "running", "gates": [], "known_assets": {}}
        env_assets._extract_and_persist_assets(
            "nuclei", _Result({"findings": [{"severity": "critical", "template": "cve-x"}]}),
            {"url": "http://t"})
        assert "analyze_cve" in _gates()

    def test_nuclei_low_opens_no_gate(self):
        scan_session._current = {"status": "running", "gates": [], "known_assets": {}}
        env_assets._extract_and_persist_assets(
            "nuclei", _Result({"findings": [{"severity": "info", "template": "banner"}]}),
            {"url": "http://t"})
        assert _gates() == []


# ── CH-8: rate-limit capture ────────────────────────────────────────────────────
class TestRateLimitCapture:
    def _limits(self):
        return (scan_session.get() or {}).get("known_assets", {}).get("rate_limits", [])

    def test_429_is_recorded(self):
        scan_session._current = {"status": "running", "gates": [], "known_assets": {}}
        env_assets._update_rate_limits(scan_session, {"status": 429, "rate_limit": {}}, "http://t/sms")
        assert any("429" in x for x in self._limits())

    def test_ratelimit_headers_recorded(self):
        scan_session._current = {"status": "running", "gates": [], "known_assets": {}}
        env_assets._update_rate_limits(
            scan_session, {"status": 200, "rate_limit": {"Retry-After": "60"}}, "http://t/api")
        assert any("Retry-After=60" in x for x in self._limits())

    def test_normal_response_records_nothing(self):
        scan_session._current = {"status": "running", "gates": [], "known_assets": {}}
        env_assets._update_rate_limits(scan_session, {"status": 200, "rate_limit": {}}, "http://t/x")
        assert self._limits() == []
