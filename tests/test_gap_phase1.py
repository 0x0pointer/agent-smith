"""Phase 1 gap-analysis fixes — behavior locks (first batch).

SM-1 (context meter seeds fixed overhead), CH-1 (tech-routed payloads),
CH-3 (CVE → exploit-validation gate).
"""
import core.session as scan_session
import mcp_server.report_tools as rt
from mcp_server.scan_engine import planner


# ── SM-1: context meter seeds real window occupancy ─────────────────────────────
class TestContextOverhead:
    def test_fixed_overhead_is_seeded(self):
        # system prompt + tool schemas + CLAUDE.md ≫ 0 — the meter must not start empty
        assert scan_session._fixed_context_overhead_chars() >= 60_000

    def test_charge_skill_context_is_safe_without_session(self):
        scan_session._current = None
        scan_session.charge_skill_context("web-exploit")  # no crash, no-op


# ── CH-1: tech-routed payloads ──────────────────────────────────────────────────
class TestTechRouting:
    def _techs(self, *names):
        scan_session._current = {"status": "running",
                                 "known_assets": {"technologies": list(names)}}
        return planner._known_techs()

    def test_freemarker_ssti(self):
        assert planner._routed_payload("ssti", "{{7*7}}", self._techs("Freemarker")) == "${7*7}"

    def test_rails_ssti(self):
        assert planner._routed_payload("ssti", "{{7*7}}", self._techs("Ruby on Rails")) == "<%= 7*7 %>"

    def test_jinja_ssti(self):
        assert planner._routed_payload("ssti", "{{7*7}}", self._techs("Flask", "Werkzeug")) == "{{7*7}}"

    def test_windows_cmdi_and_traversal(self):
        t = self._techs("Microsoft-IIS/10", "ASP.NET")
        assert planner._routed_payload("cmdi", ";id", t) == "& whoami"
        assert "win.ini" in planner._routed_payload("traversal", "....//....//etc/passwd", t)

    def test_unknown_tech_keeps_default(self):
        assert planner._routed_payload("ssti", "{{7*7}}", "") == "{{7*7}}"
        assert planner._routed_payload("cmdi", ";id", self._techs("nginx")) == ";id"


# ── CH-3: CVE → analyze-cve / metasploit gate ───────────────────────────────────
class TestCveGate:
    def _run(self, title, severity, desc, cve, monkeypatch):
        fired = {}
        monkeypatch.setattr(rt.scan_session, "get", lambda: {"gates": [], "depth": "standard"})
        monkeypatch.setattr(rt.scan_session, "trigger_gate",
                            lambda gid, reason, skills: fired.setdefault(gid, skills))
        rt._auto_trigger_finding_gates(title, severity, desc, cve)
        return fired

    def test_cve_field_fires_gate(self, monkeypatch):
        fired = self._run("Vuln", "critical", "", "CVE-2021-44228", monkeypatch)
        assert "analyze_cve" in fired and "metasploit" in fired["analyze_cve"]

    def test_cve_in_text_fires_gate(self, monkeypatch):
        fired = self._run("Log4Shell CVE-2021-44228 in dep", "high", "", "", monkeypatch)
        assert "analyze_cve" in fired

    def test_low_severity_cve_skips_metasploit(self, monkeypatch):
        fired = self._run("Old lib", "low", "", "CVE-2019-0001", monkeypatch)
        assert fired.get("analyze_cve") == ["analyze-cve"]

    def test_speculative_cve_does_not_fire(self, monkeypatch):
        fired = self._run("Possibly affected by CVE-2019-0001", "medium", "may be vulnerable", "", monkeypatch)
        assert "analyze_cve" not in fired
