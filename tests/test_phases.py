"""Three-phase scan model — saturation predicates (core/session/phases.py)."""
import core.session.phases as ph


def _sess(**kw):
    base = {"scan_phase": "exploit",
            "tool_invocations": [{"tool": "httpx"}, {"tool": "spider"}],
            "skill_history": [{"skill": "web-exploit"}]}   # hunt attempted
    base.update(kw)
    return base


def _crit(title="Confirmed SQLi", **kw):
    f = {"id": kw.get("id", "f1"), "severity": "critical", "title": title, "description": ""}
    f.update(kw)
    return f


class TestPhaseState:
    def test_default_is_exploit(self):
        assert ph.current_phase({}) == "exploit"
        assert ph.current_phase(None) == "exploit"
        assert ph.current_phase({"scan_phase": "coverage"}) == "coverage"
        assert ph.current_phase({"scan_phase": "bogus"}) == "exploit"  # unknown → default


class TestDepthSaturation:
    def _fd(self, findings, chains=None):
        return {"findings": findings, "chains": chains or []}

    def test_recon_not_done_never_saturates(self, monkeypatch):
        monkeypatch.setattr(ph, "open_bridges", lambda fd: 0)
        s = {"scan_phase": "exploit", "tool_invocations": [{"tool": "nmap"}]}  # no httpx/crawl
        assert ph.depth_saturated(s, self._fd([_crit()])) is False

    def test_no_hunt_yet_keeps_hunting(self, monkeypatch):
        monkeypatch.setattr(ph, "open_bridges", lambda fd: 0)
        s = _sess(skill_history=[])   # recon done but no exploitation skill run yet
        assert ph.depth_saturated(s, self._fd([])) is False

    def test_hardened_target_saturates_once_hunt_ran(self, monkeypatch):
        monkeypatch.setattr(ph, "open_bridges", lambda fd: 0)
        # recon + hunt ran, no high-value findings → depth exhausted → advance to breadth
        # (must NOT spin in Phase A forever on a low-vuln target)
        assert ph.depth_saturated(_sess(), self._fd([{"id": "x", "severity": "low"}])) is True

    def test_unpursued_high_blocks_saturation(self, monkeypatch):
        monkeypatch.setattr(ph, "open_bridges", lambda fd: 0)
        # a plain confirmed critical with no chain / lead / terminal text → still to pursue
        assert ph.depth_saturated(_sess(), self._fd([_crit()])) is False

    def test_pursued_via_terminal_text(self, monkeypatch):
        monkeypatch.setattr(ph, "open_bridges", lambda fd: 0)
        assert ph.depth_saturated(_sess(), self._fd([_crit(title="RCE via code execution on /x")])) is True

    def test_pursued_via_dismissed_lead(self, monkeypatch):
        monkeypatch.setattr(ph, "open_bridges", lambda fd: 0)
        f = _crit(escalation_leads=[{"lead": "role not superuser", "status": "dismissed"}])
        assert ph.depth_saturated(_sess(), self._fd([f])) is True

    def test_pursued_via_chain(self, monkeypatch):
        monkeypatch.setattr(ph, "open_bridges", lambda fd: 0)
        fd = self._fd([_crit(id="f1")], chains=[{"steps": [{"from_finding_id": "f1", "to_finding_id": "f2"}]}])
        assert ph.depth_saturated(_sess(), fd) is True

    def test_open_bridge_blocks_saturation(self, monkeypatch):
        monkeypatch.setattr(ph, "open_bridges", lambda fd: 1)   # a provable bridge unattempted
        assert ph.depth_saturated(_sess(), self._fd([_crit(title="RCE via code execution")])) is False


class TestCoverageSaturation:
    def test_pending_cells_not_saturated(self):
        assert ph.coverage_saturated({"matrix": [{"status": "pending"}, {"status": "vulnerable"}]}) is False

    def test_all_closed_saturated(self):
        assert ph.coverage_saturated({"matrix": [{"status": "tested_clean"}, {"status": "vulnerable"}]}) is True

    def test_empty_matrix_not_saturated(self):
        assert ph.coverage_saturated({"matrix": []}) is False   # nothing built yet


class TestTransitions:
    def test_forward_only(self, monkeypatch):
        monkeypatch.setattr(ph, "depth_saturated", lambda s, fd: True)
        monkeypatch.setattr(ph, "coverage_saturated", lambda m: True)
        assert ph.next_phase("exploit", {}, {}, {}) == "coverage"
        assert ph.next_phase("coverage", {}, {}, {}) == "synthesis"
        assert ph.next_phase("synthesis", {}, {}, {}) is None       # terminal phase

    def test_no_advance_when_unsaturated(self, monkeypatch):
        monkeypatch.setattr(ph, "depth_saturated", lambda s, fd: False)
        assert ph.next_phase("exploit", {}, {}, {}) is None


class TestPhaseCompletionBlocker:
    def test_blocks_before_synthesis(self, monkeypatch):
        from mcp_server.session_tools.completion_gates import _phase_completion_blocker
        import core.session as sess
        monkeypatch.setattr(sess, "maybe_advance_phase", lambda: None)
        monkeypatch.setattr(sess, "get", lambda: {"scan_phase": "exploit"})
        assert "PHASE A" in _phase_completion_blocker()
        monkeypatch.setattr(sess, "get", lambda: {"scan_phase": "coverage"})
        assert "PHASE B" in _phase_completion_blocker()
        monkeypatch.setattr(sess, "get", lambda: {"scan_phase": "synthesis"})
        assert _phase_completion_blocker() is None
        monkeypatch.setattr(sess, "get", lambda: None)
        assert _phase_completion_blocker() is None    # no session → no block
