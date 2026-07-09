"""Three-phase scan model — saturation predicates (core/session/phases.py)."""
import core.session.phases as ph


def _sess(**kw):
    base = {"scan_phase": "exploit", "tool_invocations": [{"tool": "httpx"}, {"tool": "spider"}]}
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

    def test_no_high_findings_keeps_hunting(self, monkeypatch):
        monkeypatch.setattr(ph, "open_bridges", lambda fd: 0)
        # only low findings → not saturated (don't fall back to breadth with nothing deep found)
        assert ph.depth_saturated(_sess(), self._fd([{"id": "x", "severity": "low", "title": "hdr"}])) is False

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
