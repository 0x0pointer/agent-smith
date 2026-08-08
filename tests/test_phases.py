"""Three-phase scan model — saturation predicates (core/session/phases.py)."""
import core.session.phases as ph


def _sess(**kw):
    base = {"scan_phase": "exploit",
            "tool_invocations": [{"tool": "httpx"}, {"tool": "spider"}],
            "skill_history": [{"skill": "web-exploit", "worked": True}]}   # hunt genuinely ran
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


class TestReconWiring:
    def test_tools_run_reads_tools_called_scanner_names(self):
        # REGRESSION (BUG A): recon scanners are recorded in `tools_called` as SCANNER names
        # (httpx/nmap/...), while tool_invocations[].tool holds DISPATCHER names
        # (http_request/kali). _tools_run must union BOTH — reading only tool_invocations left
        # _recon_done permanently False on real scans (scanner names never appear there), so
        # depth_saturated was always False and the advisory hint could never fire.
        s = {"scan_phase": "exploit",
             "tools_called": ["httpx", "naabu", "nuclei", "ffuf", "spider", "kali"],
             "tool_invocations": [{"tool": "http_request"}, {"tool": "kali"}],
             "skill_history": [{"skill": "web-exploit", "worked": True}]}
        assert "httpx" in ph._tools_run(s)
        assert ph._recon_done(s) is True

    def test_recon_done_false_when_only_dispatcher_names(self):
        s = {"tools_called": [], "tool_invocations": [{"tool": "http_request"}]}
        assert ph._recon_done(s) is False


class TestForcedNext:
    def test_forward_only_and_stops_at_synthesis(self):
        assert ph.forced_next("exploit") == "coverage"
        assert ph.forced_next("coverage") == "synthesis"
        assert ph.forced_next("synthesis") is None
        assert ph.forced_next("bogus") == "coverage"   # unknown → treat as start


class TestDepthSaturation:
    def _fd(self, findings, chains=None):
        return {"findings": findings, "chains": chains or []}

    def test_no_recon_no_hunt_never_saturates(self, monkeypatch):
        monkeypatch.setattr(ph, "open_bridges", lambda fd: 0)
        s = {"scan_phase": "exploit", "tool_invocations": [], "skill_history": []}
        assert ph.depth_saturated(s, self._fd([_crit()])) is False

    def test_hunt_rubber_stamp_does_not_count(self, monkeypatch):
        # set_skill without attributable work (worked flag unset) must NOT count as the hunt.
        monkeypatch.setattr(ph, "open_bridges", lambda fd: 0)
        s = _sess(skill_history=[{"skill": "web-exploit"}])   # declared, never worked
        assert ph.depth_saturated(s, self._fd([])) is False

    def test_hardened_target_saturates_once_hunt_ran(self, monkeypatch):
        monkeypatch.setattr(ph, "open_bridges", lambda fd: 0)
        # recon + hunt genuinely ran, no high-value findings → depth exhausted → advance
        assert ph.depth_saturated(_sess(), self._fd([{"id": "x", "severity": "low"}])) is True

    def test_non_web_target_can_saturate(self, monkeypatch):
        # REGRESSION (blocker): a network/AD/cloud/mobile scan runs no httpx and no web skill —
        # it must still be able to leave Phase A, not wedge forever.
        monkeypatch.setattr(ph, "open_bridges", lambda fd: 0)
        s = {"scan_phase": "exploit", "tool_invocations": [{"tool": "nmap"}],
             "skill_history": [{"skill": "network-assess", "worked": True}]}
        assert ph.depth_saturated(s, self._fd([_crit(title="RCE via code execution")])) is True

    # ── Skill-exhaustion bar (Phase A runs the FULL applicable-skill sweep, not just one) ──
    def test_owed_skill_gate_blocks_saturation(self, monkeypatch):
        # The deep hunt ran ONE skill (web-exploit) but a discovered surface opened a param-fuzz
        # gate that hasn't worked → depth is NOT exhausted, keep hunting (don't drift to breadth).
        monkeypatch.setattr(ph, "open_bridges", lambda fd: 0)
        monkeypatch.setattr(ph, "_enforce_deep_skills", lambda: True)
        s = _sess(gates=[{"id": "params", "status": "pending",
                          "required_skills": ["param-fuzz"], "satisfied_skills": []}])
        assert ph.depth_saturated(s, self._fd([])) is False

    def test_all_gate_skills_worked_saturates(self, monkeypatch):
        # Every applicable skill did real work → the deep sweep is complete → advance. Reads the
        # per-skill `worked` flag directly, so a gate still marked 'pending' (reconcile not yet run)
        # does not falsely block.
        monkeypatch.setattr(ph, "open_bridges", lambda fd: 0)
        monkeypatch.setattr(ph, "_enforce_deep_skills", lambda: True)
        s = _sess(skill_history=[{"skill": "web-exploit", "worked": True},
                                 {"skill": "param-fuzz", "worked": True}],
                  gates=[{"id": "params", "status": "pending",
                          "required_skills": ["param-fuzz"], "satisfied_skills": []}])
        assert ph.depth_saturated(s, self._fd([])) is True

    def test_satisfied_gate_never_blocks(self, monkeypatch):
        monkeypatch.setattr(ph, "open_bridges", lambda fd: 0)
        monkeypatch.setattr(ph, "_enforce_deep_skills", lambda: True)
        s = _sess(gates=[{"id": "g", "status": "satisfied",
                          "required_skills": ["reverse-shell"], "satisfied_skills": ["reverse-shell"]}])
        assert ph.depth_saturated(s, self._fd([])) is True

    def test_weak_profile_keeps_single_skill_bar(self, monkeypatch):
        # On a weak local profile the full-sweep requirement is dropped (else the small model
        # game-then-stalls) — an owed gate does NOT hold Phase A.
        monkeypatch.setattr(ph, "open_bridges", lambda fd: 0)
        monkeypatch.setattr(ph, "_enforce_deep_skills", lambda: False)
        s = _sess(gates=[{"id": "params", "status": "pending",
                          "required_skills": ["param-fuzz"], "satisfied_skills": []}])
        assert ph.depth_saturated(s, self._fd([])) is True

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
        assert ph.coverage_saturated({"matrix": [
            {"status": "pending", "injection_type": "sqli"}, {"status": "vulnerable"}]}) is False

    def test_in_progress_blocks_saturation(self):
        # in_progress = started, not concluded → must NOT count as drained
        assert ph.coverage_saturated({"matrix": [
            {"status": "in_progress", "injection_type": "xss"}, {"status": "tested_clean"}]}) is False

    def test_all_closed_saturated(self):
        assert ph.coverage_saturated({"matrix": [
            {"status": "tested_clean", "injection_type": "sqli"}, {"status": "vulnerable"}]}) is True

    def test_no_autocloser_pending_does_not_pin_phase_b(self):
        # rate_limit/jwt/race/... have no autocloser and are expected to linger — must not
        # prevent B→C, else coverage never saturates.
        assert ph.coverage_saturated({"matrix": [
            {"status": "pending", "injection_type": "rate_limit"},
            {"status": "pending", "injection_type": "jwt"},
            {"status": "tested_clean", "injection_type": "sqli"}]}) is True

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
