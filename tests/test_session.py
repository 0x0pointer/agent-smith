"""
Tests for core.session — scan lifecycle, presets, and hard limit enforcement.
"""
import time
import pytest
import core.session


# ---------------------------------------------------------------------------
# start()
# ---------------------------------------------------------------------------

def test_start_returns_dict_with_target():
    sess = core.session.start("example.com")
    assert sess["target"] == "example.com"


def test_start_defaults_to_standard_depth():
    sess = core.session.start("example.com")
    assert sess["depth"] == "standard"


def test_start_sets_status_running():
    sess = core.session.start("example.com")
    assert sess["status"] == "running"


def test_start_applies_preset_limits():
    sess = core.session.start("example.com", depth="recon")
    assert sess["limits"]["max_cost_usd"] == pytest.approx(0.10)
    assert sess["limits"]["max_time_minutes"] == 15
    assert sess["limits"]["max_tool_calls"] == 10


def test_start_thorough_preset():
    sess = core.session.start("example.com", depth="thorough")
    assert sess["limits"]["max_cost_usd"] is None  # unlimited
    assert sess["limits"]["max_tool_calls"] == 0  # unlimited


def test_start_custom_limits_override_preset():
    sess = core.session.start(
        "example.com", depth="recon",
        max_cost_usd=5.0, max_time_minutes=999, max_tool_calls=100
    )
    assert sess["limits"]["max_cost_usd"] == pytest.approx(5.0)
    assert sess["limits"]["max_time_minutes"] == 999
    assert sess["limits"]["max_tool_calls"] == 100


def test_start_scope_defaults_to_target():
    sess = core.session.start("example.com")
    assert "example.com" in sess["scope"]


def test_start_custom_scope():
    sess = core.session.start("example.com", scope=["api.example.com"])
    assert sess["scope"] == ["api.example.com"]


def test_start_out_of_scope_empty_by_default():
    sess = core.session.start("example.com")
    assert sess["out_of_scope"] == []


def test_start_persists_to_get():
    core.session.start("example.com")
    assert core.session.get() is not None
    assert core.session.get()["target"] == "example.com"


def test_start_writes_session_file(tmp_path, monkeypatch):
    import json
    monkeypatch.setattr(core.session, "_SESSION_FILE", tmp_path / "session.json")
    core.session.start("example.com")
    data = json.loads((tmp_path / "session.json").read_text())
    assert data["target"] == "example.com"


def test_start_unknown_depth_falls_back_to_standard():
    sess = core.session.start("example.com", depth="nonexistent")
    assert sess["limits"]["max_tool_calls"] == 25


# ---------------------------------------------------------------------------
# get()
# ---------------------------------------------------------------------------

def test_get_returns_none_before_start():
    assert core.session.get() is None


# ---------------------------------------------------------------------------
# check_limits()
# ---------------------------------------------------------------------------

def _fake_cost(usd=0.0, calls=0):
    return {"est_cost_usd": usd, "tool_calls_total": calls}


def test_check_limits_none_when_within_budget():
    core.session.start("example.com", depth="recon")
    assert core.session.check_limits(_fake_cost(usd=0.05, calls=5)) is None


def test_check_limits_returns_none_before_session_start():
    assert core.session.check_limits(_fake_cost()) is None


def test_check_limits_cost_exceeded_returns_stop_message():
    core.session.start("example.com", depth="recon")
    msg = core.session.check_limits(_fake_cost(usd=0.11))
    assert msg is not None
    assert "COST LIMIT" in msg


def test_check_limits_call_count_exceeded():
    core.session.start("example.com", depth="recon")
    msg = core.session.check_limits(_fake_cost(calls=10))
    assert msg is not None
    assert "CALL LIMIT" in msg


def test_check_limits_sets_status_limit_reached():
    core.session.start("example.com", depth="recon")
    core.session.check_limits(_fake_cost(usd=0.99))
    assert core.session.get()["status"] == "limit_reached"


def test_check_limits_no_further_checks_after_limit():
    """After limit is reached the session is no longer 'running', so subsequent
    calls to check_limits should return None."""
    core.session.start("example.com", depth="recon")
    core.session.check_limits(_fake_cost(usd=0.99))
    second_check = core.session.check_limits(_fake_cost(usd=0.99))
    assert second_check is None


# ---------------------------------------------------------------------------
# complete()
# ---------------------------------------------------------------------------

def test_complete_sets_status_complete():
    core.session.start("example.com")
    core.session.complete("all done")
    assert core.session.get()["status"] == "complete"


def test_complete_stores_notes():
    core.session.start("example.com")
    core.session.complete("found 3 vulns")
    assert core.session.get()["notes"] == "found 3 vulns"


def test_complete_sets_finished_timestamp():
    core.session.start("example.com")
    core.session.complete()
    assert core.session.get()["finished"] is not None


def test_complete_returns_empty_dict_when_no_session():
    result = core.session.complete()
    assert result == {}


# ---------------------------------------------------------------------------
# remaining()
# ---------------------------------------------------------------------------

def test_remaining_returns_empty_when_no_session():
    assert core.session.remaining(_fake_cost()) == {}


def test_remaining_calls_remaining_decrements():
    core.session.start("example.com", depth="recon", max_tool_calls=10)
    r = core.session.remaining(_fake_cost(calls=3))
    assert r["calls_remaining"] == 7


def test_remaining_cost_remaining():
    core.session.start("example.com", depth="recon", max_cost_usd=0.10)
    r = core.session.remaining(_fake_cost(usd=0.04))
    assert abs(r["cost_remaining_usd"] - 0.06) < 0.001


def test_remaining_never_goes_negative():
    core.session.start("example.com", depth="recon", max_tool_calls=5)
    r = core.session.remaining(_fake_cost(calls=100))
    assert r["calls_remaining"] == 0


# ---------------------------------------------------------------------------
# Unlimited tool calls (max_tool_calls=0)
# ---------------------------------------------------------------------------

def test_check_limits_unlimited_calls_never_triggers():
    core.session.start("example.com", depth="thorough")
    msg = core.session.check_limits(_fake_cost(calls=999))
    assert msg is None  # cost/time still within budget


def test_remaining_unlimited_calls_returns_minus_one():
    core.session.start("example.com", depth="thorough")
    r = core.session.remaining(_fake_cost(calls=50))
    assert r["calls_remaining"] == -1
    assert r["calls_pct"] == 0


# ---------------------------------------------------------------------------
# Counter reset on new session
# ---------------------------------------------------------------------------

def test_start_resets_cost_tracker():
    """Starting a new session should zero out cost tracker counters."""
    import core.cost as cost_tracker
    # Simulate a previous session's calls
    cid = cost_tracker.start("nmap")
    cost_tracker.finish(cid, "x" * 4000)
    assert cost_tracker.get_summary()["tool_calls_total"] == 1

    # Starting a new session should reset
    core.session.start("new-target.com")
    assert cost_tracker.get_summary()["tool_calls_total"] == 0
    assert cost_tracker.get_summary()["est_cost_usd"] == 0


# ---------------------------------------------------------------------------
# Skill tracking
# ---------------------------------------------------------------------------

def _skill_names(sess):
    """Extract ordered list of skill names from the rich skill_history."""
    return [e["skill"] for e in sess["skill_history"]]


def test_start_with_skill():
    sess = core.session.start("example.com", skill="pentester")
    assert sess["skill"] == "pentester"
    assert _skill_names(sess) == ["pentester"]


def test_start_skill_history_entry_has_required_keys():
    sess = core.session.start("example.com", skill="pentester")
    entry = sess["skill_history"][0]
    assert entry["skill"] == "pentester"
    assert entry["reason"] == "session start"
    assert entry["chained_from"] is None
    assert "timestamp" in entry


def test_start_without_skill():
    sess = core.session.start("example.com")
    assert sess["skill"] is None
    assert sess["skill_history"] == []


def test_set_skill_updates_active():
    core.session.start("example.com", skill="pentester")
    result = core.session.set_skill("ai-redteam")
    assert result["skill"] == "ai-redteam"


def test_set_skill_appends_to_history():
    core.session.start("example.com", skill="pentester")
    core.session.set_skill("ai-redteam")
    assert _skill_names(core.session.get()) == ["pentester", "ai-redteam"]


def test_set_skill_no_duplicates_in_history():
    core.session.start("example.com", skill="pentester")
    core.session.set_skill("ai-redteam")
    core.session.set_skill("pentester")
    assert _skill_names(core.session.get()) == ["pentester", "ai-redteam"]


def test_set_skill_stores_reason():
    core.session.start("example.com")
    core.session.set_skill("web-exploit", reason="web app confirmed; systematic testing needed")
    entry = core.session.get()["skill_history"][0]
    assert entry["reason"] == "web app confirmed; systematic testing needed"


def test_set_skill_stores_chained_from():
    core.session.start("example.com", skill="pentester")
    core.session.set_skill("web-exploit", reason="endpoints found", chained_from="pentester")
    entry = core.session.get()["skill_history"][1]
    assert entry["chained_from"] == "pentester"


def test_set_skill_chained_from_none_when_omitted():
    core.session.start("example.com")
    core.session.set_skill("pentester", reason="initial skill")
    entry = core.session.get()["skill_history"][0]
    assert entry["chained_from"] is None


def test_set_skill_history_entry_has_timestamp():
    core.session.start("example.com")
    core.session.set_skill("pentester")
    entry = core.session.get()["skill_history"][0]
    assert "timestamp" in entry
    assert entry["timestamp"]  # non-empty


def test_set_skill_returns_none_without_session():
    assert core.session.set_skill("pentester") is None


def test_set_skill_noop_after_complete():
    core.session.start("example.com", skill="pentester")
    core.session.complete("done")
    assert core.session.set_skill("ai-redteam") is None


def test_skill_persisted_to_file(tmp_path, monkeypatch):
    import json
    monkeypatch.setattr(core.session, "_SESSION_FILE", tmp_path / "session.json")
    core.session.start("example.com", skill="pentester")
    data = json.loads((tmp_path / "session.json").read_text())
    assert data["skill"] == "pentester"
    assert data["skill_history"][0]["skill"] == "pentester"
    assert data["skill_history"][0]["reason"] == "session start"


# ---------------------------------------------------------------------------
# tools_called tracking
# ---------------------------------------------------------------------------

def test_start_initialises_tools_called():
    sess = core.session.start("example.com")
    assert sess["tools_called"] == []


def test_add_tool_called_appends():
    core.session.start("example.com")
    core.session.add_tool_called("nmap")
    core.session.add_tool_called("nuclei")
    assert core.session.get()["tools_called"] == ["nmap", "nuclei"]


def test_add_tool_called_no_duplicates():
    core.session.start("example.com")
    core.session.add_tool_called("nmap")
    core.session.add_tool_called("nmap")
    assert core.session.get()["tools_called"] == ["nmap"]


def test_add_tool_called_noop_without_session():
    core.session._current = None
    core.session.add_tool_called("nmap")  # should not raise


def test_add_tool_called_noop_after_complete():
    core.session.start("example.com")
    core.session.complete("done")
    core.session.add_tool_called("nmap")
    assert core.session.get()["tools_called"] == []


def test_tools_called_persisted_to_file(tmp_path, monkeypatch):
    import json
    monkeypatch.setattr(core.session, "_SESSION_FILE", tmp_path / "session.json")
    core.session.start("example.com")
    core.session.add_tool_called("nmap")
    core.session.add_tool_called("httpx")
    data = json.loads((tmp_path / "session.json").read_text())
    assert data["tools_called"] == ["nmap", "httpx"]


# ---------------------------------------------------------------------------
# current_step checkpoint
# ---------------------------------------------------------------------------

def test_start_initialises_current_step():
    sess = core.session.start("example.com")
    assert sess["current_step"] is None


def test_set_step_updates():
    core.session.start("example.com")
    result = core.session.set_step("3_nuclei_scan")
    assert result["current_step"] == "3_nuclei_scan"


def test_set_step_overwrites_previous():
    core.session.start("example.com")
    core.session.set_step("3_nuclei_scan")
    core.session.set_step("5_ffuf")
    assert core.session.get()["current_step"] == "5_ffuf"


def test_set_step_returns_none_without_session():
    core.session._current = None
    assert core.session.set_step("anything") is None


def test_set_step_noop_after_complete():
    core.session.start("example.com")
    core.session.complete("done")
    assert core.session.set_step("late_step") is None


def test_step_persisted_to_file(tmp_path, monkeypatch):
    import json
    monkeypatch.setattr(core.session, "_SESSION_FILE", tmp_path / "session.json")
    core.session.start("example.com")
    core.session.set_step("5_ffuf")
    data = json.loads((tmp_path / "session.json").read_text())
    assert data["current_step"] == "5_ffuf"


# ---------------------------------------------------------------------------
# Gate tracking
# ---------------------------------------------------------------------------

def test_start_initialises_empty_gates():
    sess = core.session.start("example.com")
    assert sess["gates"] == []


def test_trigger_gate_adds_pending_gate():
    core.session.start("example.com")
    core.session.trigger_gate("post_exploit_rce", "RCE confirmed", ["post-exploit"])
    gates = core.session.get()["gates"]
    assert len(gates) == 1
    assert gates[0]["id"] == "post_exploit_rce"
    assert gates[0]["status"] == "pending"
    assert gates[0]["required_skills"] == ["post-exploit"]
    assert gates[0]["satisfied_skills"] == []


def test_trigger_gate_idempotent():
    core.session.start("example.com")
    core.session.trigger_gate("post_exploit_rce", "RCE confirmed", ["post-exploit"])
    core.session.trigger_gate("post_exploit_rce", "RCE confirmed again", ["post-exploit"])
    gates = core.session.get()["gates"]
    assert len(gates) == 1


def test_trigger_gate_merges_new_skills():
    core.session.start("example.com")
    core.session.trigger_gate("post_exploit_rce", "RCE confirmed", ["post-exploit"])
    core.session.trigger_gate("post_exploit_rce", "K8s detected", ["container-k8s-security"])
    gates = core.session.get()["gates"]
    assert len(gates) == 1
    assert set(gates[0]["required_skills"]) == {"post-exploit", "container-k8s-security"}


def test_trigger_gate_returns_none_without_session():
    core.session._current = None
    assert core.session.trigger_gate("x", "y", ["z"]) is None


def test_trigger_gate_noop_after_complete():
    core.session.start("example.com")
    core.session.complete("done")
    assert core.session.trigger_gate("x", "y", ["z"]) is None


def test_satisfy_gate_marks_skill():
    core.session.start("example.com")
    core.session.trigger_gate("post_exploit_rce", "RCE", ["post-exploit", "container-k8s-security"])
    core.session.satisfy_gate("post_exploit_rce", "post-exploit")
    gate = core.session.get()["gates"][0]
    assert "post-exploit" in gate["satisfied_skills"]
    assert gate["status"] == "pending"  # not all satisfied yet


def test_satisfy_gate_flips_to_satisfied_when_all_done():
    core.session.start("example.com")
    core.session.trigger_gate("post_exploit_rce", "RCE", ["post-exploit", "container-k8s-security"])
    core.session.satisfy_gate("post_exploit_rce", "post-exploit")
    core.session.satisfy_gate("post_exploit_rce", "container-k8s-security")
    gate = core.session.get()["gates"][0]
    assert gate["status"] == "satisfied"


def test_satisfy_gate_idempotent():
    core.session.start("example.com")
    core.session.trigger_gate("g1", "test", ["skill-a"])
    core.session.satisfy_gate("g1", "skill-a")
    core.session.satisfy_gate("g1", "skill-a")
    gate = core.session.get()["gates"][0]
    assert gate["satisfied_skills"] == ["skill-a"]


def test_satisfy_gate_nonexistent_gate_is_noop():
    core.session.start("example.com")
    result = core.session.satisfy_gate("nonexistent", "skill-a")
    assert result is not None  # returns _current, no crash


def test_pending_gates_returns_unsatisfied_only():
    core.session.start("example.com")
    core.session.trigger_gate("g1", "test1", ["skill-a"])
    core.session.trigger_gate("g2", "test2", ["skill-b"])
    core.session.satisfy_gate("g1", "skill-a")
    pending = core.session.pending_gates()
    assert len(pending) == 1
    assert pending[0]["id"] == "g2"


def test_pending_gates_empty_when_all_satisfied():
    core.session.start("example.com")
    core.session.trigger_gate("g1", "test", ["skill-a"])
    core.session.satisfy_gate("g1", "skill-a")
    assert core.session.pending_gates() == []


def test_pending_gates_empty_without_session():
    core.session._current = None
    assert core.session.pending_gates() == []


def test_gates_persisted_to_file(tmp_path, monkeypatch):
    import json
    monkeypatch.setattr(core.session, "_SESSION_FILE", tmp_path / "session.json")
    core.session.start("example.com")
    core.session.trigger_gate("post_exploit_rce", "RCE confirmed", ["post-exploit"])
    data = json.loads((tmp_path / "session.json").read_text())
    assert len(data["gates"]) == 1
    assert data["gates"][0]["id"] == "post_exploit_rce"


def test_gate_merge_reopens_satisfied_gate():
    """If a satisfied gate gets new required skills merged, it reopens as pending."""
    core.session.start("example.com")
    core.session.trigger_gate("g1", "test", ["skill-a"])
    core.session.satisfy_gate("g1", "skill-a")
    assert core.session.get()["gates"][0]["status"] == "satisfied"
    # Merge a new skill — should reopen
    core.session.trigger_gate("g1", "expanded", ["skill-b"])
    assert core.session.get()["gates"][0]["status"] == "pending"
    assert set(core.session.get()["gates"][0]["required_skills"]) == {"skill-a", "skill-b"}


# ---------------------------------------------------------------------------
# update_known_assets()
# ---------------------------------------------------------------------------

def test_update_known_assets_noop_without_session():
    core.session._current = None
    core.session.update_known_assets("domains", ["example.com"])  # should not raise


def test_update_known_assets_noop_when_not_running():
    core.session.start("example.com")
    core.session.complete("done")
    core.session.update_known_assets("domains", ["evil.com"])
    assert "evil.com" not in core.session.get().get("known_assets", {}).get("domains", [])


def test_update_known_assets_noop_when_empty_items():
    core.session.start("example.com")
    core.session.update_known_assets("domains", [])
    assert core.session.get()["known_assets"]["domains"] == []


def test_update_known_assets_accumulates_domains():
    core.session.start("example.com")
    core.session.update_known_assets("domains", ["sub.example.com", "api.example.com"])
    domains = core.session.get()["known_assets"]["domains"]
    assert domains == ["sub.example.com", "api.example.com"]


def test_update_known_assets_deduplicates_scalars():
    core.session.start("example.com")
    core.session.update_known_assets("domains", ["sub.example.com"])
    core.session.update_known_assets("domains", ["sub.example.com", "api.example.com"])
    domains = core.session.get()["known_assets"]["domains"]
    assert domains.count("sub.example.com") == 1
    assert domains.count("api.example.com") == 1


def test_update_known_assets_converts_non_strings():
    core.session.start("example.com")
    core.session.update_known_assets("technologies", [42, "nginx"])
    techs = core.session.get()["known_assets"]["technologies"]
    assert "42" in techs
    assert "nginx" in techs


def test_update_known_assets_ports_appends_dicts():
    core.session.start("example.com")
    port_entry = {"host": "10.0.0.1", "port": 80, "protocol": "tcp"}
    core.session.update_known_assets("ports", [port_entry])
    ports = core.session.get()["known_assets"]["ports"]
    assert len(ports) == 1
    assert ports[0]["port"] == 80


def test_update_known_assets_ports_deduplicates_by_host_port():
    core.session.start("example.com")
    entry = {"host": "10.0.0.1", "port": 443}
    core.session.update_known_assets("ports", [entry])
    core.session.update_known_assets("ports", [entry, {"host": "10.0.0.1", "port": 8080}])
    ports = core.session.get()["known_assets"]["ports"]
    assert len(ports) == 2
    assert any(p["port"] == 443 for p in ports)
    assert any(p["port"] == 8080 for p in ports)


def test_update_known_assets_ports_skips_non_dict_items():
    core.session.start("example.com")
    core.session.update_known_assets("ports", ["not-a-dict", 9999])
    ports = core.session.get()["known_assets"].get("ports", [])
    assert len(ports) == 0


def test_update_known_assets_multiple_types_independent():
    core.session.start("example.com")
    core.session.update_known_assets("ips", ["192.168.1.1"])
    core.session.update_known_assets("technologies", ["Apache"])
    assets = core.session.get()["known_assets"]
    assert "192.168.1.1" in assets["ips"]
    assert "Apache" in assets["technologies"]


# ── _injection_breadth_blocker ────────────────────────────────────────────────

from mcp_server.session_tools import _injection_breadth_blocker, _na_untooled_blocker


def _cell(ep_id, param, param_type, inj_type, status="pending", tested_by="", artifact_id=""):
    return {
        "id": f"cell-{ep_id}-{param}-{inj_type}",
        "endpoint_id": ep_id,
        "param": param,
        "param_type": param_type,
        "injection_type": inj_type,
        "status": status,
        "tested_by": tested_by,
        "artifact_id": artifact_id,
    }


def test_low_coverage_floor_blocks_below_40():
    from mcp_server.session_tools import _low_coverage_blocker
    cov = {"matrix": [{"id": "c1", "status": "pending"}]}
    # 20% addressed, passes done → still blocks (below the 40% hard floor)
    out = _low_coverage_blocker(cov, total=10, addressed=2, pct=20.0, passes_done=True)
    assert out is not None and "COVERAGE FLOOR" in out


def test_low_coverage_advisory_after_passes():
    from mcp_server.session_tools import _low_coverage_blocker
    cov = {"matrix": [{"id": "c1", "status": "pending"}]}
    # 60% addressed: advisory (no block) once the thorough passes are done...
    assert _low_coverage_blocker(cov, total=10, addressed=6, pct=60.0, passes_done=True) is None
    # ...but still nudges (blocks) while the passes are NOT yet complete.
    assert _low_coverage_blocker(cov, total=10, addressed=6, pct=60.0, passes_done=False) is not None


def test_low_coverage_none_at_or_above_target():
    from mcp_server.session_tools import _low_coverage_blocker
    assert _low_coverage_blocker({"matrix": []}, total=10, addressed=9, pct=90.0, passes_done=False) is None


def test_set_last_artifact_stashes_on_running_session(monkeypatch):
    import core.session as sess
    monkeypatch.setattr(sess, "_current", {"status": "running"})
    monkeypatch.setattr(sess, "_flush", lambda: None)
    sess.set_last_artifact("http_request", "http_request_1_xyz")
    assert sess._current["last_artifact_id"] == "http_request_1_xyz"
    assert sess._current["last_artifacts_by_tool"]["http_request"] == "http_request_1_xyz"


def test_set_last_artifact_noop_when_not_running(monkeypatch):
    import core.session as sess
    monkeypatch.setattr(sess, "_current", {"status": "complete"})
    monkeypatch.setattr(sess, "_flush", lambda: None)
    sess.set_last_artifact("http_request", "x")
    assert "last_artifact_id" not in sess._current


def test_injection_breadth_blocker_no_gaps():
    cells = [
        _cell("ep1", "q", "query", "sqli"),
        _cell("ep1", "q", "query", "xss"),
        _cell("ep1", "q", "query", "ssti"),
        _cell("ep1", "q", "query", "ssrf"),
        _cell("ep1", "q", "query", "cmdi"),
    ]
    assert _injection_breadth_blocker(cells, coverage_enforced=True) is None


def test_injection_breadth_blocker_gap_enforced():
    cells = [_cell("ep1", "username", "body_json", "sqli")]
    result = _injection_breadth_blocker(cells, coverage_enforced=True)
    assert result is not None
    assert "INJECTION BREADTH" in result
    assert "username" in result


def test_injection_breadth_blocker_gap_not_enforced():
    cells = [_cell("ep1", "username", "body_json", "sqli")]
    result = _injection_breadth_blocker(cells, coverage_enforced=False)
    assert result is None


def test_injection_breadth_blocker_no_sqli_cells():
    cells = [_cell("ep1", "q", "query", "xss")]
    assert _injection_breadth_blocker(cells, coverage_enforced=True) is None


def test_injection_breadth_blocker_endpoint_param_ignored():
    cells = [_cell("ep1", "_endpoint", "endpoint", "sqli")]
    assert _injection_breadth_blocker(cells, coverage_enforced=True) is None


# ── _na_untooled_blocker ──────────────────────────────────────────────────────

def test_na_untooled_blocker_no_issue():
    cells = [_cell("ep1", "q", "query", "sqli", status="tested_clean", tested_by="sqlmap")]
    assert _na_untooled_blocker(cells, {"sqli": "blind bypass"}) is None


def test_na_untooled_blocker_fires():
    # N/A bypass-type cell with neither artifact_id nor tested_by → no evidence → blocks.
    cells = [_cell("ep1", "q", "query", "sqli", status="not_applicable", tested_by="")]
    result = _na_untooled_blocker(cells, {"sqli": "blind bypass"})
    assert result is not None
    assert "INTEGRITY" in result
    assert "artifact_id" in result


def test_na_untooled_blocker_with_tested_by_ok():
    cells = [_cell("ep1", "q", "query", "sqli", status="not_applicable", tested_by="sqlmap")]
    assert _na_untooled_blocker(cells, {"sqli": "blind bypass"}) is None


def test_na_untooled_blocker_with_artifact_only_ok():
    # artifact_id is the real evidence — a bypass-tested N/A cell that cites an
    # artifact but left tested_by blank must NOT block completion (the deadlock fix).
    cells = [_cell("ep1", "q", "query", "sqli", status="not_applicable",
                   tested_by="", artifact_id="http_request_120000_abcd1234")]
    assert _na_untooled_blocker(cells, {"sqli": "blind bypass"}) is None


def test_na_untooled_blocker_non_bypass_type_ignored():
    cells = [_cell("ep1", "q", "query", "idor", status="not_applicable", tested_by="")]
    assert _na_untooled_blocker(cells, {"sqli": "blind bypass"}) is None


# ---------------------------------------------------------------------------
# open_trigger_gate
# ---------------------------------------------------------------------------

from core.session import open_trigger_gate


def test_open_trigger_gate_unknown_type_returns_none():
    result = open_trigger_gate("unknown_endpoint_type", "/some/path")
    assert result is None


def test_open_trigger_gate_known_type_opens_gate(coverage_file):
    import core.session
    core.session.start("http://example.com")
    result = open_trigger_gate("graphql", "/graphql")
    # Returns the session state dict (not None)
    assert result is not None


def test_check_limits_time_exceeded_returns_stop_message(coverage_file):
    """Time limit exceeded → returns a stop message with TIME LIMIT text."""
    import core.session
    from datetime import datetime, timezone, timedelta
    core.session.start("example.com", depth="recon", max_time_minutes=1)
    # Wind back the started timestamp so elapsed >> 1 minute
    core.session._current["started"] = (
        datetime.now(timezone.utc) - timedelta(minutes=10)
    ).isoformat()
    msg = core.session.check_limits(_fake_cost())
    assert msg is not None
    assert "TIME LIMIT" in msg


def test_remaining_returns_none_for_unlimited_cost_time(coverage_file):
    """remaining() returns None for cost/time when on thorough preset (unlimited)."""
    import core.session
    core.session.start("example.com", depth="thorough")
    r = core.session.remaining(_fake_cost(calls=5))
    assert r["cost_remaining_usd"] is None
    assert r["time_remaining_minutes"] is None
    assert r["cost_pct"] == 0
    assert r["time_pct"] == 0
    assert r["calls_remaining"] == -1  # 0 = unlimited → -1


# ---------------------------------------------------------------------------
# get_intervention — force-reload from disk before reading cache
#
# The user observed 5 HIR_STUCK_ON_TARGET events fire within 137ms because
# get_intervention() (used as the dedup check by every HIR-triggering path)
# read from a cached _current that hadn't observed the previous trigger's
# flush yet. _reconcile_if_external_write() runs first now so the dedup
# sees fresh state — same family of cross-process desync we fixed for the
# Clear All path in PR #111.
# ---------------------------------------------------------------------------

def test_get_intervention_reloads_external_trigger_from_disk(tmp_path, monkeypatch):
    """A peer process (the QA daemon in the dashboard) wrote an active
    intervention to session.json. Our in-memory _current still says
    status='running'. get_intervention() must see the disk reality
    and return the intervention dict, not None — otherwise the dedup
    check passes and a duplicate HIR fires."""
    import json
    import core.session as scan_session
    session_file = tmp_path / "session.json"
    monkeypatch.setattr(scan_session, "_SESSION_FILE", session_file)
    # Set up in-memory state as 'running' (no intervention)
    scan_session.start("https://example.com")
    assert scan_session.get_intervention() is None
    # Peer process writes an intervention directly to disk
    current_disk = json.loads(session_file.read_text())
    current_disk["status"] = "intervention_required"
    current_disk["intervention"] = {
        "code": "HIR_STUCK_ON_TARGET",
        "situation": "stuck",
        "tried": [],
        "options": [],
        "triggered_at": "2026-06-12T20:00:00+00:00",
    }
    session_file.write_text(json.dumps(current_disk))
    # Bump mtime so the reconcile check fires (otherwise mtime equality
    # short-circuits the reload — that's the desired steady-state perf)
    new_mtime = session_file.stat().st_mtime + 10
    import os
    os.utime(session_file, (new_mtime, new_mtime))
    # The next get_intervention() must reflect disk reality
    iv = scan_session.get_intervention()
    assert iv is not None
    assert iv["code"] == "HIR_STUCK_ON_TARGET"


def test_get_intervention_returns_none_when_no_intervention(tmp_path, monkeypatch):
    """Negative case: status is 'running' on disk → no intervention.
    The force-reload must NOT spuriously surface anything."""
    import core.session as scan_session
    session_file = tmp_path / "session.json"
    monkeypatch.setattr(scan_session, "_SESSION_FILE", session_file)
    scan_session.start("https://example.com")
    assert scan_session.get_intervention() is None
