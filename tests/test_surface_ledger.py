"""
PR-C — Surface-Coverage Ledger.

Covers:
  * ledger record / pending / dedup + snapshot + untracked-skill no-op
  * discovered-population from a registered AI endpoint, a host (credential) asset,
    and a CVE finding
  * covered-attribution via add_tool_called with an active skill (exact match,
    single-instance fallback, and no over-claim when ambiguous)
  * complete() emits skipped_surfaces and still completes (NON-BLOCKING)
  * GET /api/skill-usage response shape (PR-E depends on it)

The ledger is advisory + fail-soft, so these assert behaviour, never that it blocks.
"""
import json

import pytest
from fastapi.testclient import TestClient

import core.session as session
from core.session import surface_ledger as ledger


def _running(**extra) -> dict:
    """A minimal running-session _current dict with a surface_coverage map."""
    base = {
        "status": "running",
        "skill": None,
        "surface_coverage": {},
        "gates": [],
        "deferred_gates": [],
        "skill_history": [],
        "tools_called": [],
    }
    base.update(extra)
    return base


# ── 1. record / pending / dedup / snapshot ──────────────────────────────────────

def test_record_pending_dedup_and_snapshot(monkeypatch):
    monkeypatch.setattr(session, "_current", _running())

    ledger.record_discovered("ai-redteam", "/tutor/chat")
    ledger.record_discovered("ai-redteam", "/tutor/chat")   # dedup — idempotent
    ledger.record_discovered("ai-redteam", "/admin/chat")

    assert ledger.pending("ai-redteam") == ["/tutor/chat", "/admin/chat"]

    ledger.record_covered("ai-redteam", "/tutor/chat")
    ledger.record_covered("ai-redteam", "/tutor/chat")      # dedup
    assert ledger.pending("ai-redteam") == ["/admin/chat"]

    snap = ledger.snapshot()
    assert snap["ai-redteam"]["unit"] == "ai_endpoint"
    assert snap["ai-redteam"]["discovered"] == ["/tutor/chat", "/admin/chat"]
    assert snap["ai-redteam"]["covered"] == ["/tutor/chat"]
    # snapshot is a copy — mutating it must not touch session state
    snap["ai-redteam"]["discovered"].append("/mutated")
    assert ledger.snapshot()["ai-redteam"]["discovered"] == ["/tutor/chat", "/admin/chat"]


def test_untracked_skill_is_ignored(monkeypatch):
    monkeypatch.setattr(session, "_current", _running())
    ledger.record_discovered("pentester", "/anything")   # not a re-triggerable skill
    assert "pentester" not in ledger.snapshot()
    assert ledger.pending("pentester") == []


def test_no_session_is_safe(monkeypatch):
    monkeypatch.setattr(session, "_current", None)
    # No crash, empty results.
    ledger.record_discovered("ai-redteam", "/x")
    ledger.record_covered("ai-redteam", "/x")
    ledger.attribute_covered("nmap", "1.2.3.4")
    assert ledger.pending("ai-redteam") == []
    assert ledger.snapshot() == {}
    assert ledger.pending_overview() == []
    assert ledger.advisory_line() == ""


# ── 2. discovered-population from the existing discovery signals ──────────────────

@pytest.mark.asyncio
async def test_discovered_from_ai_endpoint(monkeypatch, coverage_file):
    import core.coverage.operations as ops
    monkeypatch.setattr(session, "_current", _running())

    res = await ops.add_endpoint(
        "/tutor/chat", "POST",
        [{"name": "message", "type": "llm_prompt"}], discovered_by="spider")

    assert res["new_cells"] > 0
    assert "/tutor/chat" in ledger.pending("ai-redteam")


@pytest.mark.asyncio
async def test_discovered_auth_endpoint_is_credential_audit(monkeypatch, coverage_file):
    import core.coverage.operations as ops
    monkeypatch.setattr(session, "_current", _running())

    await ops.add_endpoint("/login", "POST",
                           [{"name": "password", "type": "body_json"}], discovered_by="spider")

    pend = ledger.pending("credential-audit")
    assert pend == ["web:/login"]


def test_discovered_from_host_credential_asset(monkeypatch):
    monkeypatch.setattr(session, "_current",
                        _running(target="10.0.0.7", known_assets={}))

    session.update_known_assets("credentials", [{"username": "admin", "password": "pw"}])

    for skill in ("post-exploit", "lateral-movement", "reverse-shell"):
        assert "10.0.0.7" in ledger.pending(skill), skill


@pytest.mark.asyncio
async def test_discovered_from_cve_finding(monkeypatch, findings_file):
    import core.findings as findings
    monkeypatch.setattr(session, "_current", _running())

    await findings.add_finding("RCE", "critical", "10.0.0.7", "desc", "evidence",
                               cve="CVE-2024-1234")

    assert ledger.pending("analyze-cve") == ["CVE-2024-1234"]
    assert ledger.pending("metasploit") == ["CVE-2024-1234"]


# ── 3. covered-attribution via add_tool_called (the gates.py hook) ───────────────

def test_covered_attribution_exact_match(monkeypatch):
    monkeypatch.setattr(session, "_current", _running(
        skill="post-exploit",
        skill_history=[{"skill": "post-exploit", "worked": False}],
        surface_coverage={"post-exploit": {
            "unit": "host", "discovered": ["10.0.0.7", "10.0.0.8"], "covered": []}},
    ))

    session.add_tool_called("nmap", "10.0.0.7")

    assert "10.0.0.7" not in ledger.pending("post-exploit")   # covered
    assert "10.0.0.8" in ledger.pending("post-exploit")       # untouched


def test_covered_attribution_url_path_for_ai(monkeypatch):
    monkeypatch.setattr(session, "_current", _running(
        skill="ai-redteam",
        skill_history=[{"skill": "ai-redteam", "worked": False}],
        surface_coverage={"ai-redteam": {
            "unit": "ai_endpoint", "discovered": ["/tutor/chat"], "covered": []}},
    ))

    session.add_tool_called("redteam", "http://target.example/tutor/chat")

    assert ledger.pending("ai-redteam") == []


def test_covered_attribution_single_instance_fallback(monkeypatch):
    monkeypatch.setattr(session, "_current", _running(
        skill="analyze-cve",
        skill_history=[{"skill": "analyze-cve", "worked": False}],
        surface_coverage={"analyze-cve": {
            "unit": "cve", "discovered": ["CVE-2024-1234"], "covered": []}},
    ))

    # No derivable target → fall back to the single discovered instance.
    session.add_tool_called("metasploit", "")

    assert ledger.pending("analyze-cve") == []


def test_covered_attribution_no_overclaim_when_ambiguous(monkeypatch):
    monkeypatch.setattr(session, "_current", _running(
        skill="post-exploit",
        skill_history=[{"skill": "post-exploit", "worked": False}],
        surface_coverage={"post-exploit": {
            "unit": "host", "discovered": ["10.0.0.7", "10.0.0.8"], "covered": []}},
    ))

    # Unmatched target + >1 discovered instance → attribute NOTHING (keep surfacing).
    session.add_tool_called("kali", "curl http://example.org/")

    assert set(ledger.pending("post-exploit")) == {"10.0.0.7", "10.0.0.8"}


def test_covered_attribution_noop_when_skill_untracked(monkeypatch):
    monkeypatch.setattr(session, "_current", _running(
        skill="pentester",
        surface_coverage={"ai-redteam": {
            "unit": "ai_endpoint", "discovered": ["/chat"], "covered": []}},
    ))
    session.add_tool_called("nmap", "/chat")
    assert ledger.pending("ai-redteam") == ["/chat"]   # untouched — active skill not tracked


# ── 4. advisory surfacer ─────────────────────────────────────────────────────────

def test_pending_overview_and_advisory_line(monkeypatch):
    monkeypatch.setattr(session, "_current", _running(surface_coverage={
        "ai-redteam": {"unit": "ai_endpoint", "discovered": ["/a", "/b"], "covered": ["/a"]},
        "post-exploit": {"unit": "host", "discovered": ["10.0.0.7"], "covered": ["10.0.0.7"]},
    }))
    ov = ledger.pending_overview()
    skills = {o["skill"]: o for o in ov}
    assert "ai-redteam" in skills and skills["ai-redteam"]["pending"] == ["/b"]
    assert "post-exploit" not in skills   # fully covered → not surfaced

    line = ledger.advisory_line()
    assert "ai-redteam on /b" in line
    assert "non-blocking" in line.lower()


# ── 5. complete() records skipped_surfaces and never blocks ──────────────────────

def test_record_skipped_surfaces(monkeypatch):
    monkeypatch.setattr(session, "_current", _running(surface_coverage={
        "ai-redteam": {"unit": "ai_endpoint", "discovered": ["/a", "/b"], "covered": ["/a"]},
    }))
    snap = ledger.record_skipped_surfaces()
    assert snap["ai-redteam"]["pending"] == ["/b"]
    assert snap["ai-redteam"]["reason"] == "budget/time"
    assert snap["ai-redteam"]["unit"] == "ai_endpoint"
    assert session._current["skipped_surfaces"] == snap


def test_cover_directive_and_bounded_nudge(monkeypatch):
    """The active cover directive names only the UNcovered instances, and the nudge is
    BOUNDED by the pending fingerprint: the same gap won't re-nudge, so it can't stall."""
    monkeypatch.setattr(session, "_current", _running(surface_coverage={
        "ai-redteam": {"unit": "ai_endpoint", "discovered": ["/chat", "/tutor"], "covered": ["/chat"]}}))
    assert ledger.nudge_needed() is True
    d = ledger.cover_directive()
    assert "/ai-redteam" in d          # names the skill to re-run
    assert "/tutor" in d               # the uncovered instance
    assert "/chat" not in d            # the covered one is not listed
    ledger.mark_nudged()
    assert ledger.nudge_needed() is False             # same gap already nudged → no re-nudge
    ledger.record_covered("ai-redteam", "/tutor")     # cover it → gap closes
    assert ledger.pending("ai-redteam") == []
    assert ledger.nudge_needed() is False             # nothing uncovered


def test_complete_nudges_once_then_proceeds(monkeypatch, findings_file):
    """PR-C refinement: the FIRST complete() with an uncovered gap bounces the agent back
    with an active cover-directive (naming the exact re-run) AND records skipped_surfaces;
    the SECOND complete() on the SAME (already-nudged) gap proceeds — bounded so it can
    never stall the way an unbounded hard gate would."""
    import mcp_server.session_tools as st
    from mcp_server.session_tools.complete import _do_complete

    monkeypatch.setattr(session, "_current", _running(
        depth="standard",
        surface_coverage={"ai-redteam": {
            "unit": "ai_endpoint", "discovered": ["/chat"], "covered": []}},
        complete_attempts=0, analysis_passes=0,
    ))
    monkeypatch.setattr(st, "_collect_completion_blockers", lambda data, effective: [])
    st._complete_attempts = 0
    st._analysis_passes = 0
    st._last_blocker_count = None

    # 1st attempt: the bounded cover-before-complete nudge fires + skipped is recorded.
    r1 = _do_complete()
    assert isinstance(r1, str)
    assert "COVER UNCOVERED SURFACE" in r1   # the bounded nudge fired
    assert "/ai-redteam" in r1               # names the skill
    assert "/chat" in r1                     # names the uncovered instance
    assert session._current["skipped_surfaces"]["ai-redteam"]["pending"] == ["/chat"]

    # 2nd attempt: SAME gap already nudged → no re-nudge → proceeds (never refuses).
    r2 = _do_complete()
    assert "COVER UNCOVERED SURFACE" not in r2


# ── 6. GET /api/skill-usage shape (PR-E consumer) ────────────────────────────────

def test_api_skill_usage_shape(tmp_path, monkeypatch):
    import core.api_server as srv
    from core.api_server import app

    sess = {
        "skill_history": [
            {"skill": "ai-redteam"}, {"skill": "ai-redteam"}, {"skill": "pentester"},
        ],
        "surface_coverage": {
            "ai-redteam": {"unit": "ai_endpoint",
                           "discovered": ["/a", "/b"], "covered": ["/a"]},
        },
    }
    f = tmp_path / "session.json"
    f.write_text(json.dumps(sess))
    monkeypatch.setattr(srv, "_SESSION_FILE", f)

    client = TestClient(app)
    r = client.get("/api/skill-usage")
    assert r.status_code == 200
    data = r.json()

    assert data["ai-redteam"] == {
        "invocations": 2,
        "unit": "ai_endpoint",
        "discovered": ["/a", "/b"],
        "covered": ["/a"],
        "pending": ["/b"],
    }
    # A non-re-triggerable skill still reports its invocation count, with empty surface.
    assert data["pentester"]["invocations"] == 1
    assert data["pentester"]["discovered"] == []
    assert data["pentester"]["pending"] == []
