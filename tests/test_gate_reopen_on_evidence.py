"""Re-open a prematurely-dismissed capability gate when later evidence contradicts the dismissal
— the root fix for the dropped SQLi->RCE->internal-pivot chain — plus the proactive escalation
nudge baked into the re-opened gate's trigger.

Scenario reproduced: post_exploit_rce dismissed 'no code execution' BEFORE the auth-gated SQLi was
reachable; SQLi confirmed later must RE-OPEN the gate (once) with a concrete escalation directive.
"""
import pytest

import core.session as scan_session
from core import escalation


@pytest.fixture
def running(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
    scan_session._current = None
    scan_session.start("http://t.test:30081", depth="danger")
    yield
    scan_session._current = None


def _gate(gid):
    return next(g for g in scan_session.get()["gates"] if g["id"] == gid)


def _dismiss(gid, skills, rationale):
    scan_session.trigger_gate(gid, f"{gid} triggered", skills)
    scan_session.dismiss_gate(gid, rationale)


# ── core reopen_gate_on_evidence ─────────────────────────────────────────────

def test_reopen_flips_not_applicable_to_pending_once(running):
    _dismiss("post_exploit_rce", ["post-exploit", "reverse-shell"], "no code execution")
    assert _gate("post_exploit_rce")["status"] == "not_applicable"

    assert scan_session.reopen_gate_on_evidence(
        "post_exploit_rce", "SQLi confirmed", new_trigger="ESCALATE NOW") is not None
    g = _gate("post_exploit_rce")
    assert g["status"] == "pending" and g["evidence_reopened"] and g["trigger"] == "ESCALATE NOW"
    assert g.get("dismissal") is None and "prior_rationale" in g["reopened"]

    # bounded: an INFORMED re-dismissal is respected — a later contradicting signal won't re-open
    scan_session.dismiss_gate("post_exploit_rce", "assessed: MySQL, no stacked queries, no RCE path")
    assert scan_session.reopen_gate_on_evidence("post_exploit_rce", "another SQLi") is None
    assert _gate("post_exploit_rce")["status"] == "not_applicable"


def test_reopen_noop_on_pending_or_missing(running):
    scan_session.trigger_gate("post_exploit_rce", "t", ["post-exploit"])   # pending, never dismissed
    assert scan_session.reopen_gate_on_evidence("post_exploit_rce", "x") is None   # not a dismissal
    assert scan_session.reopen_gate_on_evidence("no_such_gate", "x") is None


# ── finding-driven reopen + escalation nudge ─────────────────────────────────

def test_sqli_finding_reopens_rce_gate_with_escalation_nudge(running):
    _dismiss("post_exploit_rce", ["post-exploit", "reverse-shell"], "all injection probes clean")
    assert escalation.reopen_gates_on_finding(
        "SQL Injection with UNION-based Data Exfiltration on /api/transactions",
        "boolean + UNION confirmed", "critical") == ["post_exploit_rce"]
    trig = _gate("post_exploit_rce")["trigger"]
    assert _gate("post_exploit_rce")["status"] == "pending"
    assert "COPY ... TO PROGRAM" in trig and "pg_read_file" in trig and "xp_cmdshell" in trig


def test_file_upload_also_reopens_rce(running):
    _dismiss("post_exploit_rce", ["post-exploit"], "no code execution")
    assert escalation.reopen_gates_on_finding(
        "Arbitrary File Upload on /upload_profile_picture - No File Type Validation", "", "critical")


def test_ssrf_finding_reopens_internal_network(running):
    _dismiss("internal_network", ["network-assess"], "single-host app, no internal network")
    assert escalation.reopen_gates_on_finding(
        "Server-Side Request Forgery (SSRF) on /upload_profile_picture_url",
        "server connects to attacker-controlled URL", "critical") == ["internal_network"]
    assert "169.254.169.254" in _gate("internal_network")["trigger"]


def test_non_codeexec_and_info_do_not_reopen(running):
    _dismiss("post_exploit_rce", ["post-exploit"], "no code execution")
    assert escalation.reopen_gates_on_finding(
        "Horizontal BOLA on /transfer via JWT Forgery", "idor", "critical") == []   # not a primitive
    assert escalation.reopen_gates_on_finding("SQL Injection somewhere", "", "info") == []  # info sev
    assert _gate("post_exploit_rce")["status"] == "not_applicable"


# ── IMPROVEMENT-PLAN 1.5: a disclosed credential/secret primitive feeds back ──

def test_stolen_sa_token_reopens_internal_and_rce(running):
    """A synthesized credential/secret (here a K8s service-account token) must feed BACK:
    re-open both the internal-network and RCE gates with a reuse directive — so the stolen
    token drives cluster-API + lateral reach instead of dead-ending as a note."""
    _dismiss("internal_network", ["network-assess"], "single-host app")
    _dismiss("post_exploit_rce", ["post-exploit"], "no code execution")
    reopened = escalation.reopen_gates_on_finding(
        "Kubernetes service account token readable via pg_read_file(/var/run/secrets/...)",
        "SA token exfiltrated", "critical")
    assert set(reopened) == {"internal_network", "post_exploit_rce"}
    assert "REUSE IT NOW" in _gate("internal_network")["trigger"]
    assert "cred x service matrix" in _gate("post_exploit_rce")["trigger"]


def test_leaked_api_key_reopens_as_credential_primitive(running):
    _dismiss("internal_network", ["network-assess"], "no internal network")
    assert "internal_network" in escalation.reopen_gates_on_finding(
        "Hardcoded AWS access key exposed in /static/app.js", "leaked credential", "high")


def test_credential_primitive_classifier():
    assert escalation.is_credential_primitive("Exposed kubeconfig on /debug")
    assert escalation.is_credential_primitive("JWT signing secret leaked in source")
    assert not escalation.is_credential_primitive("Reflected XSS on /search")


# ── end-to-end: the completion blocker surfaces the escalation after reopen ───

def test_completion_blocker_surfaces_escalation_after_reopen(running):
    from mcp_server.session_tools.completion_gates import _gate_blockers
    _dismiss("post_exploit_rce", ["post-exploit", "reverse-shell"], "no code execution")
    escalation.reopen_gates_on_finding("SQL Injection on /api/transactions", "", "critical")
    blockers = _gate_blockers()
    assert any("post_exploit_rce" in b and "COPY ... TO PROGRAM" in b for b in blockers)


# ── host-driven reopen via the deep-pivot promoter ───────────────────────────

def test_genuine_internal_host_reopens_internal_network(running):
    from core import pivot
    pivot.promote_internal_hosts("pod 10.44.0.9")                 # triggers internal_network (pending)
    scan_session.dismiss_gate("internal_network", "misread — thought 10.44.0.9 was our own IP")
    assert _gate("internal_network")["status"] == "not_applicable"
    pivot.promote_internal_hosts("another pod 10.44.0.22")        # NEW genuine host after dismissal
    g = _gate("internal_network")
    assert g["status"] == "pending" and "RE-OPENED" in g["trigger"]


def test_metadata_only_host_does_not_reopen_internal_network(running):
    from core import pivot
    pivot.promote_internal_hosts("pod 10.44.0.9")
    scan_session.dismiss_gate("internal_network", "assessed")
    pivot.promote_internal_hosts("saw 169.254.169.254 and metadata.google.internal")  # meta only
    assert _gate("internal_network")["status"] == "not_applicable"   # metadata is cloud_pivot, not this
