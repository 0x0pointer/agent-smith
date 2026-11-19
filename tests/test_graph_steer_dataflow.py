"""World-Model Graph wiring — Fix 1 (dataflow reachability steering) + Fix 2
(primitive_unblock bridge every turn). The steers replace a hoped-for model
inference with a deterministic graph query.
"""
import pytest

from core.graph import model as m
from mcp_server.scan_engine import planner


def _pending_edge(g, ep_id, inj="ssti"):
    g.add_edge(ep_id, f"inj:{inj}", m.TESTED_FOR, status="pending")


# ── Fix 1: dataflow steers ───────────────────────────────────────────────────

def test_auth_dataflow_steer():
    g = m.Graph()
    g.add_node("endpoint:login", m.ENDPOINT, "POST /login")
    g.add_node("token:jwt", m.TOKEN, "jwt")
    g.add_node("endpoint:acct", m.ENDPOINT, "GET /account")
    g.add_edge("endpoint:login", "token:jwt", m.ISSUES)
    g.add_edge("token:jwt", "endpoint:acct", m.GRANTS)
    _pending_edge(g, "endpoint:acct")
    lines = planner._graph_dataflow_steers(g)
    assert any("Auth dataflow" in l and "/account" in l for l in lines)


def test_auth_dataflow_not_emitted_when_target_fully_tested():
    g = m.Graph()
    g.add_node("endpoint:login", m.ENDPOINT, "POST /login")
    g.add_node("token:jwt", m.TOKEN, "jwt")
    g.add_node("endpoint:acct", m.ENDPOINT, "GET /account")
    g.add_edge("endpoint:login", "token:jwt", m.ISSUES)
    g.add_edge("token:jwt", "endpoint:acct", m.GRANTS)
    g.add_edge("endpoint:acct", "inj:ssti", m.TESTED_FOR, status="tested_clean")  # addressed
    assert planner._graph_dataflow_steers(g) == []


def test_credential_reuse_steer():
    # build.py always lands AUTHENTICATES on a HOST (never directly on an endpoint),
    # so the steer must hop HOST --HOSTS--> endpoint to find the pending surface.
    g = m.Graph()
    g.add_node("finding:f1", m.FINDING, "SQLi dump")
    g.add_node("cred:c", m.CREDENTIAL, "admin:pw")
    g.add_node("host:t", m.HOST, "t.test")
    g.add_node("endpoint:api", m.ENDPOINT, "GET /api/admin")
    g.add_edge("finding:f1", "cred:c", m.LEAKS)
    g.add_edge("cred:c", "host:t", m.AUTHENTICATES)       # ← real build.py topology
    g.add_edge("host:t", "endpoint:api", m.HOSTS)
    _pending_edge(g, "endpoint:api")
    lines = planner._graph_dataflow_steers(g)
    assert any("Credential reuse" in l and "/api/admin" in l for l in lines)


def test_credential_reuse_steer_via_leaked_token():
    # LEAKS can expose a TOKEN principal too — same chain shape must still fire.
    g = m.Graph()
    g.add_node("finding:f1", m.FINDING, "JWT leak")
    g.add_node("token:jwt", m.TOKEN, "jwt")
    g.add_node("host:t", m.HOST, "t.test")
    g.add_node("endpoint:api", m.ENDPOINT, "GET /api/admin")
    g.add_edge("finding:f1", "token:jwt", m.LEAKS)
    g.add_edge("token:jwt", "host:t", m.AUTHENTICATES)
    g.add_edge("host:t", "endpoint:api", m.HOSTS)
    _pending_edge(g, "endpoint:api")
    assert any("Credential reuse" in l for l in planner._graph_dataflow_steers(g))


def test_pivot_reach_steer_enumerate_when_host_has_no_endpoints():
    # The REALISTIC case: a REACHES-discovered pivot host carries NO endpoints
    # (recon hasn't enumerated it yet) → steer to ENUMERATE, not to test nothing.
    g = m.Graph()
    g.add_node("finding:ssrf", m.FINDING, "SSRF")
    g.add_node("host:internal", m.HOST, "10.0.0.5")
    g.add_edge("finding:ssrf", "host:internal", m.REACHES)
    lines = planner._graph_dataflow_steers(g)
    assert any("Pivot reach" in l and "10.0.0.5" in l and "enumerate" in l.lower() for l in lines)


def test_pivot_reach_steer_tests_when_endpoints_present():
    # Rare case: the reached host already exposes an untested endpoint → test it.
    g = m.Graph()
    g.add_node("finding:ssrf", m.FINDING, "SSRF")
    g.add_node("host:internal", m.HOST, "10.0.0.5")
    g.add_node("endpoint:int", m.ENDPOINT, "GET /internal/op")
    g.add_edge("finding:ssrf", "host:internal", m.REACHES)
    g.add_edge("host:internal", "endpoint:int", m.HOSTS)
    _pending_edge(g, "endpoint:int")
    lines = planner._graph_dataflow_steers(g)
    assert any("Pivot reach" in l and "/internal/op" in l and "test it" in l.lower() for l in lines)


def test_dataflow_capped_at_two():
    g = m.Graph()
    # three distinct auth dataflows → still at most 2 lines emitted
    for i in range(3):
        g.add_node(f"endpoint:login{i}", m.ENDPOINT, f"POST /login{i}")
        g.add_node(f"token:jwt{i}", m.TOKEN, f"jwt{i}")
        g.add_node(f"endpoint:acct{i}", m.ENDPOINT, f"GET /account{i}")
        g.add_edge(f"endpoint:login{i}", f"token:jwt{i}", m.ISSUES)
        g.add_edge(f"token:jwt{i}", f"endpoint:acct{i}", m.GRANTS)
        _pending_edge(g, f"endpoint:acct{i}")
    assert len(planner._graph_dataflow_steers(g)) <= 2


def test_dataflow_failsoft_on_bad_graph():
    assert planner._graph_dataflow_steers(object()) == []


# ── Fix 2: primitive_unblock bridge ──────────────────────────────────────────

def test_bridge_steer(monkeypatch):
    import mcp_server.report_tools.diagrams as diag
    monkeypatch.setattr(diag, "_proven_chain_fids", lambda: set())
    g = m.Graph()
    g.add_node("finding:prov", m.FINDING, "SQLi file read", severity="high")
    g.add_node("prim:rce", m.PRIMITIVE, "code_exec")
    g.add_node("finding:blk", m.FINDING, "Werkzeug console", severity="high")
    g.add_edge("finding:prov", "prim:rce", m.PROVIDES)
    g.add_edge("finding:blk", "prim:rce", m.REQUIRES)
    lines = planner._graph_bridge_steer(g)
    assert any("Chain bridge" in l and "code_exec" in l for l in lines)


def test_bridge_failsoft_on_bad_graph():
    assert planner._graph_bridge_steer(object()) == []


# ── integration: budget cap ──────────────────────────────────────────────────

def test_add_graph_steer_budget_capped(monkeypatch):
    import core.graph as cg
    import mcp_server.report_tools.diagrams as diag
    monkeypatch.setattr(diag, "_proven_chain_fids", lambda: set())

    g = m.Graph()
    # a bridge + an auth dataflow + a ranked finding all present
    g.add_node("finding:prov", m.FINDING, "SQLi file read", severity="high")
    g.add_node("prim:rce", m.PRIMITIVE, "code_exec")
    g.add_node("finding:blk", m.FINDING, "Werkzeug console", severity="high")
    g.add_edge("finding:prov", "prim:rce", m.PROVIDES)
    g.add_edge("finding:blk", "prim:rce", m.REQUIRES)
    g.add_node("endpoint:login", m.ENDPOINT, "POST /login")
    g.add_node("token:jwt", m.TOKEN, "jwt")
    g.add_node("endpoint:acct", m.ENDPOINT, "GET /account")
    g.add_edge("endpoint:login", "token:jwt", m.ISSUES)
    g.add_edge("token:jwt", "endpoint:acct", m.GRANTS)
    _pending_edge(g, "endpoint:acct")
    monkeypatch.setattr(cg, "build_graph", lambda: g)

    rec: list[str] = []
    planner._add_graph_steer(rec)
    assert len(rec) <= planner._GRAPH_STEER_MAX
    assert any("Chain bridge" in r for r in rec)  # highest-value steer wins a slot


# ── build-topology integration ───────────────────────────────────────────────
# REGRESSION guard: each dataflow steer must fire on the graph core.graph.build
# actually PROJECTS, not just on an idealized hand-built pattern. The earlier
# versions of B (credential reuse) and C (pivot reach) matched topologies
# build_graph() never emits — AUTHENTICATES landing on an endpoint, and a
# discovered pivot host carrying endpoints — so they passed here while staying
# dead in production. These tests build through build.py's own helpers.

from core.graph import build as _build


def _root_graph(root="target.test"):
    g = m.Graph()
    g.add_node(f"host:{root}", m.HOST, root)
    return g, root


def test_auth_steer_fires_on_build_topology():
    g, root = _root_graph()
    g.add_node("ep:login", m.ENDPOINT, "POST /login", path="/login", method="POST", auth_context="none")
    g.add_node("ep:acct", m.ENDPOINT, "GET /account", path="/account", method="GET", auth_context="jwt")
    for ep in ("ep:login", "ep:acct"):
        g.add_edge(f"host:{root}", ep, m.HOSTS)
    _pending_edge(g, "ep:acct")
    _build._add_auth_flow(g, {"login": "ep:login", "acct": "ep:acct"}, root)
    assert any("Auth dataflow" in l and "/account" in l for l in planner._graph_dataflow_steers(g))


def test_credential_reuse_fires_on_build_topology():
    g, root = _root_graph()
    g.add_node("ep:api", m.ENDPOINT, "GET /api/admin", path="/api/admin", method="GET", auth_context="none")
    g.add_edge(f"host:{root}", "ep:api", m.HOSTS)
    _pending_edge(g, "ep:api", inj="sqli")
    _build._add_credential_nodes(g, {"credentials": [{"username": "admin", "source": "dump"}]}, root)
    g.add_node("finding:f1", m.FINDING, "SQLi dumps admin credentials")
    # cred 'admin' AUTHENTICATES the root host whose /api/admin still has a pending cell
    _build._add_leak_edges(g, "finding:f1", "sqli dump exposes admin password credential", root)
    lines = planner._graph_dataflow_steers(g)
    assert any("Credential reuse" in l and "/api/admin" in l for l in lines), lines


def test_pivot_reach_fires_enumerate_on_build_topology(monkeypatch):
    g, root = _root_graph()
    g.add_node("finding:ssrf", m.FINDING, "SSRF")
    import core.findings as F
    monkeypatch.setattr(F, "_load", lambda: {"findings": [
        {"id": "ssrf", "title": "SSRF", "description": "reaches internal host 10.0.0.9",
         "evidence": "connected to 10.0.0.9", "target": root}]})
    _build._add_discovered_hosts(g, root, {})
    lines = planner._graph_dataflow_steers(g)
    assert any("Pivot reach" in l and "10.0.0.9" in l and "enumerate" in l.lower() for l in lines), lines
