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
    g = m.Graph()
    g.add_node("finding:f1", m.FINDING, "SQLi dump")
    g.add_node("cred:c", m.CREDENTIAL, "admin:pw")
    g.add_node("endpoint:api", m.ENDPOINT, "GET /api/admin")
    g.add_edge("finding:f1", "cred:c", m.LEAKS)
    g.add_edge("cred:c", "endpoint:api", m.AUTHENTICATES)
    _pending_edge(g, "endpoint:api")
    lines = planner._graph_dataflow_steers(g)
    assert any("Credential reuse" in l and "/api/admin" in l for l in lines)


def test_pivot_reach_steer():
    g = m.Graph()
    g.add_node("finding:ssrf", m.FINDING, "SSRF")
    g.add_node("host:internal", m.HOST, "10.0.0.5")
    g.add_node("endpoint:int", m.ENDPOINT, "GET /internal/op")
    g.add_edge("finding:ssrf", "host:internal", m.REACHES)
    g.add_edge("host:internal", "endpoint:int", m.HOSTS)
    _pending_edge(g, "endpoint:int")
    lines = planner._graph_dataflow_steers(g)
    assert any("Pivot reach" in l and "10.0.0.5" in l for l in lines)


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
