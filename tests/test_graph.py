"""Phase 2: knowledge-graph world-model — model, chain proposals, projection."""
import core.graph.model as gm
from core.graph import Graph, candidate_chains
from core.graph.model import (
    CREDENTIAL, ESCALATES_TO, FINDING, FOUND_ON, HOST, LEAKS,
)


class TestGraphModel:
    def test_add_and_query(self):
        g = Graph()
        g.add_node("a", HOST, "host-a")
        g.add_node("b", FINDING, "bug", severity="high")
        g.add_edge("b", "a", FOUND_ON)
        assert len(g.of_kind(HOST)) == 1
        assert g.out_edges("b", FOUND_ON)[0].dst == "a"
        assert g.in_edges("a", FOUND_ON)[0].src == "b"
        assert g.stats()["nodes"] == 2

    def test_add_node_idempotent(self):
        g = Graph()
        g.add_node("a", HOST)
        g.add_node("a", HOST, attrs_extra=1)
        assert len(g.nodes) == 1


class TestCandidateChains:
    def _base(self):
        g = Graph()
        g.add_node("host:t", HOST, "t")
        return g

    def test_escalation_lead_becomes_chain(self):
        g = self._base()
        g.add_node("finding:1", FINDING, "SQLi in login", severity="high")
        g.add_edge("finding:1", "host:t", FOUND_ON)
        g.add_edge("finding:1", "finding:1", ESCALATES_TO, lead="crack dumped hash, log in as admin")
        props = candidate_chains(g)
        assert props and "crack dumped hash" in props[0]["terminal"]

    def test_leak_plus_other_finding_composes(self):
        g = self._base()
        g.add_node("finding:1", FINDING, "creds leaked in JS bundle", severity="medium")
        g.add_edge("finding:1", "host:t", FOUND_ON)
        g.add_edge("finding:1", "host:t", LEAKS, what="credential-material")
        g.add_node("finding:2", FINDING, "admin panel exposed", severity="high")
        g.add_edge("finding:2", "host:t", FOUND_ON)
        props = candidate_chains(g)
        # a composed 3-step chain (leak -> authenticate -> second finding) exists
        assert any(len(p["steps"]) == 3 and "authenticate" in p["steps"][1] for p in props)

    def test_high_finding_plus_known_credential(self):
        g = self._base()
        g.add_node("finding:1", FINDING, "RCE via upload", severity="critical")
        g.add_edge("finding:1", "host:t", FOUND_ON)
        g.add_node("cred:alice", CREDENTIAL, "alice")
        g.add_edge("cred:alice", "host:t", gm.AUTHENTICATES)
        props = candidate_chains(g)
        assert any("lateral" in p["terminal"] or "escalation" in p["terminal"] for p in props)

    def test_nothing_to_chain(self):
        assert candidate_chains(self._base()) == []


class TestViews:
    def _graph(self):
        from core.graph.model import ENDPOINT, HAS_PARAM, PARAM, TESTED_FOR
        g = Graph()
        g.add_node("ep:e1", ENDPOINT, "POST /login", path="/login", method="POST")
        g.add_node("ep:e2", ENDPOINT, "GET /about", path="/about", method="GET")
        g.add_edge("ep:e1", "inj:sqli", TESTED_FOR, status="pending", param="u")
        g.add_edge("ep:e1", "inj:xss", TESTED_FOR, status="tested_clean", param="u")
        g.add_edge("ep:e2", "inj:sqli", TESTED_FOR, status="pending", param="q")
        return g

    def test_coverage_view_projects_matrix_shape(self):
        from core.graph import coverage_view
        v = coverage_view(self._graph())
        assert {e["path"] for e in v["endpoints"]} == {"/login", "/about"}
        assert len(v["matrix"]) == 3
        assert any(c["injection_type"] == "sqli" and c["status"] == "pending" for c in v["matrix"])

    def test_next_targets_value_ranked(self):
        from core.graph import next_targets
        t = next_targets(self._graph())
        # /login (auth, rank 1) must come before /about (rank 6)
        paths = [x["path"] for x in t]
        assert paths.index("/login") < paths.index("/about")

    def test_rank_findings_orders_by_severity_and_potential(self):
        from core.graph import rank_findings
        g = Graph()
        g.add_node("host:t", HOST)
        g.add_node("finding:lo", FINDING, "missing header", severity="low")
        g.add_edge("finding:lo", "host:t", FOUND_ON)
        g.add_node("finding:hi", FINDING, "RCE", severity="critical")
        g.add_edge("finding:hi", "host:t", FOUND_ON)
        g.add_edge("finding:hi", "finding:hi", ESCALATES_TO, lead="pivot to internal")
        ranked = rank_findings(g)
        assert ranked[0]["label"] == "RCE" and ranked[0]["score"] > ranked[1]["score"]


class TestBuildProjection:
    def test_build_from_stores(self, monkeypatch):
        import core.graph.build as gb
        import core.session as scan_session
        scan_session._current = {"status": "running", "target": "http://t.test",
                                 "known_assets": {"technologies": ["Flask"],
                                                  "credentials": [{"username": "alice"}]}}
        monkeypatch.setattr("core.findings._load", lambda: {"findings": [
            {"id": "f1", "title": "SQLi", "severity": "high", "target": "http://t.test/login"}]})
        monkeypatch.setattr("core.coverage.get_matrix", lambda: {
            "endpoints": [{"id": "e1", "path": "/login", "method": "POST",
                           "params": [{"name": "u", "type": "body_form"}]}],
            "matrix": [{"endpoint_id": "e1", "injection_type": "sqli", "status": "pending", "param": "u"}]})
        g = gb.build_graph()
        assert g.of_kind(HOST) and g.of_kind(FINDING) and g.of_kind(CREDENTIAL)
        assert any(n.kind == gm.ENDPOINT for n in g.nodes.values())
        assert any(e.kind == gm.TESTED_FOR for e in g.edges)
        scan_session._current = None
