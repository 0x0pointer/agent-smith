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
