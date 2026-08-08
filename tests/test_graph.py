"""Phase 2: knowledge-graph world-model — model, chain proposals, projection."""
import json

import pytest

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


class TestGraphSteer:
    def test_add_graph_steer_pushes_finding_and_target(self, monkeypatch):
        import core.graph as cg
        from mcp_server.scan_engine import planner
        monkeypatch.setattr(cg, "build_graph", lambda: object())
        monkeypatch.setattr(cg, "rank_findings",
                            lambda g: [{"label": "RCE via upload", "severity": "critical", "why": "critical"}])
        monkeypatch.setattr(cg, "next_targets",
                            lambda g, limit=1: [{"path": "/admin", "pending_cells": 4}])
        rec: list[str] = []
        planner._add_graph_steer(rec)
        assert any("RCE via upload" in r for r in rec)
        assert any("/admin" in r for r in rec)

    def test_add_graph_steer_failsoft(self, monkeypatch):
        import core.graph as cg
        from mcp_server.scan_engine import planner

        def boom():
            raise RuntimeError("no graph")
        monkeypatch.setattr(cg, "build_graph", boom)
        rec: list[str] = []
        planner._add_graph_steer(rec)  # must not raise
        assert rec == []


class TestGraphApi:
    @pytest.mark.asyncio
    async def test_api_graph_shape(self, monkeypatch):
        import core.session as scan_session
        from core.api_server.routes.findings_routes import api_graph
        scan_session._current = {"status": "running", "target": "http://t.test", "known_assets": {}}
        monkeypatch.setattr("core.findings._load", lambda: {"findings": [
            {"id": "f1", "title": "SQLi", "severity": "high", "target": "http://t.test/login"}]})
        monkeypatch.setattr("core.coverage.get_matrix", lambda: {"endpoints": [], "matrix": []})
        body = json.loads((await api_graph()).body)
        assert set(body) >= {"stats", "nodes", "edges", "candidate_chains",
                             "ranked_findings", "next_targets"}
        assert body["stats"]["nodes"] >= 1
        scan_session._current = None


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


class TestDiscoveredHosts:
    """Generic pivot linking: a host that surfaces in a finding's evidence is
    materialized as its OWN node linked back through the finding (REACHES), so the
    radial view shows separate circles for isolated hosts and connected circles for
    pivots. Not SSRF-specific — any provenance signal (SSRF, XXE/file-leak, lateral
    cred-reuse, internal/cloud DNS) links two hosts."""

    def _build(self, monkeypatch, findings, known_assets=None, matrix=None):
        import core.graph.build as gb
        import core.session as scan_session
        scan_session._current = {"status": "running", "target": "http://t.test",
                                 "known_assets": known_assets or {}}
        monkeypatch.setattr("core.findings._load", lambda: {"findings": findings})
        monkeypatch.setattr("core.coverage.get_matrix",
                            lambda: matrix or {"endpoints": [], "matrix": []})
        gb.invalidate_graph_cache()
        g = gb.build_graph()
        scan_session._current = None
        return g

    def _reached(self, g):
        return {g.nodes[e.dst].label: e.attrs.get("via")
                for e in g.edges if e.kind == gm.REACHES}

    def _reaches(self, g):
        return [e for e in g.edges if e.kind == gm.REACHES]

    def test_ssrf_internal_ip_links_new_host(self, monkeypatch):
        g = self._build(monkeypatch, [{
            "id": "f1", "title": "SSRF in fetch param", "severity": "high",
            "target": "http://t.test/api/fetch",
            "description": "The url param let us reach the cloud metadata service at "
                           "169.254.169.254 and read IAM creds."}])
        reached = self._reached(g)
        assert "169.254.169.254" in reached and reached["169.254.169.254"] == "ssrf"
        host = next(n for n in g.of_kind(HOST) if n.label == "169.254.169.254")
        assert host.attrs.get("discovered") is True

    def test_k8s_service_dns_via_file_leak(self, monkeypatch):
        g = self._build(monkeypatch, [{
            "id": "f2", "title": "Arbitrary file read", "severity": "high",
            "target": "http://t.test/download",
            "description": "Path traversal leaked a config naming the DB host "
                           "postgres.default.svc.cluster.local."}])
        reached = self._reached(g)
        assert "postgres.default.svc.cluster.local" in reached
        assert reached["postgres.default.svc.cluster.local"] == "file-disclosure"

    def test_root_host_mention_makes_no_pivot(self, monkeypatch):
        g = self._build(monkeypatch, [{
            "id": "f3", "title": "XSS", "severity": "medium",
            "target": "http://t.test/search",
            "description": "Reflected XSS on http://t.test/search — no pivot here."}])
        assert not [e for e in g.edges if e.kind == gm.REACHES]

    def test_external_fqdn_only_linked_when_a_known_asset(self, monkeypatch):
        # An arbitrary external hostname in prose is NOT linked...
        g = self._build(monkeypatch, [{
            "id": "f4", "title": "note", "severity": "low",
            "description": "docs at api.stripe.com were referenced."}])
        assert not [e for e in g.edges if e.kind == gm.REACHES]
        # ...but the same hostname IS linked once the scan recorded it as an asset.
        g2 = self._build(monkeypatch, [{
            "id": "f5", "title": "SSRF", "severity": "high",
            "description": "Forged a request to internal-api.corp.example reaching it."}],
            known_assets={"hosts": [{"value": "internal-api.corp.example"}]})
        assert "internal-api.corp.example" in self._reached(g2)

    # ── Regression guards (pre-commit review) ────────────────────────────────
    def test_dot_local_filename_is_not_a_host(self, monkeypatch):
        # File-read/traversal findings routinely name *.local FILES — never a host.
        g = self._build(monkeypatch, [{
            "id": "f6", "title": "Arbitrary file read", "severity": "high",
            "description": "Path traversal retrieved /var/www/html/wp-config.local from disk."}])
        assert not self._reaches(g)

    def test_version_number_is_not_a_host(self, monkeypatch):
        # A 4-part tool version is structurally an IP but must NOT become a host.
        g = self._build(monkeypatch, [{
            "id": "f7", "title": "SQLi", "severity": "high",
            "description": "Confirmed with sqlmap 1.7.2.1 against the id param."}])
        assert not self._reaches(g)

    def test_short_asset_not_substring_matched(self, monkeypatch):
        # A short recorded asset ('api') must not link via substring of unrelated prose.
        g = self._build(monkeypatch, [{
            "id": "f8", "title": "note", "severity": "low",
            "description": "the request was rapid and the app capitalized the token."}],
            known_assets={"hosts": [{"value": "api"}]})
        assert not self._reaches(g)

    def test_nested_meta_host_is_one_node_one_edge(self, monkeypatch):
        # kubernetes.default ⊂ kubernetes.default.svc ⊂ …cluster.local — one host, not three.
        g = self._build(monkeypatch, [{
            "id": "f9", "title": "SSRF", "severity": "high",
            "description": "Reached kubernetes.default.svc.cluster.local from the pod."}])
        khosts = [n for n in g.of_kind(HOST) if "kubernetes" in n.label]
        assert len(khosts) == 1 and len(self._reaches(g)) == 1

    def test_bare_and_port_forms_collapse_to_one_host(self, monkeypatch):
        g = self._build(monkeypatch, [{
            "id": "f10", "title": "SSRF", "severity": "high",
            "description": "Reached 10.0.0.5 and also 10.0.0.5:8080 internally."}])
        hosts = [n for n in g.of_kind(HOST) if n.label.startswith("10.0.0.5")]
        assert len(hosts) == 1

    def test_two_findings_same_host_reuse_node_but_each_gets_an_edge(self, monkeypatch):
        g = self._build(monkeypatch, [
            {"id": "f11", "title": "SSRF in fetch", "severity": "high",
             "description": "Reached internal host 10.0.0.9."},
            {"id": "f12", "title": "SSRF in webhook", "severity": "high",
             "description": "Also reached 10.0.0.9 via the webhook param."}])
        hosts = [n for n in g.of_kind(HOST) if n.label == "10.0.0.9"]
        assert len(hosts) == 1                    # one node reused
        assert len(self._reaches(g)) == 2         # one REACHES edge per discovering finding

    def test_endpoint_host_is_not_reflagged_discovered(self, monkeypatch):
        # A host already modelled as a real target (absolute-URL endpoint) must stay a
        # separate real target — no REACHES, not discovered — even when a finding names it.
        g = self._build(monkeypatch, [{
            "id": "f13", "title": "SSRF", "severity": "high",
            "description": "Reached 10.0.0.9 internally."}],
            matrix={"endpoints": [{"id": "e1", "path": "http://10.0.0.9/admin",
                                   "method": "GET", "params": [{"name": "q", "type": "query"}]}],
                    "matrix": []})
        assert not self._reaches(g)
        host = next(n for n in g.of_kind(HOST) if n.label == "10.0.0.9")
        assert not host.attrs.get("discovered")


class TestGraphCache:
    """build_graph() is memoized on the (mtime,size) of its three store files —
    it was re-projecting all three on every QA-daemon tick and report(note)."""

    def test_memoizes_until_input_signature_changes(self, monkeypatch):
        import core.graph.build as gb
        calls = {"n": 0}
        base = gb._assemble

        def counting():
            calls["n"] += 1
            return base()

        monkeypatch.setattr(gb, "_assemble", counting)
        monkeypatch.setattr(gb, "_cache_key", lambda: ("sig-v1",))
        gb.invalidate_graph_cache()

        first = gb.build_graph()
        second = gb.build_graph()
        assert calls["n"] == 1              # second call served from cache
        assert first is second             # same instance, not a rebuild

        monkeypatch.setattr(gb, "_cache_key", lambda: ("sig-v2",))
        third = gb.build_graph()
        assert calls["n"] == 2              # input signature changed → rebuild
        assert third is not first

        gb.invalidate_graph_cache()
        gb.build_graph()
        assert calls["n"] == 3              # explicit invalidation forces a rebuild
        gb.invalidate_graph_cache()

    def test_cache_key_is_stable_and_read_free(self, monkeypatch, tmp_path):
        """The key stats the three store files (mtime,size) — never reads them —
        and a missing file degrades to (0,0) rather than raising."""
        import core.graph.build as gb
        import core.paths as paths
        sess = tmp_path / "session.json"
        sess.write_text("{}")
        monkeypatch.setattr(paths, "SESSION_FILE", sess)
        monkeypatch.setattr(paths, "FINDINGS_FILE", tmp_path / "missing_findings.json")
        monkeypatch.setattr(paths, "COVERAGE_FILE", tmp_path / "missing_cov.json")
        k1 = gb._cache_key()
        assert k1[1] == (0, 0) and k1[2] == (0, 0)   # missing files → (0,0)
        assert gb._cache_key() == k1                 # stable when nothing changes
        sess.write_text('{"status": "running"}')     # bigger content → new size
        assert gb._cache_key() != k1
