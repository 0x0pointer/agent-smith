"""
Compositional cross-finding chaining — the SQLi-file-read↔Werkzeug-PIN bridge and
its supporting layers (primitives taxonomy, graph bridge rule + host guard, build
edge emission, QA obligation, and the VERIFY metric).
"""
import pytest

from core.graph import primitives as P
from core.graph import model as m, chains, build
from core.qa_agent import checks_depth as cd
from core import metrics


# ── Primitive taxonomy ───────────────────────────────────────────────────────

class TestPrimitives:
    def _bridge(self, prov, req):
        return P.classify_provides(*prov) & P.classify_requires(*req)

    def test_exemplar_sqli_to_werkzeug_pin(self):
        assert "file_read" in self._bridge(
            ("SQL Injection in /api/transactions", "pg_read_server_file confirmed; dumped the users table"),
            ("Werkzeug console exposed at /console", "PIN-gated; leaks machine_id; derive the pin"))

    def test_exemplar_ssrf_to_imds(self):
        assert "network_reach" in self._bridge(
            ("SSRF via /upload", "server-side request forgery fetches arbitrary URLs"),
            ("AWS IMDS role creds", "instance metadata reachable only from an adjacent pod, internal-only"))

    def test_exemplar_secret_to_jwt_forge(self):
        assert "signing_key" in self._bridge(
            ("Weak JWT signing secret", "hs256 secret leaked, jwt_secret = secret123"),
            ("JWT forgery to admin", "cannot forge without the signing key to forge a token"))

    def test_exemplar_lfi_to_config(self):
        assert "file_read" in self._bridge(
            ("LFI in /download", "path traversal read any file"),
            ("Config holds DB creds", "blocked on file-read, need to read /app/config.py"))

    def test_anti_spam_plain_finding_requires_nothing(self):
        # Ordinary prose must not manufacture a REQUIRES (narrow blocker-shaped markers only)
        assert P.classify_requires("Reflected XSS in search", "the q param reflects unsanitized input") == set()

    def test_code_exec_is_terminal_never_required(self):
        assert "code_exec" not in P.classify_requires("need remote code execution here", "blocked on rce")

    def test_coerce_drops_unknown(self):
        assert P.coerce_primitive_list(["file_read", "bogus", "CODE_EXEC", "file_read"]) == ["file_read", "code_exec"]

    def test_coerce_non_list(self):
        assert P.coerce_primitive_list("file_read") == []


# ── build.py primitive-edge emission ─────────────────────────────────────────

class TestBuildPrimitiveEdges:
    def test_emits_provides_and_requires_from_text(self):
        g = m.Graph()
        build._add_primitive_edges(g, "finding:x", {
            "title": "Postgres SQLi", "description": "pg_read_server_file gives arbitrary file read"})
        assert any(e.kind == m.PROVIDES and e.dst == "prim:file_read" for e in g.out_edges("finding:x"))

    def test_explicit_fields_union_with_classifier(self):
        g = m.Graph()
        build._add_primitive_edges(g, "finding:y", {
            "title": "Custom bug", "description": "", "provides": ["network_reach"], "requires": ["file_read"]})
        outs = {(e.kind, e.dst) for e in g.out_edges("finding:y")}
        assert (m.PROVIDES, "prim:network_reach") in outs
        assert (m.REQUIRES, "prim:file_read") in outs

    def test_bad_explicit_field_is_dropped_not_fatal(self):
        g = m.Graph()
        build._add_primitive_edges(g, "finding:z", {"title": "x", "provides": ["bogus"]})
        assert not any(e.kind == m.PROVIDES for e in g.out_edges("finding:z"))  # dropped, no crash


# ── graph bridge rule + same-host guard ──────────────────────────────────────

def _bridge_graph():
    g = m.Graph()
    g.add_node("finding:sqli", m.FINDING, "Postgres SQLi", severity="critical")
    g.add_node("host:H", m.HOST, "H"); g.add_edge("finding:sqli", "host:H", m.FOUND_ON)
    g.add_node("prim:file_read", m.PRIMITIVE, "file_read")
    g.add_edge("finding:sqli", "prim:file_read", m.PROVIDES)
    g.add_node("finding:wz", m.FINDING, "Werkzeug console PIN-locked", severity="high")
    g.add_edge("finding:wz", "host:H", m.FOUND_ON)
    g.add_edge("finding:wz", "prim:file_read", m.REQUIRES)
    return g


class TestBridgeRule:
    def test_same_host_bridge_fires(self):
        cc = chains.candidate_chains(_bridge_graph())
        bridges = [c for c in cc if c.get("kind") == "primitive_unblock"]
        assert len(bridges) == 1
        b = bridges[0]
        assert b["provider_id"] == "sqli" and b["blocked_id"] == "wz" and b["primitive"] == "file_read"
        assert b["combined_severity"] == "critical"

    def test_cross_host_bridge_suppressed(self):
        g = _bridge_graph()
        g.add_node("finding:other", m.FINDING, "Other-host blocked", severity="high")
        g.add_node("host:Y", m.HOST, "Y"); g.add_edge("finding:other", "host:Y", m.FOUND_ON)
        g.add_edge("finding:other", "prim:file_read", m.REQUIRES)
        bridges = [c for c in chains.candidate_chains(g) if c.get("kind") == "primitive_unblock"]
        assert not any(b["blocked_id"] == "other" for b in bridges)  # cross-host dropped

    def test_self_bridge_excluded(self):
        g = m.Graph()
        g.add_node("finding:s", m.FINDING, "Self", severity="high")
        g.add_node("prim:file_read", m.PRIMITIVE, "file_read")
        g.add_edge("finding:s", "prim:file_read", m.PROVIDES)
        g.add_edge("finding:s", "prim:file_read", m.REQUIRES)  # provides AND requires same prim
        assert not [c for c in chains.candidate_chains(g) if c.get("kind") == "primitive_unblock"]


# ── QA obligation ────────────────────────────────────────────────────────────

class TestCompositionObligation:
    def _patch_bridge(self, monkeypatch, bridges):
        import core.graph
        monkeypatch.setattr(core.graph, "build_graph", lambda: object())
        monkeypatch.setattr(core.graph, "candidate_chains", lambda g: bridges)
        # never write steering during the test
        import core.qa_agent as _qa
        monkeypatch.setattr(_qa, "_has_pending_directives", lambda: True)

    _BRIDGE = [{"kind": "primitive_unblock", "provider_id": "B", "blocked_id": "A", "primitive": "file_read"}]

    def test_fires_on_unattempted_bridge(self, monkeypatch):
        self._patch_bridge(monkeypatch, self._BRIDGE)
        alert = cd._check_composition_obligation({"findings": [{"id": "A"}, {"id": "B"}], "chains": []})
        assert alert and alert["code"] == "COMPOSITION_UNATTEMPTED"
        assert alert["blocking"] is True and alert["urgency"] == "high"

    def test_discharged_by_recorded_chain(self, monkeypatch):
        self._patch_bridge(monkeypatch, self._BRIDGE)
        fd = {"findings": [{"id": "A"}, {"id": "B"}],
              "chains": [{"steps": [{"from_finding_id": "B", "to_finding_id": "A"}]}]}
        assert cd._check_composition_obligation(fd) is None

    def test_discharged_by_dismissed_lead(self, monkeypatch):
        self._patch_bridge(monkeypatch, self._BRIDGE)
        fd = {"findings": [{"id": "A", "escalation_leads": [{"lead": "tried the bridge", "status": "dismissed"}]},
                           {"id": "B"}], "chains": []}
        assert cd._check_composition_obligation(fd) is None

    def test_no_bridge_no_alert(self, monkeypatch):
        self._patch_bridge(monkeypatch, [])
        assert cd._check_composition_obligation({"findings": [], "chains": []}) is None


# ── VERIFY metric ────────────────────────────────────────────────────────────

class TestCompositionMetric:
    def test_empty_is_safe(self):
        assert metrics._compute_composition({}) == {
            "proven_chains_total": 0, "multi_finding_chains": 0, "blocked_then_bridged_rate_pct": None}

    def test_blocked_then_bridged_rate(self):
        fd = {"findings": [{"id": "A", "requires": ["file_read"]}, {"id": "B"}],
              "chains": [{"steps": [{"from_finding_id": "B", "to_finding_id": "A"}]}]}
        r = metrics._compute_composition(fd)
        assert r["multi_finding_chains"] == 1 and r["blocked_then_bridged_rate_pct"] == 100.0

    def test_blocked_but_not_bridged_is_zero(self):
        fd = {"findings": [{"id": "A", "requires": ["file_read"]}], "chains": []}
        assert metrics._compute_composition(fd)["blocked_then_bridged_rate_pct"] == 0.0


# ── report boundary + SURFACE push ───────────────────────────────────────────

class TestReportBoundary:
    @pytest.mark.asyncio
    async def test_add_finding_stores_capabilities(self, findings_file):
        import core.findings as F
        await F.add_finding("Postgres SQLi", "critical", "http://t/x", "d", "e",
                            capabilities={"provides": ["file_read"], "requires": []})
        stored = F._load()["findings"][0]
        assert stored["provides"] == ["file_read"]
        assert "requires" not in stored  # empty requires not stored


class TestSurfacePush:
    @pytest.mark.asyncio
    async def test_blocked_note_with_provider_pushes_bridge(self, monkeypatch):
        from mcp_server.report_tools import diagrams as D
        # Graph: a SQLi provides file_read; a Werkzeug console finding on the same host.
        g = m.Graph()
        g.add_node("finding:sqli", m.FINDING, "Postgres SQLi", severity="critical")
        g.add_node("host:H", m.HOST, "H"); g.add_edge("finding:sqli", "host:H", m.FOUND_ON)
        g.add_node("prim:file_read", m.PRIMITIVE, "file_read")
        g.add_edge("finding:sqli", "prim:file_read", m.PROVIDES)
        g.add_node("finding:wz", m.FINDING, "Werkzeug console exposed", severity="high")
        g.add_edge("finding:wz", "host:H", m.FOUND_ON)
        import core.graph
        monkeypatch.setattr(core.graph, "build_graph", lambda: g)

        pushed, backfilled = [], []
        import core.steering
        monkeypatch.setattr(core.steering.steering_queue, "add_directive",
                            lambda **kw: pushed.append(kw) or "id-1")
        import core.findings
        monkeypatch.setattr(core.findings, "_load",
                            lambda: {"findings": [{"id": "wz", "title": "Werkzeug console exposed"}]})
        async def _upd(fid, **f): backfilled.append((fid, f))
        monkeypatch.setattr(core.findings, "update_finding", _upd)

        hint = await D._maybe_push_composition_bridge(
            "blocked, no LFI on the werkzeug console; machine-id un-derivable, need file-read")
        assert hint and "file_read" in hint
        assert pushed and pushed[0]["code"] == core.steering.COMPOSE_REQUIRED
        assert pushed[0]["trigger"] == "BLOCKED_PRIMITIVE_BRIDGE"
        # back-filled the requires primitive onto the blocked finding
        assert backfilled and backfilled[0][0] == "wz" and "file_read" in backfilled[0][1]["requires"]

    @pytest.mark.asyncio
    async def test_blocked_note_no_provider_no_push(self, monkeypatch):
        from mcp_server.report_tools import diagrams as D
        import core.graph
        monkeypatch.setattr(core.graph, "build_graph", lambda: m.Graph())  # no providers
        import core.steering
        pushed = []
        monkeypatch.setattr(core.steering.steering_queue, "add_directive", lambda **kw: pushed.append(kw))
        hint = await D._maybe_push_composition_bridge("blocked, no LFI, need file-read")
        assert hint is None and pushed == []

    @pytest.mark.asyncio
    async def test_non_blocked_note_is_noop(self, monkeypatch):
        from mcp_server.report_tools import diagrams as D
        import core.steering
        pushed = []
        monkeypatch.setattr(core.steering.steering_queue, "add_directive", lambda **kw: pushed.append(kw))
        assert await D._maybe_push_composition_bridge("Found a reflected XSS in the search box") is None
        assert pushed == []
