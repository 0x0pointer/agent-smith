"""World-Model Graph wiring — Phase B: Fix 3 (reachability-aware finding ranking)
and Fix 4 (graph-derived blast radius for terminal severity)."""
from core.adjunction import rubric
from core.graph import model as m
from core.graph.views import rank_findings


# ── Fix 3: reachability-aware ranking ────────────────────────────────────────

def test_unblocking_finding_outranks_isolated_of_equal_severity():
    g = m.Graph()
    g.add_node("finding:a", m.FINDING, "A unlocks", severity="high")
    g.add_node("finding:b", m.FINDING, "B blocked", severity="high")
    g.add_node("finding:c", m.FINDING, "C isolated", severity="high")
    g.add_node("prim:x", m.PRIMITIVE, "file_read")
    g.add_edge("finding:a", "prim:x", m.PROVIDES)   # A provides what B needs
    g.add_edge("finding:b", "prim:x", m.REQUIRES)
    ranked = {r["label"]: r for r in rank_findings(g)}
    assert ranked["A unlocks"]["score"] > ranked["C isolated"]["score"]
    assert "unblocks a blocked finding" in ranked["A unlocks"]["why"]


def test_reaches_opens_host_surface_term():
    g = m.Graph()
    g.add_node("finding:c", m.FINDING, "SSRF", severity="medium")
    g.add_node("host:h", m.HOST, "10.0.0.9")
    g.add_edge("finding:c", "host:h", m.REACHES)
    r = next(x for x in rank_findings(g) if x["label"] == "SSRF")
    assert "opens new host surface" in r["why"]


def test_provides_unused_primitive_does_not_boost():
    g = m.Graph()
    g.add_node("finding:a", m.FINDING, "A", severity="high")
    g.add_node("prim:x", m.PRIMITIVE, "file_read")
    g.add_edge("finding:a", "prim:x", m.PROVIDES)  # nothing REQUIRES it
    r = next(x for x in rank_findings(g) if x["label"] == "A")
    assert "unblocks a blocked finding" not in r["why"]


# ── Fix 4: graph-derived blast radius ────────────────────────────────────────

def test_terminal_band_classifies_code_exec_primitive():
    n = m.Node("prim:ce", m.PRIMITIVE, "code_exec")
    assert rubric._terminal_band(n) == "critical"


def test_terminal_band_classifies_imds_host_high():
    n = m.Node("host:x", m.HOST, "169.254.169.254")
    assert rubric._terminal_band(n) == "high"


def test_terminal_band_none_for_plain_node():
    assert rubric._terminal_band(m.Node("ep:x", m.ENDPOINT, "/about")) is None


def test_graph_terminal_severity_code_exec_path_is_critical():
    g = m.Graph()
    g.add_node("finding:f1", m.FINDING, "SQLi", severity="high")
    g.add_node("prim:ce", m.PRIMITIVE, "code_exec")
    g.add_edge("finding:f1", "prim:ce", m.PROVIDES)
    # finding text has no 'rce' keyword, but the graph proves the reach
    assert rubric.graph_terminal_severity({"id": "f1"}, g=g) == "critical"


def test_graph_terminal_severity_imds_reach_is_high():
    g = m.Graph()
    g.add_node("finding:f2", m.FINDING, "SSRF", severity="medium")
    g.add_node("host:imds", m.HOST, "169.254.169.254")
    g.add_edge("finding:f2", "host:imds", m.REACHES)
    assert rubric.graph_terminal_severity({"id": "f2"}, g=g) == "high"


def test_graph_terminal_severity_none_without_path():
    g = m.Graph()
    g.add_node("finding:f3", m.FINDING, "info leak", severity="low")
    assert rubric.graph_terminal_severity({"id": "f3"}, g=g) is None


def test_graph_terminal_severity_failsoft_no_id():
    assert rubric.graph_terminal_severity({}, g=m.Graph()) is None
