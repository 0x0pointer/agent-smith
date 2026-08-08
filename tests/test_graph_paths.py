"""Tests for the Cypher-ish path finder over the world-model graph."""
import pytest

from core.graph import model as m
from core.graph.paths import (
    Match, NodeM, Rel, match_chain, reachable, render_path, shortest_path,
)


def _graph() -> m.Graph:
    """A small world model:

        host:h  --hosts-->  ep:login  --has_param-->  param:user
        finding:leak --leaks--> cred:admin ; finding:leak --found_on--> host:h
        finding:rce  --found_on--> host:h
        finding:leak --escalates_to--> (self, lead)   (cycle-ish self edge)
    """
    g = m.Graph()
    g.add_node("host:h", m.HOST, "h")
    g.add_node("ep:login", m.ENDPOINT, "POST /login")
    g.add_node("param:user", m.PARAM, "user")
    g.add_node("cred:admin", m.CREDENTIAL, "admin")
    g.add_node("finding:leak", m.FINDING, "cred leak", severity="high")
    g.add_node("finding:rce", m.FINDING, "rce", severity="critical")
    g.add_edge("host:h", "ep:login", m.HOSTS)
    g.add_edge("ep:login", "param:user", m.HAS_PARAM)
    g.add_edge("finding:leak", "cred:admin", m.LEAKS)
    g.add_edge("finding:leak", "host:h", m.FOUND_ON)
    g.add_edge("finding:rce", "host:h", m.FOUND_ON)
    return g


# ── match_chain ──────────────────────────────────────────────────────────────

def test_match_chain_single_hop_by_kind():
    g = _graph()
    ms = match_chain(g, [NodeM(m.FINDING), Rel(m.LEAKS), NodeM(m.CREDENTIAL)])
    assert len(ms) == 1
    assert ms[0].node_ids == ["finding:leak", "cred:admin"]
    assert ms[0].edges[0].kind == m.LEAKS


def test_match_chain_binds_vars():
    g = _graph()
    ms = match_chain(g, [NodeM(m.HOST, var="h"), Rel(m.HOSTS), NodeM(m.ENDPOINT, var="e")])
    assert len(ms) == 1
    assert ms[0].var("h").id == "host:h"
    assert ms[0].var("e").id == "ep:login"


def test_match_chain_leak_then_other_finding_same_host():
    """The classic chain: (leaker)-[:LEAKS]->cred ; and a second finding on the
    SAME host, reached leaker-[:FOUND_ON]->host<-[:FOUND_ON]-other."""
    g = _graph()
    ms = match_chain(g, [
        NodeM(m.FINDING, where=lambda n: bool(g.out_edges(n.id, m.LEAKS)), var="leak"),
        Rel(m.FOUND_ON),
        NodeM(m.HOST),
        Rel(m.FOUND_ON, direction="in"),
        NodeM(m.FINDING, var="other"),
    ])
    # leak reaches host:h, host:h has two incoming FOUND_ON (leak, rce); simple-path
    # rule forbids revisiting finding:leak, so only finding:rce is a valid "other".
    pairs = {(x.var("leak").id, x.var("other").id) for x in ms}
    assert pairs == {("finding:leak", "finding:rce")}


def test_match_chain_direction_in():
    g = _graph()
    ms = match_chain(g, [NodeM(m.CREDENTIAL), Rel(m.LEAKS, direction="in"), NodeM(m.FINDING)])
    assert [x.node_ids for x in ms] == [["cred:admin", "finding:leak"]]


def test_match_chain_no_match_returns_empty():
    g = _graph()
    assert match_chain(g, [NodeM(m.TOKEN), Rel(m.LEAKS), NodeM(m.CREDENTIAL)]) == []


def test_match_chain_respects_limit():
    g = _graph()
    ms = match_chain(g, [NodeM(m.FINDING), Rel(m.FOUND_ON), NodeM(m.HOST)], limit=1)
    assert len(ms) == 1


def test_match_chain_rejects_bad_pattern():
    g = _graph()
    with pytest.raises(ValueError):
        match_chain(g, [NodeM(m.HOST), Rel(m.HOSTS)])  # even length / ends on Rel
    with pytest.raises(ValueError):
        match_chain(g, [Rel(m.HOSTS)])  # starts with Rel


# ── reachable (variable-length) ────────────────────────────────────────────────

def test_reachable_multi_hop_host_to_param():
    g = _graph()
    paths = reachable(g, "host:h", NodeM(m.PARAM), max_hops=4)
    assert ["host:h", "ep:login", "param:user"] in paths


def test_reachable_respects_max_hops():
    g = _graph()
    # param is 2 hops from host; max_hops=1 must not reach it.
    assert reachable(g, "host:h", NodeM(m.PARAM), max_hops=1) == []


def test_reachable_edge_kind_filter():
    g = _graph()
    # Only HOSTS edges allowed → can reach the endpoint (1 hop) but not the param
    # (needs a HAS_PARAM hop).
    paths = reachable(g, "host:h", NodeM(kind=None), edge_kinds=m.HOSTS, max_hops=4)
    reached = {p[-1] for p in paths}
    assert "ep:login" in reached
    assert "param:user" not in reached


def test_reachable_from_nodem_start():
    g = _graph()
    paths = reachable(g, NodeM(m.HOST), NodeM(m.PARAM), max_hops=3)
    assert paths and paths[0][0] == "host:h"


def test_reachable_simple_path_no_cycle():
    g = _graph()
    # self-loop must not cause infinite traversal
    g.add_edge("host:h", "host:h", m.RUNS)
    paths = reachable(g, "host:h", NodeM(m.ENDPOINT), max_hops=5)
    assert ["host:h", "ep:login"] in paths


# ── shortest_path + render ─────────────────────────────────────────────────────

def test_shortest_path():
    g = _graph()
    assert shortest_path(g, "host:h", "param:user") == ["host:h", "ep:login", "param:user"]


def test_shortest_path_none_when_unreachable():
    g = _graph()
    assert shortest_path(g, "param:user", "host:h", direction="out") is None


def test_shortest_path_same_node():
    g = _graph()
    assert shortest_path(g, "host:h", "host:h") == ["host:h"]


def test_render_path():
    g = _graph()
    assert render_path(g, ["host:h", "ep:login"]) == "h -> POST /login"
