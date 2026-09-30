"""
Tests for issue #182 — the World Model graph must stay legible at scale.

render_view is the presentation projection that replaced the insertion-order
[:500] slice. It must:
  - NEVER truncate non-endpoint nodes (host/tech/token/finding/primitive) — those
    were the "interesting nodes lost in the noise";
  - interest-rank endpoints (findings > tested cells > params) under the cap;
  - default-hide 0-param/0-tested/no-finding endpoints (dead weight);
  - fold every dropped endpoint into a '+N more' cluster node (no silent drop);
  - honour the discovered_by provenance filter.
"""
from core.graph import model as m
from core.graph.views import _endpoint_interest, _path_prefix, next_targets, render_view


def _ep(id_, path, *, params=0, tested=0, findings=False, candidate=False, src="spider"):
    return m.Node(f"ep:{id_}", m.ENDPOINT, f"GET {path}", {
        "path": path, "method": "GET", "param_count": params, "tested_count": tested,
        "has_findings": findings, "candidate": candidate, "discovered_by": src,
    })


def _graph(*nodes):
    g = m.Graph()
    for n in nodes:
        g.nodes[n.id] = n
    return g


def test_non_endpoint_nodes_are_never_dropped():
    g = _graph(
        m.Node("host:t", m.HOST, "t"),
        m.Node("tech:nginx", m.TECH, "Nginx"),
        m.Node("token:jwt", m.TOKEN, "jwt"),
        m.Node("finding:f1", m.FINDING, "SQLi", {"severity": "high"}),
        m.Node("primitive:code_exec", m.PRIMITIVE, "code_exec"),
        # 300 dead-weight endpoints that used to swamp the [:500] slice
        *[_ep(i, f"/.noise{i}") for i in range(300)],
    )
    nodes, _edges, dropped = render_view(g, node_cap=10)
    kinds = {n.kind for n in nodes}
    assert {m.HOST, m.TECH, m.TOKEN, m.FINDING, m.PRIMITIVE} <= kinds
    # every one of the 300 dead endpoints is hidden and represented by a cluster
    assert dropped == 300
    assert any(n.attrs.get("cluster") for n in nodes)


def test_dead_weight_hidden_but_interesting_endpoints_kept():
    g = _graph(
        m.Node("host:t", m.HOST, "t"),
        _ep("live", "/api/users", params=3, tested=2, findings=True),
        _ep("dead", "/.bash_history"),           # 0 param, 0 tested, no finding
    )
    nodes, _edges, dropped = render_view(g)
    paths = {n.attrs.get("path") for n in nodes if n.kind == m.ENDPOINT}
    assert "/api/users" in paths
    assert "/.bash_history" not in paths        # hidden
    assert dropped == 1


def test_show_untested_keeps_dead_weight():
    g = _graph(m.Node("host:t", m.HOST, "t"), _ep("dead", "/.bashrc"))
    nodes, _edges, dropped = render_view(g, show_untested=True)
    assert dropped == 0
    assert any(n.attrs.get("path") == "/.bashrc" for n in nodes)


def test_provenance_filter():
    g = _graph(
        m.Node("host:t", m.HOST, "t"),
        _ep("s", "/from-spider", params=1, src="spider"),
        _ep("f", "/from-ffuf", params=1, src="ffuf"),
    )
    nodes, _edges, _dropped = render_view(g, discovered_by="ffuf")
    ep_paths = {n.attrs.get("path") for n in nodes if n.kind == m.ENDPOINT and not n.attrs.get("cluster")}
    assert ep_paths == {"/from-ffuf"}


def test_cap_keeps_highest_interest_and_clusters_rest():
    g = _graph(
        m.Node("host:t", m.HOST, "t"),
        _ep("hot", "/api/pay", params=2, tested=5, findings=True),
        _ep("warm", "/api/users", params=4, tested=1),
        _ep("cool", "/api/list", params=1),
    )
    nodes, _edges, dropped = render_view(g, node_cap=1)
    kept = [n for n in nodes if n.kind == m.ENDPOINT and not n.attrs.get("cluster")]
    assert len(kept) == 1 and kept[0].attrs["path"] == "/api/pay"   # highest interest
    assert dropped == 2
    clusters = [n for n in nodes if n.attrs.get("cluster")]
    assert clusters and sum(c.attrs["count"] for c in clusters) == 2


def test_cluster_edge_anchored_to_host():
    g = _graph(m.Node("host:t", m.HOST, "t"), _ep("d", "/.env"))
    nodes, edges, _dropped = render_view(g)
    cid = next(n.id for n in nodes if n.attrs.get("cluster"))
    assert any(e.src == "host:t" and e.dst == cid for e in edges)


def test_interest_ordering():
    assert _endpoint_interest(_ep("a", "/a", findings=True)) > \
           _endpoint_interest(_ep("b", "/b", tested=3))
    assert _endpoint_interest(_ep("c", "/c", tested=3)) > \
           _endpoint_interest(_ep("d", "/d", params=3))
    # a confirmed endpoint edges out a candidate at equal signal
    assert _endpoint_interest(_ep("e", "/e", params=1, candidate=False)) > \
           _endpoint_interest(_ep("f", "/f", params=1, candidate=True))


def test_path_prefix_groups_root_noise_and_deep_routes():
    assert _path_prefix("/.bash_history.php") == "/"
    assert _path_prefix("/.bashrc") == "/"
    assert _path_prefix("/api/v1/users/1") == "/api/v1/users"
    assert _path_prefix("") == "/"


def test_next_targets_skips_candidate_endpoints():
    # candidate (phantom) endpoints with pending cells must NOT appear in the worklist
    g = m.Graph()
    g.nodes["ep:real"] = _ep("real", "/api/users", params=2)
    g.nodes["ep:phantom"] = _ep("phantom", "/.bash_history", params=1, candidate=True)
    g.add_edge("ep:real", "inj:sqli", m.TESTED_FOR, status="pending")
    g.add_edge("ep:phantom", "inj:sqli", m.TESTED_FOR, status="pending")
    paths = {t["path"] for t in next_targets(g)}
    assert "/api/users" in paths
    assert "/.bash_history" not in paths          # phantom not steered to


def test_cluster_edges_survive_edge_cap():
    # many real edges + dropped endpoints: the cluster anchor edges must not be
    # truncated away (else '+N more' nodes float disconnected — the #182 symptom).
    g = m.Graph()
    g.nodes["host:t"] = m.Node("host:t", m.HOST, "t")
    # 30 real params generating 30 real has_param edges from one kept endpoint
    keep = _ep("keep", "/api/keep", params=1, tested=1)
    g.nodes[keep.id] = keep
    for i in range(30):
        g.nodes[f"param:{i}"] = m.Node(f"param:{i}", m.PARAM, f"p{i}")
        g.add_edge(keep.id, f"param:{i}", m.HAS_PARAM)
    # 5 dead endpoints → clustered
    for i in range(5):
        d = _ep(f"d{i}", f"/dead/{i}")
        g.nodes[d.id] = d
        g.add_edge("host:t", d.id, m.HOSTS)
    nodes, edges, _ = render_view(g, edge_cap=30)   # cap below real edge count
    cluster_ids = {n.id for n in nodes if n.attrs.get("cluster")}
    anchored = {e.dst for e in edges if e.kind == m.HOSTS and e.attrs.get("cluster")}
    assert cluster_ids and cluster_ids <= anchored   # every cluster keeps its host edge
    assert len(edges) <= 30


def test_clusters_anchor_to_owning_host_multi_host():
    g = m.Graph()
    g.nodes["host:a"] = m.Node("host:a", m.HOST, "a")
    g.nodes["host:b"] = m.Node("host:b", m.HOST, "b")
    ea, eb = _ep("ea", "/x"), _ep("eb", "/y")
    g.nodes[ea.id], g.nodes[eb.id] = ea, eb
    g.add_edge("host:a", ea.id, m.HOSTS)
    g.add_edge("host:b", eb.id, m.HOSTS)
    _nodes, edges, _ = render_view(g)             # both dead → clustered per host
    anchors = {(e.src, e.dst) for e in edges if e.attrs.get("cluster")}
    hosts = {src for src, _ in anchors}
    assert hosts == {"host:a", "host:b"}          # not all folded onto one host
