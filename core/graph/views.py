"""Views + rankings derived from the world-model graph (Phase 2 / AR-B1/B2/WF-A5).

The coverage matrix as a VIEW over the graph (proving the model unification the
analysis called for), plus the derived reasoning — finding prioritization and
value-ranked next targets — that used to be scattered ad-hoc. Pure: reads a
Graph, returns plain dicts/lists. The JSON matrix remains the persistent write
store; this is the coherent read/reasoning layer over it.
"""
from __future__ import annotations

from . import model as m

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "": 0}
_ADDRESSED = {"tested_clean", "vulnerable", "not_applicable", "skipped"}


def coverage_view(g: m.Graph) -> dict:
    """Project the coverage-matrix shape from the graph — demonstrates that the
    matrix IS a view (Endpoint + Param --tested_for--> InjectionType). Usable for
    parallel-run validation against the authoritative JSON matrix."""
    endpoints = [
        {"id": n.id.split(":", 1)[1], "path": n.attrs.get("path", ""),
         "method": n.attrs.get("method", "GET"), "auth_context": n.attrs.get("auth_context", "none")}
        for n in g.of_kind(m.ENDPOINT)
    ]
    cells = [
        {"endpoint_id": e.src.split(":", 1)[1], "injection_type": e.dst.split(":", 1)[1],
         "param": e.attrs.get("param"), "status": e.attrs.get("status"),
         "finding_id": e.attrs.get("finding_id")}
        for e in g.edges if e.kind == m.TESTED_FOR
    ]
    return {"endpoints": endpoints, "matrix": cells}


def rank_findings(g: m.Graph) -> list[dict]:
    """WF-A5: prioritize findings for deepening. Score = severity (dominant) +
    chain-potential (has an escalation lead / leaks credential material) +
    reachability (co-located with other findings on the same host). Returns
    ``[{finding_id, label, severity, score, why}]`` most-promising first."""
    def _host(fid: str) -> str | None:
        es = g.out_edges(fid, m.FOUND_ON)
        return es[0].dst if es else None

    hosts: dict[str, int] = {}
    for f in g.of_kind(m.FINDING):
        h = _host(f.id)
        if h:
            hosts[h] = hosts.get(h, 0) + 1

    ranked = []
    for f in g.of_kind(m.FINDING):
        sev = f.attrs.get("severity", "")
        score = _SEV_RANK.get(sev, 0) * 10
        why = [sev or "unrated"]
        if g.out_edges(f.id, m.ESCALATES_TO):
            score += 5
            why.append("has escalation lead")
        if g.out_edges(f.id, m.LEAKS):
            score += 4
            why.append("leaks credential material")
        h = _host(f.id)
        if h and hosts.get(h, 0) > 1:
            score += 2
            why.append("co-located findings")
        ranked.append({"finding_id": f.id.split(":", 1)[1], "label": f.label,
                       "severity": sev, "score": score, "why": ", ".join(why)})
    ranked.sort(key=lambda r: r["score"], reverse=True)
    return ranked


def _endpoint_interest(n: m.Node) -> int:
    """Interest score for de-noising the World Model graph (#182). Findings dominate,
    then worked cells, then parameter richness; a confirmed endpoint edges out an
    unconfirmed (candidate) one at the same signal level."""
    a = n.attrs
    score = 0
    if a.get("has_findings"):
        score += 1000
    score += int(a.get("tested_count", 0)) * 50
    score += int(a.get("param_count", 0)) * 5
    if not a.get("candidate"):
        score += 2
    return score


def _path_prefix(path: str) -> str:
    """The directory portion of an endpoint path, used as the cluster key. Groups
    root-level wordlist noise (/.bash_history, /.bashrc, …) under '/' and deep API
    routes under their shared parent (/api/v1/users → /api/v1)."""
    if not path:
        return "/"
    p = path.split("?", 1)[0].rstrip("/")
    parent = p.rsplit("/", 1)[0]
    return parent or "/"


def render_view(g: m.Graph, node_cap: int = 140, show_untested: bool = False,
                discovered_by: str | None = None, edge_cap: int = 2000) -> tuple[list, list, int]:
    """Presentation projection of the graph for the World Model tab (#182).

    build_graph()'s graph is shared with the reasoning layer (chains/paths/rankings)
    and MUST stay whole, so de-noising happens HERE, not in the graph itself:
      - every NON-endpoint node (host/tech/token/credential/finding/primitive) is
        ALWAYS kept — these are exactly the nodes the old insertion-order [:500]
        slice silently truncated when hundreds of endpoints preceded them;
      - endpoints are interest-ranked (findings > tested cells > params > confirmed)
        and capped at ``node_cap``;
      - endpoints with 0 params AND 0 tested cells AND no findings are hidden by
        default (``show_untested=True`` keeps them) — dead weight per the issue;
      - an optional ``discovered_by`` filter narrows endpoints by provenance;
      - every endpoint removed by a cap/hide/filter is folded into a synthetic
        ``+N more`` cluster node grouped by path prefix and anchored to the host,
        so coverage is summarized, never silently dropped.
    Returns ``(nodes, edges, dropped_endpoint_count)`` as model objects for the
    route to serialize."""
    endpoints = [n for n in g.nodes.values() if n.kind == m.ENDPOINT]
    others = [n for n in g.nodes.values() if n.kind != m.ENDPOINT]

    if discovered_by:
        endpoints = [n for n in endpoints if n.attrs.get("discovered_by") == discovered_by]

    def _dead(n: m.Node) -> bool:
        a = n.attrs
        return (not show_untested
                and int(a.get("param_count", 0)) == 0
                and int(a.get("tested_count", 0)) == 0
                and not a.get("has_findings"))

    live = sorted((n for n in endpoints if not _dead(n)), key=_endpoint_interest, reverse=True)
    kept_eps = live[:node_cap]
    kept_ids = {n.id for n in kept_eps}
    dropped_eps = [n for n in endpoints if n.id not in kept_ids]

    kept_nodes = others + kept_eps

    # Which host owns each endpoint (host --hosts--> endpoint), so a dropped endpoint
    # is clustered under ITS host — not a single first-host bucket that would
    # mis-attribute routes on a multi-host (pivot) map.
    ep_host = {e.dst: e.src for e in g.edges if e.kind == m.HOSTS}
    any_host = next((n.id for n in others if n.kind == m.HOST), None)

    # Cluster every dropped endpoint into a '+N more' summary keyed by (host, prefix).
    clusters: dict[tuple, int] = {}
    for n in dropped_eps:
        host = ep_host.get(n.id) or any_host
        key = (host, _path_prefix(n.attrs.get("path", "")))
        clusters[key] = clusters.get(key, 0) + 1
    synth_nodes: list = []
    synth_edges: list = []
    for (host, prefix), count in sorted(clusters.items(), key=lambda kv: -kv[1]):
        cid = f"epcluster:{host or ''}:{prefix}"
        synth_nodes.append(m.Node(cid, m.ENDPOINT, f"+{count} more under {prefix}",
                                  {"cluster": True, "count": count, "prefix": prefix,
                                   "path": prefix}))
        if host:
            synth_edges.append(m.Edge(host, cid, m.HOSTS, {"cluster": True}))

    all_nodes = kept_nodes + synth_nodes
    node_ids = {n.id for n in all_nodes}
    real_edges = [e for e in g.edges
                  if e.src in node_ids and e.dst in node_ids and e.src != e.dst]
    # Reserve room for the cluster anchor edges so they're never truncated — a
    # floating '+N more' node is exactly the disconnected-node symptom #182 fixes.
    real_edges = real_edges[:max(0, edge_cap - len(synth_edges))]
    edges = real_edges + synth_edges
    return all_nodes, edges, len(dropped_eps)


def next_targets(g: m.Graph, limit: int = 5) -> list[dict]:
    """Value-ranked endpoints with the most untested surface (WF-A1 over the
    graph): highest-value endpoints that still have pending tested_for cells."""
    _EP_RANK = {"financial": 0, "auth": 1, "admin": 1, "ai-redteam": 2,
                "graphql": 2, "upload": 3, "api": 4, "websocket": 4}

    def _ep_value(path: str) -> int:
        import re
        low = path.lower()
        for kw, r in (("transfer", 0), ("payment", 0), ("login", 1), ("admin", 1),
                      ("token", 1), ("graphql", 2), ("upload", 3), ("api", 4)):
            if re.search(rf"/{kw}", low) or (kw == "api" and "/api" in low):
                return r
        return 6

    out = []
    for ep in g.of_kind(m.ENDPOINT):
        # Skip candidate (unconfirmed wordlist) endpoints — steering the model to
        # probe phantom paths is the exact wedge #180 removes; don't reintroduce it
        # via the worklist. The operator can still reach them via the graph's
        # provenance / show-untested controls.
        if ep.attrs.get("candidate"):
            continue
        pending = [e for e in g.out_edges(ep.id, m.TESTED_FOR)
                   if e.attrs.get("status") not in _ADDRESSED]
        if pending:
            out.append({"endpoint": ep.label, "path": ep.attrs.get("path", ""),
                        "pending_cells": len(pending), "value_rank": _ep_value(ep.attrs.get("path", ""))})
    out.sort(key=lambda t: (t["value_rank"], -t["pending_cells"]))
    return out[:limit]
