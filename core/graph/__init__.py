"""Knowledge-graph world-model (Phase 2 / AR-B1).

A shared graph built from everything the scan has learned — hosts, endpoints,
params, credentials, tokens, technologies, findings — over which reasoning the
flat coverage matrix can't express (reachability, data flow, attack chains)
becomes deterministic traversal. Additive: projected on demand from the existing
stores; the matrix stays authoritative while this grows into the substrate it
becomes a view over.
"""
from __future__ import annotations

from .build import build_graph
from .chains import candidate_chains
from .model import Edge, Graph, Node
from .paths import Match, NodeM, Rel, match_chain, reachable, render_path, shortest_path
from .views import coverage_view, next_targets, rank_findings

__all__ = ["build_graph", "candidate_chains", "coverage_view", "next_targets",
           "rank_findings", "Graph", "Node", "Edge",
           "match_chain", "reachable", "shortest_path", "render_path",
           "NodeM", "Rel", "Match"]
