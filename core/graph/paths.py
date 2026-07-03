"""A thin, Cypher-ish path finder over the in-memory world-model Graph (AR-B3+).

Attack-chaining is a graph-path problem. Rather than hand-code each chain shape in
``chains.py`` (imperative traversal), this exposes a small declarative matcher so a
pattern is *data*, not code — the 80% of Neo4j/Cypher's value with none of the
operational cost (no service, no persistence, no drift; the matrix stays
authoritative and the graph is still projected on demand).

Two primitives, plus helpers:

  match_chain(g, pattern)   fixed-length node–rel–node patterns. The Cypher
                            (a:Finding)-[:LEAKS]->(:Host)<-[:FOUND_ON]-(b:Finding)
                            becomes
                            [NodeM("finding", var="a"), Rel(LEAKS),
                             NodeM("host"), Rel(FOUND_ON, "in"),
                             NodeM("finding", var="b")]

  reachable(g, src, target) variable-length reachability — the Cypher
                            (src)-[:kind*1..4]->(target) "what can I reach in ≤N
                            hops" query that is painful to hand-roll each time.

Pure, no I/O. Simple paths only (a node is never revisited within one path), so
results are finite and cycle-safe. Bounded by `limit` and `max_hops`.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Iterable

from .model import Edge, Graph, Node

_DIRECTIONS = ("out", "in", "any")


@dataclass
class NodeM:
    """A node matcher. ``kind`` filters by node kind (None = any); ``where`` is an
    optional predicate on the Node; ``var`` binds the matched node in the result."""
    kind: str | None = None
    where: Callable[[Node], bool] | None = None
    var: str | None = None

    def matches(self, node: Node) -> bool:
        if self.kind is not None and node.kind != self.kind:
            return False
        return self.where is None or bool(self.where(node))


@dataclass
class Rel:
    """A relationship matcher for a single hop. ``kind`` filters by edge kind
    (None = any); ``direction`` is 'out' (src→dst), 'in' (dst→src), or 'any'."""
    kind: str | None = None
    direction: str = "out"

    def __post_init__(self) -> None:
        if self.direction not in _DIRECTIONS:
            raise ValueError(f"direction must be one of {_DIRECTIONS}, got {self.direction!r}")


@dataclass
class Match:
    """One matched path. ``nodes`` are the pattern-position nodes in order;
    ``vars`` binds the NodeM.var names; ``edges`` are the traversed edges."""
    nodes: list[Node]
    edges: list[Edge] = field(default_factory=list)
    vars: dict[str, Node] = field(default_factory=dict)

    @property
    def node_ids(self) -> list[str]:
        return [n.id for n in self.nodes]

    def var(self, name: str) -> Node | None:
        return self.vars.get(name)


# ── adjacency (built once per query — the base Graph does O(E) edge scans) ──────

def _adjacency(g: Graph) -> tuple[dict[str, list[Edge]], dict[str, list[Edge]]]:
    out: dict[str, list[Edge]] = {}
    inc: dict[str, list[Edge]] = {}
    for e in g.edges:
        out.setdefault(e.src, []).append(e)
        inc.setdefault(e.dst, []).append(e)
    return out, inc


def _neighbors(out: dict, inc: dict, node_id: str, rel: Rel) -> list[tuple[Edge, str]]:
    """(edge, other_node_id) pairs reachable from node_id via one hop matching rel."""
    res: list[tuple[Edge, str]] = []
    if rel.direction in ("out", "any"):
        for e in out.get(node_id, []):
            if rel.kind is None or e.kind == rel.kind:
                res.append((e, e.dst))
    if rel.direction in ("in", "any"):
        for e in inc.get(node_id, []):
            if rel.kind is None or e.kind == rel.kind:
                res.append((e, e.src))
    return res


def _validate_pattern(pattern: list) -> None:
    if not pattern or len(pattern) % 2 == 0:
        raise ValueError("pattern must be a non-empty, odd-length list: NodeM, Rel, NodeM, ...")
    for i, part in enumerate(pattern):
        expect = NodeM if i % 2 == 0 else Rel
        if not isinstance(part, expect):
            raise ValueError(f"pattern[{i}] must be a {expect.__name__}, got {type(part).__name__}")


# ── fixed-length pattern matching ───────────────────────────────────────────────

def match_chain(g: Graph, pattern: list, limit: int = 200) -> list[Match]:
    """Find every simple path matching a fixed node–rel–node pattern.

    ``pattern`` alternates NodeM and Rel and must start and end with a NodeM, e.g.
    ``[NodeM("finding", var="a"), Rel(LEAKS), NodeM("credential")]``. Each Rel is a
    single hop. Returns up to ``limit`` Matches (deterministic order)."""
    _validate_pattern(pattern)
    out, inc = _adjacency(g)
    node_specs = pattern[0::2]
    rel_specs = pattern[1::2]
    matches: list[Match] = []

    def _extend(path_nodes: list[Node], path_edges: list[Edge], seen: set[str]) -> None:
        pos = len(path_nodes) - 1
        if len(matches) >= limit:
            return
        if pos == len(node_specs) - 1:
            bindings = {s.var: n for s, n in zip(node_specs, path_nodes) if s.var}
            matches.append(Match(nodes=list(path_nodes), edges=list(path_edges), vars=bindings))
            return
        rel = rel_specs[pos]
        nxt_spec = node_specs[pos + 1]
        for edge, nid in _neighbors(out, inc, path_nodes[-1].id, rel):
            if nid in seen:  # simple path — no revisits
                continue
            nn = g.nodes.get(nid)
            if nn is None or not nxt_spec.matches(nn):
                continue
            _extend(path_nodes + [nn], path_edges + [edge], seen | {nid})
            if len(matches) >= limit:
                return

    for start in g.nodes.values():
        if node_specs[0].matches(start):
            _extend([start], [], {start.id})
            if len(matches) >= limit:
                break
    return matches[:limit]


# ── variable-length reachability ────────────────────────────────────────────────

def _resolve_starts(g: Graph, src) -> list[Node]:
    if isinstance(src, NodeM):
        return [n for n in g.nodes.values() if src.matches(n)]
    if isinstance(src, str):
        n = g.nodes.get(src)
        return [n] if n else []
    raise TypeError("src must be a node id (str) or a NodeM")


def reachable(g: Graph, src, target, edge_kinds: str | Iterable[str] | None = None,
              direction: str = "out", min_hops: int = 1, max_hops: int = 4,
              limit: int = 100) -> list[list[str]]:
    """Variable-length reachability: the Cypher ``(src)-[:kinds*min..max]->(target)``.

    ``src`` is a node id or a NodeM; ``target`` is a NodeM. ``edge_kinds`` limits
    which edge kinds may be traversed (None = any). Returns simple paths (lists of
    node ids, each of length in [min_hops, max_hops]) — the concrete route, not just
    a yes/no — so a caller can turn a reachable pair into a proposed chain."""
    if direction not in _DIRECTIONS:
        raise ValueError(f"direction must be one of {_DIRECTIONS}")
    if not isinstance(target, NodeM):
        raise TypeError("target must be a NodeM")
    kinds = {edge_kinds} if isinstance(edge_kinds, str) else (set(edge_kinds) if edge_kinds else None)
    out, inc = _adjacency(g)
    hop_rel = Rel(kind=None, direction=direction)

    def _step(node_id: str) -> list[str]:
        nbrs = _neighbors(out, inc, node_id, hop_rel)
        return [nid for e, nid in nbrs if kinds is None or e.kind in kinds]

    paths: list[list[str]] = []
    # BFS by depth so shorter routes surface first; deque of (node_id, path).
    for start in _resolve_starts(g, src):
        frontier: deque[tuple[str, list[str]]] = deque([(start.id, [start.id])])
        while frontier and len(paths) < limit:
            cur, path = frontier.popleft()
            depth = len(path) - 1
            if depth >= min_hops and depth >= 1:
                node = g.nodes.get(cur)
                if node is not None and target.matches(node):
                    paths.append(path)
                    if len(paths) >= limit:
                        break
            if depth >= max_hops:
                continue
            for nid in _step(cur):
                if nid in path or nid not in g.nodes:  # simple path
                    continue
                frontier.append((nid, path + [nid]))
    return paths[:limit]


def shortest_path(g: Graph, src_id: str, dst_id: str,
                  edge_kinds: str | Iterable[str] | None = None,
                  direction: str = "out", max_hops: int = 8) -> list[str] | None:
    """BFS shortest simple path (node ids) from src_id to dst_id, or None."""
    if src_id not in g.nodes or dst_id not in g.nodes:
        return None
    if src_id == dst_id:
        return [src_id]
    kinds = {edge_kinds} if isinstance(edge_kinds, str) else (set(edge_kinds) if edge_kinds else None)
    out, inc = _adjacency(g)
    hop_rel = Rel(kind=None, direction=direction)
    frontier: deque[list[str]] = deque([[src_id]])
    visited = {src_id}
    while frontier:
        path = frontier.popleft()
        if len(path) - 1 >= max_hops:
            continue
        for edge, nid in _neighbors(out, inc, path[-1], hop_rel):
            if kinds is not None and edge.kind not in kinds:
                continue
            if nid in visited:
                continue
            if nid == dst_id:
                return path + [nid]
            visited.add(nid)
            frontier.append(path + [nid])
    return None


def render_path(g: Graph, node_ids: list[str]) -> str:
    """Human-readable ``label -> label -> ...`` for a path of node ids."""
    return " -> ".join(g.nodes[i].label if i in g.nodes else i for i in node_ids)
