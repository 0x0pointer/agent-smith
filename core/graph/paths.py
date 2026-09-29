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


def _normalize_kinds(edge_kinds: str | Iterable[str] | None) -> set[str] | None:
    """A single edge kind, an iterable of kinds, or None → a set of kinds or None."""
    if isinstance(edge_kinds, str):
        return {edge_kinds}
    return set(edge_kinds) if edge_kinds else None


def _validate_pattern(pattern: list) -> None:
    if not pattern or len(pattern) % 2 == 0:
        raise ValueError("pattern must be a non-empty, odd-length list: NodeM, Rel, NodeM, ...")
    for i, part in enumerate(pattern):
        expect = NodeM if i % 2 == 0 else Rel
        if not isinstance(part, expect):
            raise ValueError(f"pattern[{i}] must be a {expect.__name__}, got {type(part).__name__}")


# ── fixed-length pattern matching ───────────────────────────────────────────────

@dataclass
class _ChainQuery:
    """Immutable per-query context threaded through the fixed-length DFS."""
    g: Graph
    out: dict[str, list[Edge]]
    inc: dict[str, list[Edge]]
    node_specs: list[NodeM]
    rel_specs: list[Rel]
    limit: int


def _chain_match(node_specs: list[NodeM], path_nodes: list[Node], path_edges: list[Edge]) -> Match:
    """Build the Match for a completed path, binding each spec's ``var``."""
    bindings = {s.var: n for s, n in zip(node_specs, path_nodes) if s.var}
    return Match(nodes=list(path_nodes), edges=list(path_edges), vars=bindings)


def _chain_extensions(q: _ChainQuery, last: Node, rel: Rel, nxt_spec: NodeM,
                      seen: set[str]) -> list[tuple[Edge, Node]]:
    """(edge, node) pairs that extend the path by one valid, unvisited hop."""
    exts: list[tuple[Edge, Node]] = []
    for edge, nid in _neighbors(q.out, q.inc, last.id, rel):
        if nid in seen:  # simple path — no revisits
            continue
        nn = q.g.nodes.get(nid)
        if nn is None or not nxt_spec.matches(nn):
            continue
        exts.append((edge, nn))
    return exts


def _chain_dfs(q: _ChainQuery, path_nodes: list[Node], path_edges: list[Edge],
               seen: set[str], matches: list[Match]) -> None:
    """Depth-first extend the current path, appending completed Matches."""
    if len(matches) >= q.limit:
        return
    pos = len(path_nodes) - 1
    if pos == len(q.node_specs) - 1:
        matches.append(_chain_match(q.node_specs, path_nodes, path_edges))
        return
    rel = q.rel_specs[pos]
    nxt_spec = q.node_specs[pos + 1]
    for edge, nn in _chain_extensions(q, path_nodes[-1], rel, nxt_spec, seen):
        _chain_dfs(q, path_nodes + [nn], path_edges + [edge], seen | {nn.id}, matches)
        if len(matches) >= q.limit:
            return


def match_chain(g: Graph, pattern: list, limit: int = 200) -> list[Match]:
    """Find every simple path matching a fixed node–rel–node pattern.

    ``pattern`` alternates NodeM and Rel and must start and end with a NodeM, e.g.
    ``[NodeM("finding", var="a"), Rel(LEAKS), NodeM("credential")]``. Each Rel is a
    single hop. Returns up to ``limit`` Matches (deterministic order)."""
    _validate_pattern(pattern)
    out, inc = _adjacency(g)
    q = _ChainQuery(g=g, out=out, inc=inc,
                    node_specs=pattern[0::2], rel_specs=pattern[1::2], limit=limit)
    matches: list[Match] = []
    for start in g.nodes.values():
        if not q.node_specs[0].matches(start):
            continue
        _chain_dfs(q, [start], [], {start.id}, matches)
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


@dataclass
class _ReachQuery:
    """Immutable per-query context threaded through the reachability BFS."""
    g: Graph
    out: dict[str, list[Edge]]
    inc: dict[str, list[Edge]]
    target: NodeM
    hop_rel: Rel
    kinds: set[str] | None
    min_hops: int
    max_hops: int
    limit: int


def _reachable_step(q: _ReachQuery, node_id: str) -> list[str]:
    """Neighbor ids reachable in one hop, filtered by the allowed edge kinds."""
    nbrs = _neighbors(q.out, q.inc, node_id, q.hop_rel)
    return [nid for e, nid in nbrs if q.kinds is None or e.kind in q.kinds]


def _reachable_hit(q: _ReachQuery, node_id: str, depth: int) -> bool:
    """True when a path of ``depth`` hops ending at ``node_id`` matches the target."""
    if depth < q.min_hops or depth < 1:
        return False
    node = q.g.nodes.get(node_id)
    return node is not None and q.target.matches(node)


def _reachable_enqueue(q: _ReachQuery, frontier: deque, cur: str, path: list[str]) -> None:
    """Push each unvisited, in-graph neighbor onto the BFS frontier."""
    for nid in _reachable_step(q, cur):
        if nid in path or nid not in q.g.nodes:  # simple path
            continue
        frontier.append((nid, path + [nid]))


def _reachable_bfs(q: _ReachQuery, start_id: str, paths: list[list[str]]) -> None:
    """BFS by depth from one start, appending matching simple paths to ``paths``."""
    frontier: deque[tuple[str, list[str]]] = deque([(start_id, [start_id])])
    while frontier and len(paths) < q.limit:
        cur, path = frontier.popleft()
        depth = len(path) - 1
        if _reachable_hit(q, cur, depth):
            paths.append(path)
            if len(paths) >= q.limit:
                return
        if depth >= q.max_hops:
            continue
        _reachable_enqueue(q, frontier, cur, path)


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
    out, inc = _adjacency(g)
    q = _ReachQuery(g=g, out=out, inc=inc, target=target,
                    hop_rel=Rel(kind=None, direction=direction),
                    kinds=_normalize_kinds(edge_kinds),
                    min_hops=min_hops, max_hops=max_hops, limit=limit)
    # BFS by depth so shorter routes surface first; deque of (node_id, path).
    paths: list[list[str]] = []
    for start in _resolve_starts(g, src):
        if len(paths) >= limit:
            break
        _reachable_bfs(q, start.id, paths)
    return paths[:limit]


def _shortest_expand(out: dict, inc: dict, hop_rel: Rel, kinds: set[str] | None,
                     path: list[str], dst_id: str, visited: set[str],
                     frontier: deque) -> list[str] | None:
    """Expand ``path`` by one hop: return the completed path if it reaches
    ``dst_id``, otherwise enqueue each unvisited neighbor and return None."""
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


def shortest_path(g: Graph, src_id: str, dst_id: str,
                  edge_kinds: str | Iterable[str] | None = None,
                  direction: str = "out", max_hops: int = 8) -> list[str] | None:
    """BFS shortest simple path (node ids) from src_id to dst_id, or None."""
    if src_id not in g.nodes or dst_id not in g.nodes:
        return None
    if src_id == dst_id:
        return [src_id]
    kinds = _normalize_kinds(edge_kinds)
    out, inc = _adjacency(g)
    hop_rel = Rel(kind=None, direction=direction)
    frontier: deque[list[str]] = deque([[src_id]])
    visited = {src_id}
    while frontier:
        path = frontier.popleft()
        if len(path) - 1 >= max_hops:
            continue
        found = _shortest_expand(out, inc, hop_rel, kinds, path, dst_id, visited, frontier)
        if found is not None:
            return found
    return None


def render_path(g: Graph, node_ids: list[str]) -> str:
    """Human-readable ``label -> label -> ...`` for a path of node ids."""
    return " -> ".join(g.nodes[i].label if i in g.nodes else i for i in node_ids)
