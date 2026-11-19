"""Cross-run graph persistence (World-Model Graph spec, Fix 5 — the achievable,
non-destructive slice).

The spec's keystone is "make the graph the substrate, the matrix a view," with a
backing store so the graph ACCUMULATES across runs. The full authority inversion
(the matrix becoming ``coverage_view(g)``) plus a Neo4j service is a large,
high-risk structural migration against the live write store, and the spec marks
it P2 / "can follow" — so it is deliberately NOT done here (doing it half-way
would violate the spec's own "do not break the closure-integrity gates / the
matrix is authoritative" constraint).

What IS delivered, correctly and safely:
  * serialize / deserialize — the graph (de)serialization substrate every future
    persistence backend (Neo4j or otherwise) needs, and which also lets the
    matrix-as-view projection (views.coverage_view) be round-trip validated.
  * save_snapshot / load_snapshot — a per-target snapshot of the RECON ASSET MAP
    (host / service / endpoint / tech / param nodes and their structural edges).
    NO secrets (credentials / tokens), NO findings, NO coverage verdicts — a
    fresh run re-captures and re-confirms those; only the attack-surface map is
    carried. Bounded and atomic.
  * merge_prior_assets — OPT-IN (``SMITH_GRAPH_CROSSRUN=1``, default OFF). When a
    new scan of a known target starts, prior asset nodes are merged in tagged
    ``provenance="prior_run"`` and ``candidate=True`` so they inherit the existing
    phantom-path handling (next_targets skips candidates; render de-noises them) —
    carried CONTEXT, never a confirmation. Default OFF ⇒ zero behaviour change.

The cross-target asset-graph gap the analysis called out closes here without
touching the authoritative stores.
"""
from __future__ import annotations

import json
import os
import re
import tempfile

from . import model as m

# Only the reconnaissance asset map crosses runs — never secrets or verdicts.
_CARRY_NODE_KINDS = frozenset({m.HOST, m.SERVICE, m.ENDPOINT, m.TECH, m.PARAM})
_CARRY_EDGE_KINDS = frozenset({m.HOSTS, m.RUNS, m.HAS_PARAM})

_MAX_NODES = 600
_MAX_EDGES = 2000
_HOST_RE = re.compile(r"[^A-Za-z0-9._-]")


def crossrun_enabled() -> bool:
    return os.environ.get("SMITH_GRAPH_CROSSRUN", "").strip().lower() in ("1", "true", "yes", "on")


def serialize(g: m.Graph) -> dict:
    """Plain-dict form of a Graph (JSON-safe)."""
    return {
        "nodes": [{"id": n.id, "kind": n.kind, "label": n.label, "attrs": n.attrs}
                  for n in g.nodes.values()],
        "edges": [{"src": e.src, "dst": e.dst, "kind": e.kind, "attrs": e.attrs}
                  for e in g.edges],
    }


def deserialize(d: dict) -> m.Graph:
    """Rebuild a Graph from serialize()'s output. Tolerant of partial data."""
    g = m.Graph()
    for n in (d or {}).get("nodes", []):
        if n.get("id") and n.get("kind"):
            g.add_node(n["id"], n["kind"], n.get("label", ""), **(n.get("attrs") or {}))
    known = set(g.nodes)
    for e in (d or {}).get("edges", []):
        if e.get("src") in known and e.get("dst") in known and e.get("kind"):
            g.add_edge(e["src"], e["dst"], e["kind"], **(e.get("attrs") or {}))
    return g


def _snapshot_dir():
    from core import paths as _paths
    return _paths.REPO_ROOT / "graph-snapshots"


def _target_key(target: str) -> str:
    host = (target or "").split("//")[-1].split("/")[0].split(":")[0].strip().lower()
    return _HOST_RE.sub("_", host) or "unknown"


def snapshot_path(target: str):
    return _snapshot_dir() / f"{_target_key(target)}.json"


def _asset_subgraph(g: m.Graph) -> dict:
    """Serialize ONLY the recon asset map (carryable kinds), bounded."""
    nodes = [n for n in g.nodes.values() if n.kind in _CARRY_NODE_KINDS][:_MAX_NODES]
    keep = {n.id for n in nodes}
    edges = [e for e in g.edges
             if e.kind in _CARRY_EDGE_KINDS and e.src in keep and e.dst in keep][:_MAX_EDGES]
    return {
        "nodes": [{"id": n.id, "kind": n.kind, "label": n.label,
                   # carry only non-secret structural attrs
                   "attrs": {k: v for k, v in (n.attrs or {}).items()
                             if k in ("path", "method", "auth_context", "param_type",
                                      "version", "product", "discovered_by")}}
                  for n in nodes],
        "edges": [{"src": e.src, "dst": e.dst, "kind": e.kind} for e in edges],
    }


def save_snapshot(g: m.Graph, target: str) -> bool:
    """Persist the target's recon asset map. Atomic, fail-soft. Returns success."""
    try:
        if not target:
            return False
        d = _snapshot_dir()
        d.mkdir(parents=True, exist_ok=True)
        payload = _asset_subgraph(g)
        payload["target"] = target
        path = snapshot_path(target)
        fd, tmp = tempfile.mkstemp(dir=str(d), suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        os.replace(tmp, path)
        return True
    except Exception:
        return False


def load_snapshot(target: str) -> dict | None:
    try:
        path = snapshot_path(target)
        if not path.exists():
            return None
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def merge_prior_assets(g: m.Graph, target: str) -> int:
    """Merge a prior run's asset nodes into ``g`` as carried CONTEXT. Each new node
    is tagged provenance='prior_run' + candidate=True so it inherits phantom-path
    handling and never counts as a confirmation. Returns #nodes added. Fail-soft."""
    try:
        snap = load_snapshot(target)
        if not snap:
            return 0
        added = 0
        for n in snap.get("nodes", []):
            nid = n.get("id")
            if not nid or nid in g.nodes:
                continue
            attrs = dict(n.get("attrs") or {})
            attrs["provenance"] = "prior_run"
            attrs["candidate"] = True
            g.add_node(nid, n["kind"], n.get("label", ""), **attrs)
            added += 1
        known = set(g.nodes)
        for e in snap.get("edges", []):
            if e.get("src") in known and e.get("dst") in known:
                g.add_edge(e["src"], e["dst"], e["kind"])
        return added
    except Exception:
        return 0
