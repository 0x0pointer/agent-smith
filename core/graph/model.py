"""Knowledge-graph model (Phase 2 / AR-B1).

A shared world-model the framework builds from what it has learned — hosts,
services, endpoints, params, credentials, tokens, technologies, findings — and
the relationships between them. This is the substrate the analysis called for:
the flat coverage matrix becomes one VIEW over this graph (Param --tested_for-->
InjectionType), and the reasoning the matrix can't express — reachability, data
flow, "what does exploiting X reach" — becomes deterministic graph traversal.

Pure data structures, no I/O. ``build`` projects a Graph from the live stores;
``chains`` queries it. Additive: nothing here mutates session/matrix/findings.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# ── Node kinds ──────────────────────────────────────────────────────────────
HOST = "host"
SERVICE = "service"
ENDPOINT = "endpoint"
PARAM = "param"
CREDENTIAL = "credential"
TOKEN = "token"
TECH = "tech"
FINDING = "finding"
PRIMITIVE = "primitive"        # an attack capability (file_read, code_exec, network_reach, …)

# ── Edge kinds ──────────────────────────────────────────────────────────────
HOSTS = "hosts"                # host --hosts--> endpoint/service
RUNS = "runs"                  # host --runs--> tech/service
HAS_PARAM = "has_param"        # endpoint --has_param--> param
TESTED_FOR = "tested_for"      # param/endpoint --tested_for--> (injection type, via edge attr + status)
AUTHENTICATES = "authenticates"  # credential/token --authenticates--> host/endpoint
FOUND_ON = "found_on"          # finding --found_on--> endpoint/host
LEAKS = "leaks"                # finding --leaks--> credential/token
ESCALATES_TO = "escalates_to"  # finding --escalates_to--> (terminal, via edge attr)
PROVIDES = "provides"          # finding --provides--> primitive (this bug HANDS YOU the capability)
REQUIRES = "requires"          # finding --requires--> primitive (this bug is BLOCKED needing it)
ISSUES = "issues"              # endpoint --issues--> token/session (auth DATAFLOW: login mints a token)
GRANTS = "grants"              # token/session --grants--> endpoint (auth DATAFLOW: token unlocks a protected component)


@dataclass
class Node:
    id: str
    kind: str
    label: str = ""
    attrs: dict = field(default_factory=dict)


@dataclass
class Edge:
    src: str
    dst: str
    kind: str
    attrs: dict = field(default_factory=dict)


@dataclass
class Graph:
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)

    def add_node(self, node_id: str, kind: str, label: str = "", **attrs) -> str:
        if node_id not in self.nodes:
            self.nodes[node_id] = Node(node_id, kind, label or node_id, attrs)
        elif attrs:
            self.nodes[node_id].attrs.update(attrs)
        return node_id

    def add_edge(self, src: str, dst: str, kind: str, **attrs) -> None:
        self.edges.append(Edge(src, dst, kind, attrs))

    def of_kind(self, kind: str) -> list[Node]:
        return [n for n in self.nodes.values() if n.kind == kind]

    def out_edges(self, node_id: str, kind: str | None = None) -> list[Edge]:
        return [e for e in self.edges if e.src == node_id and (kind is None or e.kind == kind)]

    def in_edges(self, node_id: str, kind: str | None = None) -> list[Edge]:
        return [e for e in self.edges if e.dst == node_id and (kind is None or e.kind == kind)]

    def stats(self) -> dict:
        kinds: dict[str, int] = {}
        for n in self.nodes.values():
            kinds[n.kind] = kinds.get(n.kind, 0) + 1
        return {"nodes": len(self.nodes), "edges": len(self.edges), "by_kind": kinds}
