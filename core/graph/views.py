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
        pending = [e for e in g.out_edges(ep.id, m.TESTED_FOR)
                   if e.attrs.get("status") not in _ADDRESSED]
        if pending:
            out.append({"endpoint": ep.label, "path": ep.attrs.get("path", ""),
                        "pending_cells": len(pending), "value_rank": _ep_value(ep.attrs.get("path", ""))})
    out.sort(key=lambda t: (t["value_rank"], -t["pending_cells"]))
    return out[:limit]
