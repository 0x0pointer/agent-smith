"""Project a knowledge Graph from the live stores (Phase 2 / AR-B1).

Additive and read-only: assembles nodes/edges from session known_assets, the
coverage matrix, and findings.json. Nothing here mutates those stores — the
graph is a derived view, rebuilt on demand, so it can't drift from or corrupt
the source of truth while the matrix remains authoritative.
"""
from __future__ import annotations

from urllib.parse import urlparse

from . import model as m


def _host_of(url_or_target: str) -> str:
    try:
        p = urlparse(url_or_target if "//" in url_or_target else f"//{url_or_target}")
        return p.netloc or p.path.split("/")[0] or url_or_target
    except Exception:
        return url_or_target


def _add_tech_nodes(g, ka, root_host) -> None:
    """Technologies / fingerprints → TECH nodes RUN by the host."""
    for tech in ka.get("technologies", []) or []:
        tid = g.add_node(f"tech:{str(tech).lower()}", m.TECH, str(tech))
        if root_host:
            g.add_edge(f"host:{root_host}", tid, m.RUNS)


def _add_endpoint_nodes(g, matrix, root_host) -> dict:
    """Endpoints + their params. Returns {endpoint_id: node_id} for cell wiring."""
    ep_by_id: dict = {}
    for ep in matrix.get("endpoints", []):
        eid = f"ep:{ep['id']}"
        ep_by_id[ep["id"]] = eid
        g.add_node(eid, m.ENDPOINT, f"{ep.get('method','GET')} {ep.get('path','')}",
                   path=ep.get("path", ""), method=ep.get("method", "GET"),
                   auth_context=ep.get("auth_context", "none"))
        host = _host_of(ep.get("path", "")) or root_host
        if host:
            g.add_edge(f"host:{host}", eid, m.HOSTS)
        for p in ep.get("params", []) or []:
            pid = f"param:{ep['id']}:{p.get('name','')}"
            g.add_node(pid, m.PARAM, p.get("name", ""), type=p.get("type", "query"))
            g.add_edge(eid, pid, m.HAS_PARAM)
    return ep_by_id


def _add_cell_edges(g, matrix, ep_by_id) -> None:
    """The coverage matrix cells, as endpoint→injection TESTED_FOR edges."""
    for cell in matrix.get("matrix", []):
        eid = ep_by_id.get(cell.get("endpoint_id"))
        if not eid:
            continue
        g.add_edge(eid, f"inj:{cell.get('injection_type')}", m.TESTED_FOR,
                   status=cell.get("status"), param=cell.get("param"),
                   finding_id=cell.get("finding_id"))


def _add_credential_nodes(g, ka, root_host) -> None:
    """Credentials + tokens — principals that AUTHENTICATE the host."""
    for c in ka.get("credentials", []) or []:
        u = c.get("username")
        if not u:
            continue
        cid = g.add_node(f"cred:{u}", m.CREDENTIAL, u, source=c.get("source", ""))
        if root_host:
            g.add_edge(cid, f"host:{root_host}", m.AUTHENTICATES)
    for t in ka.get("auth_tokens", []) or []:
        val = t.get("value") if isinstance(t, dict) else t
        if not val:
            continue
        tid = g.add_node(f"token:{str(val)[:16]}", m.TOKEN, "jwt/token",
                         role=(t.get("role") if isinstance(t, dict) else ""))
        if root_host:
            g.add_edge(tid, f"host:{root_host}", m.AUTHENTICATES)


# Markers in a finding's text that imply it leaks credential material.
_CRED_LEAK_MARKERS = ("credential", "password", "token leak", "secret", "api key", "api_key")


def _add_finding_nodes(g, root_host) -> None:
    """Findings → FOUND_ON host, LEAKS (credential material), ESCALATES_TO, and
    PROVIDES/REQUIRES primitive edges (the substrate for compositional chaining)."""
    from core import findings as findings_store
    for f in findings_store._load().get("findings", []):
        fid = f"finding:{f.get('id','')}"
        g.add_node(fid, m.FINDING, f.get("title", ""),
                   severity=(f.get("severity") or "").lower(), target=f.get("target", ""),
                   status=(f.get("status") or "").lower())
        fhost = _host_of(f.get("target", "")) or root_host
        if fhost:
            g.add_node(f"host:{fhost}", m.HOST, fhost)  # materialize so the edge isn't dangling
            g.add_edge(fid, f"host:{fhost}", m.FOUND_ON)
        title, desc = f.get("title", ""), f.get("description", "")
        text = f"{title} {desc}".lower()
        if fhost and any(k in text for k in _CRED_LEAK_MARKERS):
            g.add_edge(fid, f"host:{fhost}", m.LEAKS, what="credential-material")
        for lead in f.get("escalation_leads", []) or []:
            if isinstance(lead, dict) and lead.get("status") == "pending":
                g.add_edge(fid, fid, m.ESCALATES_TO, lead=lead.get("lead", ""))
        _add_primitive_edges(g, fid, f)


def _add_primitive_edges(g, fid: str, f: dict) -> None:
    """Emit finding→primitive PROVIDES/REQUIRES edges (the compositional-chaining
    substrate). Explicit ``provides``/``requires`` fields (set via
    report(action='finding'/'update_finding')) union with the text classifier.
    Fail-soft: a classifier raise never breaks the caller's finding loop."""
    from core.graph import primitives as prim
    try:
        title, desc = f.get("title", ""), f.get("description", "")
        provides = set(prim.coerce_primitive_list(f.get("provides"))) | prim.classify_provides(title, desc, f.get("cve", ""))
        requires = set(prim.coerce_primitive_list(f.get("requires"))) | prim.classify_requires(title, desc)
        for kind, prims in ((m.PROVIDES, provides), (m.REQUIRES, requires)):
            for p in prims:
                g.add_node(f"prim:{p}", m.PRIMITIVE, p)
                g.add_edge(fid, f"prim:{p}", kind)
    except Exception:
        pass


def build_graph() -> m.Graph:
    """Assemble the world-model graph from everything learned so far."""
    from core import session as scan_session
    try:
        from core import coverage as cov
        matrix = cov.get_matrix()
    except Exception:
        matrix = {"endpoints": [], "matrix": []}

    g = m.Graph()
    sess = scan_session.get() or {}
    ka = sess.get("known_assets") or {}
    target = sess.get("target", "") or ""
    root_host = _host_of(target) if target else ""
    if root_host:
        g.add_node(f"host:{root_host}", m.HOST, root_host)

    _add_tech_nodes(g, ka, root_host)
    ep_by_id = _add_endpoint_nodes(g, matrix, root_host)
    _add_cell_edges(g, matrix, ep_by_id)
    _add_credential_nodes(g, ka, root_host)
    _add_finding_nodes(g, root_host)
    return g
