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


def build_graph() -> m.Graph:
    """Assemble the world-model graph from everything learned so far."""
    from core import findings as findings_store
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

    # Technologies / fingerprints
    for tech in ka.get("technologies", []) or []:
        tid = g.add_node(f"tech:{str(tech).lower()}", m.TECH, str(tech))
        if root_host:
            g.add_edge(f"host:{root_host}", tid, m.RUNS)

    # Endpoints + params + tested_for cells (the coverage matrix, as graph edges)
    ep_by_id = {}
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

    for cell in matrix.get("matrix", []):
        eid = ep_by_id.get(cell.get("endpoint_id"))
        if not eid:
            continue
        g.add_edge(eid, f"inj:{cell.get('injection_type')}", m.TESTED_FOR,
                   status=cell.get("status"), param=cell.get("param"),
                   finding_id=cell.get("finding_id"))

    # Credentials + tokens (principals that authenticate the host)
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

    # Findings: found_on + leaks + escalates_to
    for f in findings_store._load().get("findings", []):
        fid = f"finding:{f.get('id','')}"
        g.add_node(fid, m.FINDING, f.get("title", ""),
                   severity=(f.get("severity") or "").lower(), target=f.get("target", ""),
                   status=(f.get("status") or "").lower())
        fhost = _host_of(f.get("target", "")) or root_host
        if fhost:
            g.add_edge(fid, f"host:{fhost}", m.FOUND_ON)
        text = f"{f.get('title','')} {f.get('description','')}".lower()
        if any(k in text for k in ("credential", "password", "token leak", "secret", "api key", "api_key")):
            g.add_edge(fid, f"host:{fhost or root_host}", m.LEAKS, what="credential-material")
        for lead in f.get("escalation_leads", []) or []:
            if isinstance(lead, dict) and lead.get("status") == "pending":
                g.add_edge(fid, fid, m.ESCALATES_TO, lead=lead.get("lead", ""))

    return g
