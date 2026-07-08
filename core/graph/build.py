"""Project a knowledge Graph from the live stores (Phase 2 / AR-B1).

Additive and read-only: assembles nodes/edges from session known_assets, the
coverage matrix, and findings.json. Nothing here mutates those stores — the
graph is a derived view, rebuilt on demand, so it can't drift from or corrupt
the source of truth while the matrix remains authoritative.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from . import model as m


def _host_of(url_or_target: str) -> str:
    try:
        p = urlparse(url_or_target if "//" in url_or_target else f"//{url_or_target}")
        return p.netloc or p.path.split("/")[0] or url_or_target
    except Exception:
        return url_or_target


def _clean_host(raw: str, root_host: str) -> str:
    """Best-effort host from a freeform finding ``target`` string, falling back to
    the scan's root host. Finding targets are human-written (e.g.
    "http://localhost:5000 (JWT auth, /sup3r_s3cr3t_admin)"), so a naive
    ``_host_of`` yields junk like ``localhost:5000 (JWT auth,`` — reject anything
    that isn't a clean ``host[:port]`` and use the root host instead. This keeps
    every finding anchored to the ONE target node rather than spawning duplicate,
    disconnected host nodes (a cause of the 'loose nodes' the graph used to show)."""
    if not raw:
        return root_host
    h = _host_of(raw)
    if not h or any(c in h for c in " /()[]"):
        return root_host
    return h or root_host


def _endpoint_host(path: str, root_host: str) -> str:
    """The host an endpoint belongs to. Endpoint paths from the coverage matrix are
    RELATIVE ("/login", "/api/v1/payments"), so they must anchor to the scan's root
    host. Only override when the path is a genuine absolute URL to another host
    (real netloc). The old code ran ``_host_of("/login")`` -> "/login" (a truthy
    non-host), built an edge to a ``host:/login`` node that was never created, and
    the dangling edge got dropped client-side — leaving every endpoint (and its
    params) floating disconnected from the target."""
    if "//" in path:
        h = _host_of(path)
        if h and "/" not in h and " " not in h:
            return h
    return root_host


def _add_tech_nodes(g, ka, root_host) -> None:
    """Technologies / fingerprints → TECH nodes RUN by the host."""
    for tech in ka.get("technologies", []) or []:
        tid = g.add_node(f"tech:{str(tech).lower()}", m.TECH, str(tech))
        if root_host:
            g.add_edge(f"host:{root_host}", tid, m.RUNS)


def _add_endpoint_nodes(g, matrix, root_host) -> tuple[dict, dict]:
    """Endpoints + their params, anchored to the target host so the graph reads
    target -> component -> param. Returns ({endpoint_id: node_id}, {path: node_id})
    — the first wires coverage cells, the second lets findings attach to the
    component they were found on."""
    ep_by_id: dict = {}
    ep_by_path: dict = {}
    for ep in matrix.get("endpoints", []):
        eid = f"ep:{ep['id']}"
        ep_by_id[ep["id"]] = eid
        path = ep.get("path", "")
        g.add_node(eid, m.ENDPOINT, f"{ep.get('method','GET')} {path}",
                   path=path, method=ep.get("method", "GET"),
                   auth_context=ep.get("auth_context", "none"))
        if path:
            ep_by_path.setdefault(path, eid)
        host = _endpoint_host(path, root_host)
        if host:
            g.add_node(f"host:{host}", m.HOST, host)  # materialize so the edge isn't dangling
            g.add_edge(f"host:{host}", eid, m.HOSTS)
        for p in ep.get("params", []) or []:
            pid = f"param:{ep['id']}:{p.get('name','')}"
            g.add_node(pid, m.PARAM, p.get("name", ""), type=p.get("type", "query"))
            g.add_edge(eid, pid, m.HAS_PARAM)
    return ep_by_id, ep_by_path


def _add_cell_edges(g, matrix, ep_by_id) -> dict:
    """The coverage matrix cells, as endpoint→injection TESTED_FOR edges. Also
    returns {finding_id: endpoint_node_id} so confirmed findings anchor to the
    exact component whose cell they closed."""
    fid_to_ep: dict = {}
    for cell in matrix.get("matrix", []):
        eid = ep_by_id.get(cell.get("endpoint_id"))
        if not eid:
            continue
        g.add_edge(eid, f"inj:{cell.get('injection_type')}", m.TESTED_FOR,
                   status=cell.get("status"), param=cell.get("param"),
                   finding_id=cell.get("finding_id"))
        if cell.get("finding_id"):
            fid_to_ep[cell["finding_id"]] = eid
    return fid_to_ep


# Endpoint paths whose handler MINTS auth material (a session/JWT) — the source
# of the auth dataflow. Matched against the endpoint path.
_AUTH_ISSUER_RE = re.compile(r"/(login|signin|sign-in|authenticate|auth|token|oauth|session)(/|$)", re.I)
# auth_context values that mean "this component is gated by a token/session" — the
# sinks of the auth dataflow.
_PROTECTED_AUTH = {"jwt", "bearer", "token", "session", "cookie", "apikey", "api_key",
                   "merchant", "merchantapikey", "oauth", "basic"}


def _add_auth_flow(g, ep_by_id, root_host) -> None:
    """Overlay the auth/token DATAFLOW: issuer endpoints (login/token) --issues-->
    a session/token hub --grants--> every auth-gated endpoint. This is the 'how are
    the components linked together' the flat node soup lacked — it shows the
    credential a login mints flowing into each protected component."""
    endpoints = g.of_kind(m.ENDPOINT)
    issuers = [n for n in endpoints if _AUTH_ISSUER_RE.search(n.attrs.get("path", ""))]
    protected = [n for n in endpoints
                 if str(n.attrs.get("auth_context", "none")).lower() in _PROTECTED_AUTH]
    if not issuers and not protected:
        return
    # Prefer a real captured token node as the hub; else a synthetic session node.
    toks = g.of_kind(m.TOKEN)
    hub = toks[0].id if toks else g.add_node(f"token:session:{root_host}", m.TOKEN, "session/JWT")
    if root_host:
        g.add_edge(hub, f"host:{root_host}", m.AUTHENTICATES)  # anchor the hub to the target
    issuer_ids = {n.id for n in issuers}
    for iss in issuers:
        g.add_edge(iss.id, hub, m.ISSUES)
    for pep in protected:
        if pep.id not in issuer_ids:
            g.add_edge(hub, pep.id, m.GRANTS)


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


def _match_endpoint(text: str, ep_by_path: dict) -> str | None:
    """Anchor a finding to the component it names. Longest path first so
    "/admin/create_admin" wins over "/admin"."""
    for path in sorted((p for p in ep_by_path if len(p) > 1), key=len, reverse=True):
        if path in text:
            return ep_by_path[path]
    return None


def _add_finding_nodes(g, root_host, ep_by_path, fid_to_ep) -> None:
    """Findings → FOUND_ON their endpoint (falling back to the target host), LEAKS
    (credential material), ESCALATES_TO, and PROVIDES/REQUIRES primitive edges (the
    substrate for compositional chaining). Anchoring to the endpoint (not just the
    host) is what makes a finding read as belonging to a component in the tree."""
    from core import findings as findings_store
    for f in findings_store._load().get("findings", []):
        fid = f"finding:{f.get('id','')}"
        g.add_node(fid, m.FINDING, f.get("title", ""),
                   severity=(f.get("severity") or "").lower(), target=f.get("target", ""),
                   status=(f.get("status") or "").lower())
        fhost = _clean_host(f.get("target", ""), root_host)
        title, desc = f.get("title", ""), f.get("description", "")
        text = f"{title} {desc} {f.get('target','')}"
        # Prefer the exact endpoint (via the cell it closed, else a path match in
        # its text); anchor to the host only when no component is identifiable.
        anchor = fid_to_ep.get(f.get("id", "")) or _match_endpoint(text, ep_by_path)
        if anchor:
            g.add_edge(fid, anchor, m.FOUND_ON)
        elif fhost:
            g.add_node(f"host:{fhost}", m.HOST, fhost)  # materialize so the edge isn't dangling
            g.add_edge(fid, f"host:{fhost}", m.FOUND_ON)
        if fhost and any(k in text.lower() for k in _CRED_LEAK_MARKERS):
            g.add_node(f"host:{fhost}", m.HOST, fhost)
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


# Memoized (mtime, size) signature → built Graph. build_graph() was re-run on
# every QA-daemon tick and every report(action='note') bridge, each time
# re-reading and re-projecting all three stores. The projection is read-only and
# consumers never mutate the returned graph, so a shared instance is reused until
# an input changes.
_GRAPH_CACHE: "tuple[tuple, m.Graph] | None" = None


def _cache_key() -> tuple:
    """Cheap version signature of the three stores build_graph reads. All three
    flush to disk on every mutation (findings._save / coverage._save /
    session._flush), so (mtime_ns, size) is an accurate change signal both
    in-process and across the QA-daemon / dashboard processes — and no file is
    read to compute it."""
    from core import paths as _paths
    sig = []
    for p in (_paths.SESSION_FILE, _paths.FINDINGS_FILE, _paths.COVERAGE_FILE):
        try:
            st = p.stat()
            sig.append((st.st_mtime_ns, st.st_size))
        except OSError:
            sig.append((0, 0))
    return tuple(sig)


def invalidate_graph_cache() -> None:
    """Drop the memoized graph. The test harness calls this between tests (the
    stores are monkeypatched in-memory there, so the mtime key can't observe the
    change); also available to any caller that mutates a store out-of-band."""
    global _GRAPH_CACHE
    _GRAPH_CACHE = None


def build_graph() -> m.Graph:
    """Assemble the world-model graph, memoized on the (mtime, size) of
    session.json / findings.json / coverage_matrix.json (see _cache_key)."""
    global _GRAPH_CACHE
    key = _cache_key()
    if _GRAPH_CACHE is not None and _GRAPH_CACHE[0] == key:
        return _GRAPH_CACHE[1]
    g = _assemble()
    _GRAPH_CACHE = (key, g)
    return g


def _assemble() -> m.Graph:
    """Project the world-model graph from everything learned so far."""
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
    ep_by_id, ep_by_path = _add_endpoint_nodes(g, matrix, root_host)
    fid_to_ep = _add_cell_edges(g, matrix, ep_by_id)
    _add_credential_nodes(g, ka, root_host)
    _add_auth_flow(g, ep_by_id, root_host)
    _add_finding_nodes(g, root_host, ep_by_path, fid_to_ep)
    return g
