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


def _add_cell_edges(g, matrix, ep_by_id) -> tuple[dict, dict]:
    """The coverage matrix cells, as endpoint→injection TESTED_FOR edges. Returns
    ({finding_id: endpoint_node}, {finding_id: param_node}) so a confirmed finding
    anchors to the exact PARAM it closed (deepest) — falling back to its endpoint."""
    fid_to_ep: dict = {}
    fid_to_param: dict = {}
    for cell in matrix.get("matrix", []):
        eid = ep_by_id.get(cell.get("endpoint_id"))
        if not eid:
            continue
        g.add_edge(eid, f"inj:{cell.get('injection_type')}", m.TESTED_FOR,
                   status=cell.get("status"), param=cell.get("param"),
                   finding_id=cell.get("finding_id"))
        fid = cell.get("finding_id")
        if fid:
            fid_to_ep[fid] = eid
            if cell.get("param"):
                fid_to_param[fid] = f"param:{cell.get('endpoint_id')}:{cell.get('param')}"
    return fid_to_ep, fid_to_param


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


def _leaked_cred_nodes(g, text: str) -> list[str]:
    """Credential/token nodes whose identity (username, or token value snippet) is
    named in a leak finding's text — so the leak edge points at the actual principal
    it exposed, not just the host."""
    low = text.lower()
    out: list[str] = []
    for n in g.of_kind(m.CREDENTIAL) + g.of_kind(m.TOKEN):
        label = (n.label or "").lower()
        if n.kind == m.CREDENTIAL and len(label) >= 4 and label in low:
            out.append(n.id)
        elif n.kind == m.TOKEN:
            snippet = n.id.split(":", 1)[-1].lower()  # token:<value[:16]>
            if len(snippet) >= 6 and snippet in low:
                out.append(n.id)
    return out


def _add_finding_nodes(g, root_host, ep_by_path, fid_to_ep, fid_to_param) -> None:
    """Findings → FOUND_ON the exact PARAM they closed (deepest; else endpoint, else
    host), LEAKS the specific credential/token they exposed (else host), ESCALATES_TO,
    and PROVIDES/REQUIRES primitive edges. Anchoring down to the param/component is what
    makes a finding read as belonging where it was found, not piled on the host."""
    from core import findings as findings_store
    for f in findings_store._load().get("findings", []):
        fid = f"finding:{f.get('id','')}"
        g.add_node(fid, m.FINDING, f.get("title", ""),
                   severity=(f.get("severity") or "").lower(), target=f.get("target", ""),
                   status=(f.get("status") or "").lower())
        fhost = _clean_host(f.get("target", ""), root_host)
        title, desc = f.get("title", ""), f.get("description", "")
        text = f"{title} {desc} {f.get('target','')}"
        # Deepest anchor: the exact PARAM its cell closed → else its endpoint → else a
        # path match in the text → else the host.
        param_anchor = fid_to_param.get(f.get("id", ""))
        anchor = (param_anchor if param_anchor in g.nodes else None) \
            or fid_to_ep.get(f.get("id", "")) or _match_endpoint(text, ep_by_path)
        if anchor:
            g.add_edge(fid, anchor, m.FOUND_ON)
        elif fhost:
            g.add_node(f"host:{fhost}", m.HOST, fhost)  # materialize so the edge isn't dangling
            g.add_edge(fid, f"host:{fhost}", m.FOUND_ON)
        # LEAKS → the specific credential/token exposed (where it lives), else the host.
        if any(k in text.lower() for k in _CRED_LEAK_MARKERS):
            leaked = _leaked_cred_nodes(g, text)
            if leaked:
                for cn in leaked:
                    g.add_edge(fid, cn, m.LEAKS, what="credential-material")
            elif fhost:
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


# ── Generic host-discovery / pivot linking ──────────────────────────────────
# A world model should show hosts as SEPARATE circles by default; two hosts get
# LINKED only when there's evidence one was reached/discovered THROUGH the other.
# That is the general pattern behind many exploits, not just SSRF: an XXE or LFI
# leaks a DB host from a config, harvested creds authenticate on a second box
# (lateral movement), a response leaks an internal service URL, a shell pivots
# deeper, a cloud-metadata read exposes another resource. The unifying signal is
# PROVENANCE — a host identifier that surfaces in the EVIDENCE of a finding anchored
# on host A means "A reached B" — so we materialize B and draw
# finding --reaches[via=…]--> B. Hosts already modelled as real targets (root / scope
# / endpoint hosts) are left untouched, so genuinely separate machines with no chain
# between them stay as separate circles.
_IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\.?(?![\w.])")
# Internal / cloud / orchestration host names trusted as pivot targets on sight —
# require a <label>. prefix AND a specific internal suffix. Bare 'local'/'svc' are
# deliberately EXCLUDED: they collide with ordinary filenames (config.local, app.svc)
# that appear in exactly the file-read/traversal findings this model keys on.
_INTERNAL_NAME_RE = re.compile(
    r"(?<![\w.-])[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*"
    r"\.(?:svc\.cluster\.local|cluster\.local|internal|consul)\.?(?![\w.-])", re.I)
_META_HOSTS = ("metadata.google.internal", "169.254.169.254", "169.254.170.2",
               "kubernetes.default.svc.cluster.local", "kubernetes.default.svc",
               "kubernetes.default")
# How a host was reached — cosmetic label on the REACHES edge, best-effort from text.
_MECHANISMS = (
    (("ssrf", "server-side request forgery", "server side request"), "ssrf"),
    (("xxe", "xml external entity"), "xxe"),
    (("pass-the-hash", "pass the hash", "kerberoast", "ntlm relay", "lateral", "pivot"), "lateral"),
    (("path traversal", "local file inclusion", "lfi", "file read", "file disclosure",
      "/etc/", "arbitrary file"), "file-disclosure"),
    (("connection string", "reused credential", "credential reuse", "hardcoded",
      "leaked credential", "harvested"), "cred-reuse"),
    (("open redirect", "gopher://", "dict://", "proxied", "proxy"), "proxy"),
    (("subdomain", "certificate transparency", "dns record", "resolves to"), "recon"),
)


def _mechanism_of(text: str) -> str:
    low = text.lower()
    for markers, label in _MECHANISMS:
        if any(mk in low for mk in markers):
            return label
    return "discovery"


def _asset_host_values(ka) -> set:
    """Hostnames/IPs the scan already recorded — used to confirm (denoise) external
    FQDNs named in finding prose."""
    out: set = set()
    for key in ("ips", "hosts", "domains", "subdomains"):
        for a in ka.get(key, []) or []:
            v = a.get("value") if isinstance(a, dict) else a
            if v:
                out.add(str(v).strip().lower())
    return out


def _internal_ip(ip: str) -> bool:
    """True for an RFC1918 / loopback / link-local / CGNAT address with valid octets —
    the only IPs trusted from finding prose WITHOUT an asset record. A public dotted-quad
    is indistinguishable from a 4-part software version ('sqlmap 1.7.2.1'), so public IPs
    qualify only via the asset branch, not on sight."""
    parts = ip.split(":", 1)[0].split(".")
    if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return False
    a, b = int(parts[0]), int(parts[1])
    return (a in (10, 127) or (a == 169 and b == 254) or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168) or (a == 100 and 64 <= b <= 127))


def _asset_hits(low: str, asset_hosts: set) -> set:
    """Recorded asset hostnames named in the text — matched on a word boundary with a
    length floor. A raw substring test links short names ('api') into unrelated prose
    ('rapid'), mirroring the same defect _leaked_cred_nodes guards against."""
    return {a for a in asset_hosts
            if a and len(a) >= 4 and re.search(rf"(?<![\w.-]){re.escape(a)}(?![\w.-])", low)}


def _collapse_ports(hosts: set) -> set:
    """Drop a host:port form when its bare host is also present, so one host doesn't
    become two circles (10.0.0.5 + 10.0.0.5:8080)."""
    bare = {h.split(":")[0] for h in hosts}
    return {h for h in hosts if ":" not in h or h.split(":")[0] not in bare}


def _hosts_in_text(text: str, asset_hosts: set) -> set:
    """Host identifiers named in a finding's evidence: INTERNAL IPs, internal/cloud DNS,
    cloud-metadata endpoints, plus any hostname already on record as an asset. Public
    dotted-quads are intentionally NOT trusted here (version-number false positives) —
    they qualify only via the asset branch."""
    low = text.lower()
    # .rstrip('.') so a sentence-final host ("…10.0.0.9." / "…cluster.local.") normalizes.
    out: set = {ip for ip in (mo.group(0).lower().rstrip(".") for mo in _IP_RE.finditer(text))
                if _internal_ip(ip)}
    out |= {mo.group(0).lower().rstrip(".") for mo in _INTERNAL_NAME_RE.finditer(text)}
    # Cloud/k8s metadata hosts nest as substrings (kubernetes.default ⊂
    # kubernetes.default.svc ⊂ …cluster.local) — keep only the maximal match so one host
    # doesn't explode into several circles.
    metas = [meta for meta in _META_HOSTS if meta in low]
    out |= {mh for mh in metas if not any(mh != o and mh in o for o in metas)}
    out |= _asset_hits(low, asset_hosts)
    return _collapse_ports(out)


def _add_discovered_hosts(g, root_host, ka) -> None:
    """Link hosts discovered THROUGH a finding to that finding (generic pivot model —
    see the comment above). Only NEW hosts (not already real target nodes) are
    materialized, so separate in-scope machines remain separate circles; each
    discovering finding contributes its own REACHES edge so multiple paths to the same
    pivot are all visible."""
    from core import findings as findings_store
    existing: set = set()
    for n in g.of_kind(m.HOST):
        lab = (n.label or "").strip().lower()
        if lab:
            existing.add(lab)
            existing.add(lab.split(":")[0])
    if root_host:
        existing.add(root_host.lower())
        existing.add(root_host.lower().split(":")[0])
    asset_hosts = _asset_host_values(ka)
    discovered: dict = {}   # bare host -> node id, so bare+port forms across findings reuse ONE node
    for f in findings_store._load().get("findings", []):
        fid = f"finding:{f.get('id','')}"
        if fid not in g.nodes:
            continue
        text = " ".join(str(f.get(k, "")) for k in ("title", "description", "evidence", "target"))
        via = _mechanism_of(text)
        for h in _hosts_in_text(text, asset_hosts):
            h = h.strip().rstrip(".")
            bare = h.split(":")[0]
            if not h or h in existing or bare in existing:
                continue
            hn = discovered.get(bare)
            if hn is None:
                hn = g.add_node(f"host:{h}", m.HOST, h, discovered=True, via=via)
                discovered[bare] = hn
            g.add_edge(fid, hn, m.REACHES, via=via)   # one edge per discovering finding


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
    fid_to_ep, fid_to_param = _add_cell_edges(g, matrix, ep_by_id)
    _add_credential_nodes(g, ka, root_host)
    _add_auth_flow(g, ep_by_id, root_host)
    _add_finding_nodes(g, root_host, ep_by_path, fid_to_ep, fid_to_param)
    _add_discovered_hosts(g, root_host, ka)
    return g
