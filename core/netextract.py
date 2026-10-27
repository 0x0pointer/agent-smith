"""Internal-host / IP extraction from free text (finding evidence, tool output).

Shared by the knowledge-graph builder (draws REACHES pivot edges) and the
deep-pivot asset promoter (``core.pivot`` — promotes SSRF/RCE-discovered internal
hosts into ``known_assets.ips`` so they can be scanned). Pure stdlib, no side
effects, no session state.

Only INTERNAL addresses are trusted from prose without an asset record: a public
dotted-quad is indistinguishable from a 4-part software version ("sqlmap 1.7.2.1"),
so public IPs are deliberately excluded here (the graph layer qualifies those via
the asset branch instead).
"""
from __future__ import annotations

import re

# A dotted-quad with an optional :port, bounded so it isn't glued to a longer token.
_IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\.?(?![\w.])")

# Internal / cloud / orchestration host names trusted as pivot targets on sight —
# require a <label>. prefix AND a specific internal suffix. Bare 'local'/'svc' are
# deliberately EXCLUDED: they collide with ordinary filenames (config.local, app.svc).
_INTERNAL_NAME_RE = re.compile(
    r"(?<![\w.-])[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*"
    r"\.(?:svc\.cluster\.local|cluster\.local|internal|consul)\.?(?![\w.-])", re.I)

_META_HOSTS = ("metadata.google.internal", "169.254.169.254", "169.254.170.2",
               "kubernetes.default.svc.cluster.local", "kubernetes.default.svc",
               "kubernetes.default")

# SCANNER-OWN infrastructure — reachable only because the scanner itself is containerized,
# and NEVER a pentest target. Promoting these wastes the pivot on the Kali container's own
# Docker bridge + the Docker Desktop gateway (the exact over-promotion seen in the field:
# 172.17.0.2 = Kali's own eth0, 192.168.65.x / host.docker.internal = Docker Desktop vpnkit).
# Names: anything under the Docker Desktop internal domains.
_SCANNER_INFRA_NAME_SUFFIXES = (".docker.internal",)
_SCANNER_INFRA_NAMES = frozenset({
    "host.docker.internal", "gateway.docker.internal", "kubernetes.docker.internal",
    "vpnkit.controller.internal", "docker.for.mac.host.internal", "docker.for.mac.localhost",
    "docker.for.win.host.internal", "docker.for.win.localhost",
})

# Scanner-OWN interface addresses resolved at RUNTIME and excluded as EXACT /32s, never a CIDR
# (IMPROVEMENT-PLAN 1.2). The Kali container's own bridge IP lands inside 10.0.0.0/8 (field:
# 10.110.0.3), so a static range can't carve it out without also blinding genuine 10.x / 172.16/12
# pivot targets (K8s pod CIDRs, a corp LAN — see scannable_internal_ip + the 10.44.0.x test hosts).
# The Kali runner resolves the container's real addresses at start and registers them here; a
# containerized MCP process can register its own via resolve_and_register_local_ips().
_SCANNER_OWN_IPS: set[str] = set()


def register_scanner_own_ips(ips) -> None:
    """Record exact scanner-own addresses (bare dotted-quads) to exclude from promotion.
    Idempotent, fail-soft; only well-formed dotted-quads are stored (never a range)."""
    try:
        for ip in ips or ():
            bare = str(ip).split(":", 1)[0].strip().rstrip(".")
            if looks_like_ip(bare):
                _SCANNER_OWN_IPS.add(bare)
    except Exception:
        pass


def scanner_own_ips() -> frozenset[str]:
    """The exact scanner-own addresses currently excluded from promotion (diagnostics/tests)."""
    return frozenset(_SCANNER_OWN_IPS)


def clear_scanner_own_ips() -> None:
    """Drop every registered scanner-own address (test isolation)."""
    _SCANNER_OWN_IPS.clear()


def resolve_and_register_local_ips() -> frozenset[str]:
    """Resolve THIS process's own IPv4 interface addresses (stdlib, fail-soft) and register
    them as scanner-own. Opt-in — call from a containerized-MCP bootstrap; NOT run implicitly,
    so promotion stays deterministic for callers (and tests) that rely only on what the Kali
    runner explicitly registers."""
    found: set[str] = set()
    try:
        import socket
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            found.add(info[4][0])
    except Exception:
        pass
    register_scanner_own_ips(found)
    return frozenset(found)


def _scanner_infra_ip(ip: str) -> bool:
    """Docker-local fabric the scanner sits on — the default bridge (172.17/16), the first
    user-defined bridge (172.18/16), and the Docker Desktop vpnkit subnet (192.168.65/24) —
    PLUS the scanner's own runtime-resolved interface addresses (exact /32s; see
    register_scanner_own_ips). These are the scanner's own plumbing, not pivotable target
    networks, so they are excluded from promotion. (A real corp 172.16/12 LAN stays scannable —
    only Docker's own two default /16s, the one Docker Desktop /24, and exact scanner-own
    addresses are carved out.)"""
    bare = ip.split(":", 1)[0]
    if bare in _SCANNER_OWN_IPS:
        return True
    o = bare.split(".")
    if len(o) != 4 or not all(p.isdigit() for p in o):
        return False
    a, b, c = int(o[0]), int(o[1]), int(o[2])
    return (a == 172 and b in (17, 18)) or (a == 192 and b == 168 and c == 65)


def _scanner_infra_host(host: str) -> bool:
    """True for a scanner-own-infra host (Docker Desktop name or Docker-local-fabric IP)."""
    h = (host or "").split(":", 1)[0].lower().rstrip(".")
    if h in _SCANNER_INFRA_NAMES or h.endswith(_SCANNER_INFRA_NAME_SUFFIXES):
        return True
    return _scanner_infra_ip(h)


def internal_ip(ip: str) -> bool:
    """True for an RFC1918 / loopback / link-local / CGNAT address with valid octets —
    the only IPs trusted from prose WITHOUT an asset record."""
    parts = ip.split(":", 1)[0].split(".")
    if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return False
    a, b = int(parts[0]), int(parts[1])
    return (a in (10, 127) or (a == 169 and b == 254) or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168) or (a == 100 and 64 <= b <= 127))


def collapse_ports(hosts: set) -> set:
    """Drop a host:port form when its bare host is also present, so one host doesn't
    become two entries (10.0.0.5 + 10.0.0.5:8080)."""
    bare = {h.split(":")[0] for h in hosts}
    return {h for h in hosts if ":" not in h or h.split(":")[0] not in bare}


def scannable_internal_ip(ip: str) -> bool:
    """`internal_ip()` minus loopback (127/8) and link-local (169.254/16) — the set that
    is worth PROMOTING as a pivot scan target.

    A reflected ``127.0.0.1`` is the target's (or, from the Kali container, the scanner's)
    OWN localhost, not a pivotable host; generic link-local is not a pivot target either.
    The two real cloud-metadata endpoints (169.254.169.254 / .170.2) are still caught by the
    ``_META_HOSTS`` branch in ``extract_internal_hosts``, independent of this check. The
    unrestricted ``internal_ip`` is kept for the knowledge-graph layer (visualization)."""
    if not internal_ip(ip):
        return False
    if _scanner_infra_ip(ip):          # the scanner's own Docker bridge / Desktop gateway
        return False
    a, b = (int(x) for x in ip.split(":", 1)[0].split(".")[:2])
    return not (a == 127 or (a == 169 and b == 254))


def extract_internal_hosts(text: str) -> set[str]:
    """Internal IPs (RFC1918/loopback/link-local/CGNAT), internal/cloud DNS names, and
    cloud-metadata endpoints named in `text`. Public dotted-quads are excluded
    (version-number false positives). Returns BARE hosts — any ``:port`` on an IP is
    stripped so ``10.0.0.5:5000`` and ``10.0.0.5`` collapse to one host.
    """
    if not text:
        return set()
    low = text.lower()
    out: set = set()
    for mo in _IP_RE.finditer(text):
        tok = mo.group(0).lower().rstrip(".")
        if scannable_internal_ip(tok):             # excludes loopback/link-local (not pivot targets)
            out.add(tok.split(":", 1)[0])          # drop :port → bare IP
    out |= {mo.group(0).lower().rstrip(".") for mo in _INTERNAL_NAME_RE.finditer(text)}
    # Cloud/k8s metadata hosts nest as substrings (kubernetes.default ⊂ …svc ⊂ …cluster.local);
    # keep only the maximal match so one host doesn't explode into several.
    metas = [meta for meta in _META_HOSTS if meta in low]
    out |= {mh for mh in metas if not any(mh != o and mh in o for o in metas)}
    # Drop the scanner's own container/gateway infra (Docker bridge + Desktop vpnkit) — it's
    # reachable only because the scanner is containerized, never a pivot target.
    return {h for h in out if not _scanner_infra_host(h)}


def looks_like_ip(host: str) -> bool:
    """True when `host` (bare, no port) is a dotted-quad — used to route a promoted
    host into known_assets.ips vs known_assets.domains."""
    parts = host.split(":", 1)[0].split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
