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
    return out


def looks_like_ip(host: str) -> bool:
    """True when `host` (bare, no port) is a dotted-quad — used to route a promoted
    host into known_assets.ips vs known_assets.domains."""
    parts = host.split(":", 1)[0].split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
