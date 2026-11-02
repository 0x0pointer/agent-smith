"""Deep post-exploit pivot (depth=danger / scan_mode=benchmark).

When SSRF/RCE reveals internal hosts, a deep-pivot scan PROMOTES them into
``known_assets`` and records each as a per-host scanning surface so the scan
can't finish while they're unscanned (the completion blocker in
``completion_gates``). A normal scan instead raises a NON-BLOCKING wishlist
``scope`` item so the operator decides whether to pivot — scanning internal
hosts reached only through the perimeter is aggressive and auto-runs solely
under explicit opt-in.

All entry points are fail-soft: they never raise into the finding/HTTP hot path.
"""
from __future__ import annotations

import core.session as scan_session
from core import netextract


def _known_hosts(cur: dict) -> set[str]:
    """Host keys already on record (target + known ips/domains) or out-of-scope — never
    re-promoted or re-asked."""
    from core.session import surface_ledger as _ledger
    out: set[str] = set()
    if cur.get("target"):
        out.add(_ledger.host_key(cur["target"]))
    ka = cur.get("known_assets", {}) or {}
    for key in ("ips", "domains"):
        for v in ka.get(key, []) or []:
            if isinstance(v, str):
                out.add(_ledger.host_key(v))
    for v in cur.get("out_of_scope", []) or []:
        if isinstance(v, str):
            out.add(_ledger.host_key(v))
    return {h for h in out if h}


# K8s service DNS collapses: a short name and its FQDN are the SAME service, so promoting both
# (across separate SSRF leaks) double-counts one host. Normalize to a base identity for dedup.
_CLUSTER_SUFFIXES = (".svc.cluster.local", ".cluster.local", ".svc")


def _cluster_base(host: str) -> str | None:
    """Base identity of a K8s service DNS name (short name == FQDN); None if not cluster-family."""
    hl = (host or "").lower()
    for suf in _CLUSTER_SUFFIXES:
        if hl.endswith(suf):
            return hl[: -len(suf)]
    return "kubernetes.default" if hl.startswith("kubernetes.default") else None


def _new_internal_hosts(text: str, cur: dict) -> list[str]:
    """Internal host keys named in `text` that aren't already known/out-of-scope. Collapses K8s
    service short-name/FQDN variants so one service isn't promoted as several hosts."""
    from core.session import surface_ledger as _ledger
    known = _known_hosts(cur)
    known_bases = {b for b in (_cluster_base(k) for k in known) if b}
    new: list[str] = []
    seen: set[str] = set()
    seen_bases: set[str] = set()
    for h in netextract.extract_internal_hosts(text or ""):
        hk = _ledger.host_key(h)
        if not hk or hk in known or hk in seen:
            continue
        base = _cluster_base(hk)
        if base and (base in known_bases or base in seen_bases):
            continue          # a K8s short-name/FQDN variant of an already-known service
        seen.add(hk)
        if base:
            seen_bases.add(base)
        new.append(hk)
    return new


def pivot_reachable(cur: dict) -> bool:
    """True once ANY promoted internal host has actually been REACHED — i.e. a working pivot path
    (a tunnel through the foothold, or a direct route) exists. Until then, cluster-internal hosts
    are reachable ONLY from the compromised pod and a direct scan from Kali just times out — so the
    blocker/recovery steer must be TUNNEL-FIRST rather than 'scan each host' (which caused the
    multi-hour unreachable-retry churn). Fail-soft → False."""
    try:
        na = ((cur or {}).get("surface_coverage") or {}).get("network-assess") or {}
        return bool(na.get("covered"))
    except Exception:
        return False


def promote_internal_hosts(text: str, source: str = "") -> list[str]:
    """DEEP-PIVOT: promote newly-seen internal hosts in `text` into known_assets
    (ips/domains), record each for per-host scanning in the surface ledger, and open
    the ``internal_network`` gate. Returns the promoted host keys; [] when deep-pivot
    is off or nothing new was found. Fail-soft."""
    try:
        cur = scan_session.get()
        if not scan_session.deep_pivot_enabled(cur):
            return []
        new = _new_internal_hosts(text, cur)
        if not new:
            return []
        ips = [h for h in new if netextract.looks_like_ip(h)]
        names = [h for h in new if not netextract.looks_like_ip(h)]
        if ips:
            scan_session.update_known_assets("ips", ips)
        if names:
            scan_session.update_known_assets("domains", names)
        from core.session import surface_ledger as _ledger
        for h in new:
            for sk in _ledger.HOST_UNIT_SKILLS:
                _ledger.record_discovered(sk, h, "host")
        _register_pivot_matrix_stubs(new)
        scan_session.trigger_gate(
            "internal_network",
            f"Deep-pivot: {len(new)} internal host(s) discovered via {source or 'pivot'} "
            f"({', '.join(new[:5])}) — port-scan + recon each",
            ["network-assess"])
        # A genuine (non-metadata) internal host reached AFTER an 'no internal network' dismissal
        # CONTRADICTS it — trigger_gate alone won't re-open a not_applicable gate (same skills), so
        # re-open it once with a clear directive instead of silently skipping the pivot.
        if any(h not in netextract._META_HOSTS for h in new):
            scan_session.reopen_gate_on_evidence(
                "internal_network",
                reason=f"internal host(s) reached post-dismissal: {', '.join(new[:5])}",
                new_trigger=(f"RE-OPENED: internal host(s) reached after a 'no internal network' "
                             f"dismissal ({', '.join(new[:5])}) — the target DOES expose an internal "
                             "network from the foothold. Port-scan + recon each via /network-assess "
                             "(tunnel through the foothold first if a direct scan can't route)."))
        try:
            from core import logger as log
            log.note(f"deep-pivot promoted {len(new)} internal host(s): {', '.join(new[:8])}")
        except Exception:
            pass
        _notify_operator_pivot(new, source)
        return new
    except Exception:
        return []


def _register_pivot_matrix_stubs(hosts: list[str]) -> None:
    """Give each promoted internal host a thin ATTRIBUTION STUB in the coverage matrix
    (IMPROVEMENT-PLAN 1.4): a host-tagged endpoint row with NO cells, so the matrix can
    answer "which endpoint belongs to which host" the moment a pivot host is promoted —
    without fanning out injection/cross-cutting cells (no NA bloat, nothing to stall
    completion while the host is unreachable). Real testable cells are added later, when the
    agent re-registers host-qualified endpoints WITH params through add_endpoint once a route
    exists (the dedup path upgrades the stub). Fail-soft."""
    try:
        from core import coverage
        for h in hosts:
            coverage.register_pivot_stub(h, path="/", method="GET", discovered_by="deep-pivot")
    except Exception:
        pass


def _notify_operator_pivot(hosts: list[str], source: str = "") -> None:
    """DANGER auto-pivots WITHOUT the normal-scan per-host approval — but the operator must still
    SEE it happening and be able to stop it. Raise ONE non-blocking wishlist FYI (deduped by the
    fixed need text, so it appears once no matter how many hosts stream in over the run) the first
    time the pivot opens. Fixes the 'no operator touchpoint in danger' gap without blocking the
    autonomous pivot. Fail-soft."""
    try:
        if not hosts:
            return
        from core.wishlist import wishlist_queue
        wishlist_queue.add(
            need=("Deep-pivot ACTIVE (depth=danger): auto-scanning internal host(s) discovered "
                  "behind the perimeter — review / de-scope"),
            category="scope",
            rationale=(f"depth=danger pivots autonomously (no per-host yes/no). Hosts reached via "
                       f"{source or 'the foothold'}; latest: {', '.join(hosts[:8])}"
                       f"{' …' if len(hosts) > 8 else ''}. To STOP pivoting a host, add it to "
                       "out_of_scope (it is then never re-promoted); the live host list is on the "
                       "dashboard network-assess panel."),
        )
    except Exception:
        pass


def request_pivot_scope(text: str, source: str = "") -> list[str]:
    """NORMAL scan: internal hosts were discovered but scanning them isn't auto-authorized.
    Raise a NON-BLOCKING wishlist ``scope`` item so the operator can approve pivoting (or
    re-run with depth=danger). Returns the hosts named; deduped by the wishlist. Fail-soft."""
    try:
        cur = scan_session.get()
        if not cur or scan_session.deep_pivot_enabled(cur):
            return []
        new = _new_internal_hosts(text, cur)
        if not new:
            return []
        from core.wishlist import wishlist_queue
        shown = ", ".join(new[:8]) + (f" (+{len(new) - 8} more)" if len(new) > 8 else "")
        wishlist_queue.add(
            need=f"Approve internal pivot-scanning of discovered host(s): {shown}",
            category="scope",
            rationale=(f"SSRF/RCE reached internal host(s) via {source or 'pivot'}. They sit behind "
                       "the perimeter (out of the declared scope); approve to pivot-scan them, or "
                       "re-run with depth=danger to pivot autonomously."),
        )
        return new
    except Exception:
        return []


def handle_internal_host_discovery(text: str, source: str = "") -> None:
    """Hook entrypoint (finding filing / HTTP responses): route internal-host discovery
    to promotion (deep-pivot) or a wishlist scope-ask (normal scan). Fail-soft."""
    try:
        cur = scan_session.get()
        if not cur:
            return
        if scan_session.deep_pivot_enabled(cur):
            promote_internal_hosts(text, source)
        else:
            request_pivot_scope(text, source)
    except Exception:
        pass
