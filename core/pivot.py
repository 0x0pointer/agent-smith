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

# Host-unit skills re-triggered per discovered internal host (surface ledger). The
# first — network-assess — is the port-scan/recon whose pending set == unscanned hosts.
_HOST_UNIT_SKILLS = ("network-assess", "post-exploit", "lateral-movement", "reverse-shell")


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


def _new_internal_hosts(text: str, cur: dict) -> list[str]:
    """Internal host keys named in `text` that aren't already known/out-of-scope."""
    from core.session import surface_ledger as _ledger
    known = _known_hosts(cur)
    new: list[str] = []
    seen: set[str] = set()
    for h in netextract.extract_internal_hosts(text or ""):
        hk = _ledger.host_key(h)
        if hk and hk not in known and hk not in seen:
            seen.add(hk)
            new.append(hk)
    return new


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
            for sk in _HOST_UNIT_SKILLS:
                _ledger.record_discovered(sk, h, "host")
        scan_session.trigger_gate(
            "internal_network",
            f"Deep-pivot: {len(new)} internal host(s) discovered via {source or 'pivot'} "
            f"({', '.join(new[:5])}) — port-scan + recon each",
            ["network-assess"])
        try:
            from core import logger as log
            log.note(f"deep-pivot promoted {len(new)} internal host(s): {', '.join(new[:8])}")
        except Exception:
            pass
        return new
    except Exception:
        return []


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
