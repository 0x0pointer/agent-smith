"""Graph-derived attack-chain proposals (Phase 2 / AR-B3).

The highest-value pentest output — the kill chain — is today 100% model-declared:
nothing PROPOSES which finding feeds which. This traverses the world-model graph
to surface candidate chains for the model to prove and file (the artifact-backed
`report(action='chain')` validation stays the gate — we only propose, never
assert). Pure: reads a Graph, returns proposals.
"""
from __future__ import annotations

from . import model as m

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "": 0}


def _sev(node: m.Node) -> int:
    return _SEV_RANK.get(node.attrs.get("severity", ""), 0)


def _host(g: m.Graph, fid: str) -> str | None:
    es = g.out_edges(fid, m.FOUND_ON)
    return es[0].dst if es else None


def _chains_from_escalation_leads(g: m.Graph, findings: list) -> list[dict]:
    """(1) A finding with a pending escalation lead → prove the lead to its terminal."""
    props: list[dict] = []
    for f in findings:
        for e in g.out_edges(f.id, m.ESCALATES_TO):
            lead = e.attrs.get("lead", "")
            if lead:
                props.append({
                    "steps": [f.label, lead],
                    "terminal": lead,
                    "combined_severity": f.attrs.get("severity", "medium"),
                    "rationale": f"'{f.label}' has an unproven escalation lead — follow it to terminal impact.",
                    "_score": _sev(f) + 1,
                })
    return props


def _chains_from_cred_leaks(g: m.Graph, findings: list) -> list[dict]:
    """(2) A credential/secret-leak finding + another finding on the SAME host →
    'leak creds, authenticate, then reach the second bug' — a chain a model rarely
    self-assembles."""
    props: list[dict] = []
    leakers = [f for f in findings if g.out_edges(f.id, m.LEAKS)]
    for lk in leakers:
        h = _host(g, lk.id)
        if not h:
            continue
        for other in findings:
            if other.id == lk.id or _host(g, other.id) != h:
                continue
            props.append({
                "steps": [lk.label, "authenticate with the leaked credentials/token", other.label],
                "terminal": other.label,
                "combined_severity": max((lk.attrs.get("severity", "medium"),
                                          other.attrs.get("severity", "medium")),
                                         key=lambda s: _SEV_RANK.get(s, 0)),
                "rationale": f"'{lk.label}' leaks credential material on the same host as "
                             f"'{other.label}' — chain the leak into authenticated access.",
                "_score": _sev(lk) + _sev(other),
            })
    return props


def _chains_from_creds_plus_finding(g: m.Graph, findings: list) -> list[dict]:
    """(3) A confirmed high-sev finding + a known credential/token on the host →
    chain toward account takeover / lateral movement."""
    creds = g.of_kind(m.CREDENTIAL) + g.of_kind(m.TOKEN)
    if not creds:
        return []
    props: list[dict] = []
    for f in findings:
        if _sev(f) >= 3 and g.out_edges(f.id, m.FOUND_ON):
            props.append({
                "steps": [f.label, f"reuse a known principal ({creds[0].label}) to widen impact"],
                "terminal": "privilege escalation / lateral movement",
                "combined_severity": f.attrs.get("severity", "high"),
                "rationale": f"'{f.label}' is high-severity and {len(creds)} principal(s) are "
                             "known — test cross-account/lateral reach.",
                "_score": _sev(f),
            })
    return props


def _chains_from_primitive_bridge(g: m.Graph) -> list[dict]:
    """(4) Finding B PROVIDES the primitive Finding A is BLOCKED on (REQUIRES) →
    'use B's <primitive> to unblock A'. THE compositional bridge the model never
    self-assembles (Postgres SQLi file-read → Werkzeug console PIN → RCE).

    Expressed as the two-hop pattern (provider)-[:PROVIDES]->(primitive)<-[:REQUIRES]-
    (blocked) over the existing paths.match_chain matcher. SAME-HOST guarded (mirrors
    rule 2) so a provider on host X can't 'unblock' a finding on host Y — the free
    _host helper kills that combinatorial cross-host spam. Capped to keep a common
    primitive (file_read) from flooding the proposal list."""
    from . import paths
    pattern = [
        paths.NodeM(m.FINDING, var="provider"),
        paths.Rel(m.PROVIDES),
        paths.NodeM(m.PRIMITIVE, var="prim"),
        paths.Rel(m.REQUIRES, direction="in"),
        paths.NodeM(m.FINDING, var="blocked"),
    ]
    props: list[dict] = []
    seen: set[tuple] = set()
    for match in paths.match_chain(g, pattern):
        provider, blocked, primn = (match.vars.get("provider"),
                                    match.vars.get("blocked"), match.vars.get("prim"))
        if not (provider and blocked and primn) or provider.id == blocked.id:
            continue  # a bug can't unblock itself
        ph, bh = _host(g, provider.id), _host(g, blocked.id)
        if ph and bh and ph != bh:
            continue  # cross-host bridge is physically impossible — drop it
        key = (provider.id, primn.label, blocked.id)
        if key in seen:
            continue
        seen.add(key)
        props.append({
            "steps": [provider.label,
                      f"use its {primn.label} primitive to unblock the next step",
                      blocked.label],
            "terminal": blocked.label,
            "combined_severity": max((provider.attrs.get("severity", "medium"),
                                      blocked.attrs.get("severity", "medium")),
                                     key=lambda s: _SEV_RANK.get(s, 0)),
            "rationale": f"'{provider.label}' PROVIDES {primn.label}, which "
                         f"'{blocked.label}' is blocked needing — bridge them.",
            "kind": "primitive_unblock",
            "provider_id": provider.id.replace("finding:", "", 1),
            "blocked_id": blocked.id.replace("finding:", "", 1),
            "primitive": primn.label,
            "_score": _sev(provider) + _sev(blocked) + 2,  # +2: an exact-primitive match beats co-location noise
        })
    props.sort(key=lambda p: p["_score"], reverse=True)
    return props[:20]  # cap the rule's own output


def candidate_chains(g: m.Graph) -> list[dict]:
    """Propose multi-step chains from the graph. Each proposal:
    ``{steps: [str], terminal: str, combined_severity: str, rationale: str}``.
    Ranked most-promising first. Heuristic and conservative — a proposal is a
    lead to prove, not a claim."""
    findings = g.of_kind(m.FINDING)
    props = (_chains_from_escalation_leads(g, findings)
             + _chains_from_cred_leaks(g, findings)
             + _chains_from_creds_plus_finding(g, findings)
             + _chains_from_primitive_bridge(g))

    props.sort(key=lambda p: p.pop("_score", 0), reverse=True)
    # de-dup identical step sequences
    seen, out = set(), []
    for p in props:
        key = tuple(p["steps"])
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out
