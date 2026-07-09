"""Read APIs + finding mutation routes."""
from __future__ import annotations

import logging

from fastapi import Request
from fastapi.responses import JSONResponse

import core.api_server as _api

from ._common import router

_log = logging.getLogger(__name__)


# ── Read APIs ───────────────────────────────────────────────────────────────

@router.get("/api/findings")
async def api_findings() -> JSONResponse:
    data = _api._read_json(_api._FINDINGS_FILE)
    # Render diagram + exploit-chain SVGs server-side so the topology tab matches
    # the threat-model theme.
    for d in [*data.get("diagrams", []), *data.get("chains", [])]:
        if d.get("mermaid") and "svg" not in d:
            wrapped = f"```mermaid\n{d['mermaid']}\n```"
            svgs = _api._render_mermaid_svgs(wrapped)
            d["svg"] = svgs.get("0", "")
    return JSONResponse(data)


@router.get("/api/findings/{finding_id}")
async def api_finding(finding_id: str) -> JSONResponse:
    """One finding + any exploit chains that reference it — feeds the standalone
    /finding/<id> detail page. Chain mermaid is pre-rendered server-side (same as
    api_findings) so the dossier's kill-chain matches the topology theme. Falls
    back to the archived list so a deleted finding's URL still resolves."""
    data = _api._read_json(_api._FINDINGS_FILE)
    finding = next((f for f in data.get("findings", []) if f.get("id") == finding_id), None)
    archived = False
    if finding is None:
        finding = next((f for f in data.get("archived", []) if f.get("id") == finding_id), None)
        archived = finding is not None
    if finding is None:
        return JSONResponse({"error": "not found"}, status_code=404)

    related = []
    for c in data.get("chains", []):
        steps = c.get("steps", []) or []
        touches = any(
            s.get("from_finding_id") == finding_id or s.get("to_finding_id") == finding_id
            for s in steps
        )
        if not touches:
            continue
        if c.get("mermaid") and "svg" not in c:
            wrapped = f"```mermaid\n{c['mermaid']}\n```"
            svgs = _api._render_mermaid_svgs(wrapped)
            c = {**c, "svg": svgs.get("0", "")}
        related.append(c)

    return JSONResponse(
        {"finding": finding, "chains": related, "archived": archived, "meta": data.get("meta", {})}
    )


@router.get("/api/session")
async def api_session() -> JSONResponse:
    data = _api._read_json(_api._SESSION_FILE)
    # Self-heal the triage banner + expose the live pending count so the dashboard
    # can show progress (and a "stalled" warning if Smith goes idle mid-pass).
    if isinstance(data, dict) and data.get("triage_requested"):
        try:
            import time
            from core.findings import _load as _load_findings
            from core.adjunction import pending_findings
            from core import session as scan_session
            pending = pending_findings(_load_findings())
            data["pending_adjudication"] = len(pending)
            if not pending:
                # Every in-scope finding has a verdict — clear the flag so the
                # banner doesn't linger after Smith finishes the pass.
                scan_session.load_from_disk(force=True)
                scan_session.set_triage_requested(False)
                # Also acknowledge the steering directive itself. Clearing only
                # the session flag (above) hid the banner but left the directive
                # live in get_active(), so it kept replaying into Smith's spawn
                # prompt / status / recovery responses — driving an unwanted
                # adjudication pass on the next run. Ack it here, on completion,
                # so a finished triage leaves nothing behind.
                try:
                    from core.steering import steering_queue
                    steering_queue.cancel_by_trigger(
                        "TRIAGE_ADJUDICATION", "all findings adjudicated"
                    )
                except Exception:
                    pass
                data = _api._read_json(_api._SESSION_FILE)
            else:
                # Advance the stall clock on real progress, then expose how long
                # the pass has gone without recording a verdict. The dashboard
                # uses this (not just the MCP heartbeat) to flip the banner to a
                # "stalled" warning when Smith abandons the pass with findings
                # still awaiting a verdict — even if it stays busy elsewhere.
                scan_session.load_from_disk(force=True)
                scan_session.note_triage_progress(len(pending))
                data = _api._read_json(_api._SESSION_FILE)
                data["pending_adjudication"] = len(pending)
                progressed_at = (
                    data.get("triage_progress_at")
                    or data.get("triage_requested_at")
                )
                if progressed_at:
                    data["triage_idle_s"] = int(time.time() - progressed_at)
        except Exception:
            pass
    return JSONResponse(data)


@router.get("/api/cost")
async def api_cost() -> JSONResponse:
    return JSONResponse(_api._read_json(_api._COST_FILE))


@router.get("/api/coverage")
async def api_coverage() -> JSONResponse:
    return JSONResponse(_api._read_json(_api._COVERAGE_FILE))


@router.get("/api/graph")
async def api_graph() -> JSONResponse:
    """Phase 2: the knowledge-graph world-model for the dashboard's World Model
    tab — nodes/edges + graph-derived candidate chains, finding rankings, and
    value-ranked next targets. The dashboard is a separate process, so load the
    session from disk first (findings/matrix are already disk-backed)."""
    empty = {"stats": {"nodes": 0, "edges": 0, "by_kind": {}}, "nodes": [], "edges": [],
             "candidate_chains": [], "ranked_findings": [], "next_targets": []}
    try:
        from core import session as scan_session
        from core.graph import build_graph, candidate_chains, next_targets, rank_findings
        from core.graph import model as gm
        if scan_session.get() is None:
            scan_session.load_from_disk()
        g = build_graph()

        # Worklist semantics: "Proposed kill-chains" and "Deepen next" should DRAIN to
        # empty as work is proven — mirroring "next_targets", which empties when 0 cells
        # pend. Subtract chains already proven & filed via report(action='chain').
        proven = _proven_fids()
        cands = candidate_chains(g, proven)
        # "Deepen next" = findings still in UNPROVEN work: source of an open candidate
        # chain, or carrying a pending escalation lead. Everything worked → empty.
        open_fids = {fid for c in cands for fid in (c.get("finding_ids") or [])}
        open_fids |= {f.id.split(":", 1)[1] for f in g.of_kind(gm.FINDING)
                      if g.out_edges(f.id, gm.ESCALATES_TO)}
        ranked = [r for r in rank_findings(g) if r["finding_id"] in open_fids]

        # Serialize the graph for the World Model tab. CRITICAL: keep only edges whose BOTH
        # endpoints are real nodes BEFORE any cap. The matrix contributes 846 tested_for
        # edges that point at injection-type PSEUDO-nodes the graph never materializes — the
        # client drops them as dangling anyway, but if they're serialized first they eat the
        # edge budget and the meaningful found_on / reaches / provides / requires / leaks edges
        # (which come after) get truncated away — leaving findings, discovered hosts and
        # primitives floating disconnected. Filter, THEN cap.
        node_list = list(g.nodes.values())[:500]
        node_ids = {n.id for n in node_list}
        real_edges = [e for e in g.edges
                      if e.src in node_ids and e.dst in node_ids and e.src != e.dst][:2000]

        return JSONResponse({
            "stats": g.stats(),
            # Labeled-property-graph shape: each node/edge carries its full property bag
            # (attrs) so the dashboard can inspect it Neo4j-style. Flat src/dst/severity
            # kept for backward-compat with an older cached frontend.
            "nodes": [{"id": n.id, "kind": n.kind, "label": n.label,
                       "severity": n.attrs.get("severity", ""),
                       "properties": dict(n.attrs)} for n in node_list],
            "edges": [{"id": f"e{i}", "source": e.src, "target": e.dst,
                       "src": e.src, "dst": e.dst, "kind": e.kind,
                       "properties": dict(e.attrs)} for i, e in enumerate(real_edges)],
            "candidate_chains": cands[:10],
            "ranked_findings": ranked[:10],
            "next_targets": next_targets(g, limit=8),
        })
    except Exception:
        _log.exception("api_graph failed")
        return JSONResponse({**empty, "error": _api._ERR_REQUEST_FAILED})


# A finding whose TITLE already reads as a proven chain narrative (Smith sometimes files
# the chain as a finding instead of via report(action='chain')) — treat it as worked too.
_PROVEN_CHAIN_TITLE = ("proven chain", "exploit chain proven", "full exploit chain",
                       "chain proven")


def _proven_fids() -> set:
    """The flat set of finding-ids already worked into a proven chain — from the formal
    findings.json 'chains' (steps → from/to_finding_id) AND from findings whose own title
    reads as a proven chain. A candidate chain all of whose findings are in this set is
    already done and drops off the worklist panel."""
    out: set = set()
    try:
        data = _api._read_json(_api._FINDINGS_FILE)
        for ch in data.get("chains", []) or []:
            for s in ch.get("steps", []) or []:
                for k in ("from_finding_id", "to_finding_id"):
                    v = s.get(k)
                    if v and v != "auto":
                        out.add(v)
        for f in data.get("findings", []) or []:
            title = (f.get("title") or "").lower()
            if f.get("id") and any(mk in title for mk in _PROVEN_CHAIN_TITLE):
                out.add(f["id"])
    except Exception:
        pass
    return out


@router.get("/api/threat-model")
async def api_get_threat_model(file: str = "") -> JSONResponse:
    md_paths: list = []
    if _api._THREAT_MODEL_DIR.exists():
        # Sort by modification time (most recent first) so the active scan's
        # threat model appears as the default selection.
        md_paths = list(_api._THREAT_MODEL_DIR.glob("*.md"))
        md_paths.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    files = [p.name for p in md_paths]

    if not file and files:
        file = files[0]

    content = ""
    if file:
        if "/" in file or "\\" in file or ".." in file:
            return JSONResponse({"error": "invalid file"}, status_code=400)
        # Look up the Path from the trusted glob results — user-controlled `file`
        # is used only as a filter key, never directly in a path expression.
        safe_path = next((p for p in md_paths if p.name == file), None)
        if safe_path is not None:
            content = safe_path.read_text(encoding="utf-8")

    svgs = {}
    if content:
        svgs = _api._render_mermaid_svgs(content)

    return JSONResponse({"files": files, "file": file, "content": content, "svgs": svgs})


@router.patch("/api/findings/{finding_id}")
async def api_patch_finding(finding_id: str, request: Request) -> JSONResponse:
    from core.findings import update_finding
    try:
        body = await request.json()
        updated = await update_finding(
            finding_id,
            severity=body.get("severity"),
            title=body.get("title"),
            description=body.get("description"),
            evidence=body.get("evidence"),
            status=body.get("status"),
            gh_issue=body.get("gh_issue"),
            remediation=body.get("remediation"),
            reproduction=body.get("reproduction"),
            escalation_leads=body.get("escalation_leads"),
        )
        return JSONResponse({"ok": updated})
    except Exception:
        _log.exception("api_update_finding failed")
        return JSONResponse({"ok": False, "error": _api._ERR_REQUEST_FAILED}, status_code=400)


@router.delete("/api/findings/{finding_id}")
async def api_delete_finding(finding_id: str) -> JSONResponse:
    from core.findings import delete_finding
    try:
        archived = await delete_finding(finding_id)
        return JSONResponse({"ok": archived})
    except Exception:
        _log.exception("api_delete_finding failed")
        return JSONResponse({"ok": False, "error": _api._ERR_REQUEST_FAILED}, status_code=400)
