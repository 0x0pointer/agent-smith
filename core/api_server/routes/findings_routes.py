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
        if scan_session.get() is None:
            scan_session.load_from_disk()
        g = build_graph()
        return JSONResponse({
            "stats": g.stats(),
            "nodes": [{"id": n.id, "kind": n.kind, "label": n.label,
                       "severity": n.attrs.get("severity", "")} for n in list(g.nodes.values())[:400]],
            "edges": [{"src": e.src, "dst": e.dst, "kind": e.kind} for e in g.edges[:800]],
            "candidate_chains": candidate_chains(g)[:10],
            "ranked_findings": rank_findings(g)[:10],
            "next_targets": next_targets(g, limit=8),
        })
    except Exception as exc:
        _log.debug("api_graph failed: %s", exc)
        return JSONResponse({**empty, "error": str(exc)})


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
