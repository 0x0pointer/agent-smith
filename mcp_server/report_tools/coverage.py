"""
Coverage matrix actions: endpoint registration, cell updates, dispatch.
"""
import json
from typing import Any

from ._common import log, scan_session
from .coverage_extra import (
    _autofile_crosscutting_findings,
    _do_coverage_auto_crosscutting,
    _do_coverage_next_batch,
    _do_coverage_list,
)


def _coerce_endpoint_params(raw_params: Any) -> list[dict]:
    """Coerce params from various model formats to a clean list of dicts."""
    if isinstance(raw_params, str):
        try:
            raw_params = json.loads(raw_params)
        except json.JSONDecodeError:
            raw_params = []
    if not isinstance(raw_params, list):
        return []
    clean: list[dict] = []
    for p in raw_params:
        if isinstance(p, str):
            clean.append({"name": p, "type": "query", "value_hint": "string"})
        elif isinstance(p, dict):
            clean.append({
                "name": p.get("name", p.get("param", "")),
                "type": p.get("type", p.get("param_type", "query")),
                "value_hint": p.get("value_hint", p.get("hint", "string")),
            })
    return clean


def _infer_coverage_type(data: dict) -> str:
    """Auto-detect coverage type from data shape when not explicitly provided."""
    if "path" in data:
        return "endpoint"
    if "cell_id" in data:
        return "tested"
    if "updates" in data:
        return "bulk_tested"
    return ""


async def _do_coverage_endpoint(data: dict, cov: Any) -> str:
    """Handle coverage type='endpoint': register an endpoint in the matrix."""
    path = data.get("path", "")
    if not path:
        return (
            "Error: 'path' is required for endpoint registration. "
            "Example: report(action='coverage', data={type:'endpoint', path:'/login', "
            "method:'GET', params:[{name:'q', type:'query', value_hint:'string'}]})"
        )
    clean_params = _coerce_endpoint_params(data.get("params", []))
    result = await cov.add_endpoint(
        path=path,
        method=data.get("method", "GET"),
        params=clean_params,
        discovered_by=data.get("discovered_by", "spider"),
        auth_context=data.get("auth_context", "none"),
    )
    if result["dedup"]:
        return f"Endpoint already registered (dedup): {path} {data.get('method', 'GET')}"
    await _emit_coverage_event()
    return (
        f"Endpoint registered: {data.get('method', 'GET')} {path} — "
        f"{result['new_cells']} test cells auto-generated"
    )


async def _do_coverage_tested(data: dict, cov: Any) -> str:
    """Handle coverage type='tested': mark a single cell as tested."""
    result = await cov.update_cell(
        cell_id=data.get("cell_id", ""),
        status=data.get("status", ""),
        notes=data.get("notes", ""),
        finding_id=data.get("finding_id"),
        tested_by=data.get("tested_by", ""),
        artifact_id=data.get("artifact_id", ""),
    )
    if result is False:
        # Common after context compaction: Smith carried the cell ID across a
        # turn boundary, the matrix on disk still has the cell, but the
        # in-context ID was lost OR Smith reconstructed it incorrectly. Point
        # at the recovery primitive instead of leaving Smith to guess (or
        # worse, re-register endpoints, which produces duplicate cells).
        return (
            f"Cell not found: {data.get('cell_id')}. "
            "If your context was recently compacted, fetch the current matrix "
            "via report(action='coverage', type='list') — optionally filter by "
            "endpoint_path, method, param_name, or injection_type to narrow "
            "the response. DO NOT re-register endpoints; the cells are still "
            "on disk."
        )
    if isinstance(result, str):
        return result  # passes through REJECTED messages directly
    return f"Cell updated: {data.get('cell_id')}"


async def _do_coverage_bulk(data: dict, cov: Any) -> str:
    """Handle coverage type='bulk_tested': update multiple cells at once."""
    result = await cov.bulk_update(data.get("updates", []))
    await _emit_coverage_event()
    msg = f"Bulk update: {result['updated']} cell(s) updated"
    if result["warnings"]:
        msg += f"\n\nINTEGRITY WARNINGS ({len(result['warnings'])}):\n"
        msg += "\n".join(f"  - {w}" for w in result["warnings"])
    return msg


async def _do_coverage_reset(cov: Any) -> str:
    """Handle coverage type='reset': clear the matrix (blocked during active scan)."""
    current = scan_session.get()
    if current and current.get("status") in ("running", "intervention_required"):
        log.note("coverage reset BLOCKED — scan is active. Do NOT reset the matrix mid-scan.")
        return (
            "BLOCKED: Cannot reset coverage matrix while a scan is active. "
            "The matrix tracks your testing progress — resetting it mid-scan destroys that state. "
            "If you need to re-register endpoints, just call coverage(type='endpoint') again — "
            "duplicates are automatically ignored."
        )
    await cov.reset()
    return "Coverage matrix reset."


async def _do_coverage_sweep(data, cov):
    """SM-5/SM-10: server-side probe → evaluate → auto-close-clean / flag-candidates
    for pending INJECTION cells (ssti/xss/cmdi/traversal/sqli), so the model
    doesn't hand-run every probe and thread every artifact_id — the mechanical
    bookkeeping small models drop. Auto-closes ONLY confident-clean cells
    (artifact-backed); oracle POSITIVES are returned as CANDIDATES for the model
    to confirm + file (never auto-filed — respects the finding_id gate). Opt-in,
    bounded, fail-soft."""
    import json as _json
    from core.coverage import sweep as _sweep
    from core.prompt_fence import fence as _fence
    from mcp_server.http_tools import http_probe
    from mcp_server.scan_engine import planner as _planner
    from mcp_server.scan_engine.envelope import store_artifact

    target = (scan_session.get() or {}).get("target", "")
    if not target:
        return "Sweep needs a running scan with a target."

    max_cells = max(1, min(int(data.get("max_cells", 25) or 25), 60))
    ep_filter = data.get("endpoint_id")

    m = cov.get_matrix()
    eps = {e["id"]: e for e in m.get("endpoints", [])}
    cells = [c for c in m.get("matrix", [])
             if c.get("status") == "pending"
             and c.get("injection_type") in _sweep.SWEEPABLE
             and (not ep_filter or c.get("endpoint_id") == ep_filter)][:max_cells]
    if not cells:
        return ("Sweep: no pending server-side-sweepable injection cells "
                "(ssti/xss/cmdi/traversal/sqli). Other types need OOB/diffing/judgment — test those manually.")

    closures: list[dict] = []
    candidates: list[dict] = []
    blocked = inconclusive = 0

    for c in cells:
        ep = eps.get(c["endpoint_id"], {})
        probe = _planner.build_probe(
            c["injection_type"], target, ep.get("path", ""), ep.get("method", "GET"),
            c.get("param", ""), c.get("param_type", "query"))
        if not probe:
            inconclusive += 1
            continue
        try:
            if probe["kind"] == "http":
                resp = await http_probe(probe["url"], probe["method"])
                status, body = resp.get("status", 0), resp.get("body", "")
                content = _json.dumps(resp)[:20_000]
            else:  # kali — sqlmap runs its own oracle
                from tools import kali_runner
                body = await kali_runner.exec_command(probe["cmd"])
                status, content = 0, body[:20_000]
        except Exception as exc:  # fail-soft — one dead probe never aborts the sweep
            inconclusive += 1
            log.note(f"sweep probe error on cell {c['id']}: {exc}")
            continue

        artifact_id = store_artifact("sweep", content)
        v = _sweep.evaluate_probe(c["injection_type"], probe.get("payload", ""), status, body)
        if v["verdict"] == "clean":
            closures.append({"cell_id": c["id"], "status": "tested_clean",
                             "artifact_id": artifact_id, "notes": f"sweep: {v['basis']}"})
        elif v["verdict"] == "candidate":
            candidates.append({"cell_id": c["id"], "injection": c["injection_type"],
                               "endpoint": ep.get("path", ""), "param": c.get("param", ""),
                               "artifact_id": artifact_id, "basis": v["basis"]})
        elif v["verdict"] == "blocked":
            blocked += 1
        else:
            inconclusive += 1

    applied = await cov.bulk_update(closures) if closures else {"updated": 0}

    lines = [
        f"🧹 SWEEP: probed {len(cells)} pending cell(s) — "
        f"{applied.get('updated', 0)} auto-closed tested_clean, {len(candidates)} candidate(s), "
        f"{blocked} auth-blocked, {inconclusive} inconclusive."
    ]
    if blocked:
        lines.append("Auth-blocked cells stayed pending — re-run the sweep once authenticated.")
    if candidates:
        lines.append("\nCANDIDATES — confirm each, file a finding, then close the cell vulnerable "
                     "with the linked artifact_id:")
        for cand in candidates:
            lines.append(
                f"  • cell {cand['cell_id']} [{cand['injection']}] on {_fence(cand['endpoint'])} "
                f"param {_fence(cand['param'])} — {cand['basis']} (artifact_id={cand['artifact_id']}). "
                f"report(action='finding', …) then report(action='coverage', data={{type:'tested', "
                f"cell_id:'{cand['cell_id']}', status:'vulnerable', finding_id:'<id>', artifact_id:'{cand['artifact_id']}'}})"
            )
    else:
        lines.append("No exploitable candidates surfaced by the sweep on these cells.")
    return "\n".join(lines)


async def _do_coverage(data):
    from core import coverage as cov

    cov_type = data.get("type", "")
    log.note(f"coverage({cov_type}): {json.dumps(data)[:300]}")

    if not cov_type:
        cov_type = _infer_coverage_type(data)

    if cov_type == "endpoint":
        return await _do_coverage_endpoint(data, cov)
    if cov_type == "tested":
        return await _do_coverage_tested(data, cov)
    if cov_type == "bulk_tested":
        return await _do_coverage_bulk(data, cov)
    if cov_type == "reset":
        return await _do_coverage_reset(cov)
    if cov_type == "list":
        return await _do_coverage_list(data, cov)
    if cov_type == "next_batch":
        return await _do_coverage_next_batch(data, cov)
    if cov_type == "sweep":
        return await _do_coverage_sweep(data, cov)
    if cov_type == "auto_crosscutting":
        return await _do_coverage_auto_crosscutting(data, cov)
    return (
        f"Unknown coverage type '{cov_type}'. Use: endpoint, tested, bulk_tested, list, next_batch, "
        f"sweep, auto_crosscutting, reset. "
        f"Example: report(action='coverage', data={{type:'endpoint', path:'/login', method:'GET', "
        f"params:[{{name:'user', type:'query', value_hint:'string'}}]}})"
    )


async def _emit_coverage_event() -> None:
    """Append a COVERAGE entry to quick_log with current matrix totals."""
    try:
        from core.quick_log import quick_log as _qlog
        from core import coverage as _cov
        matrix    = _cov.get_matrix()
        meta      = matrix.get("meta", {})
        all_cells = matrix.get("matrix", [])
        # "Unevidenced" = closed without an artifact_id (the write-enforced proof
        # a tool ran) AND without legacy tested_by. Keying these counts on
        # artifact_id keeps the QA completion gates satisfiable: a cell closed
        # with a real artifact but empty tested_by is evidenced, not orphaned.
        from core.coverage import cell_has_test_evidence
        await _qlog.append({
            "type":           "COVERAGE",
            "registered":     len(matrix.get("endpoints", [])),
            "pending":        sum(1 for c in all_cells if c["status"] == "pending"),
            "tested":         meta.get("tested", 0),
            "vulnerable":     meta.get("vulnerable", 0),
            "not_applicable": sum(1 for c in all_cells if c["status"] == "not_applicable"),
            "skipped":        sum(1 for c in all_cells if c["status"] == "skipped"),
            "na_untooled":    sum(1 for c in all_cells
                                  if c["status"] == "not_applicable"
                                  and not cell_has_test_evidence(c)),
            "untooled":       sum(1 for c in all_cells
                                  if c["status"] in ("tested_clean", "vulnerable")
                                  and not cell_has_test_evidence(c)),
        })
    except Exception:
        pass
