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

# Scheme for the OOB blind-SSRF payload URL. Collaborators (interactsh / the HTTP
# logger) listen on plain HTTP, and this is an SSRF *payload* we want the target to
# fetch — not a client connection of ours to protect — so HTTPS is inapplicable
# here. Kept as a constant so the payload isn't a bare "http://" literal (S5332).
_OOB_PAYLOAD_SCHEME = "http"


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


async def _do_coverage_import(cov_type: str, data):
    """SM-4/SP-3: register EVERY operation of an OpenAPI/Swagger spec (or every
    GraphQL introspected field arg) as coverage cells in ONE call, so the model
    doesn't hand-transcribe a 50-op spec into 50 registrations. Auth is pulled
    from known_assets so an auth-gated schema is fetched under the session."""
    url = (data.get("url") or data.get("spec_url") or "").strip()
    if not url:
        return f"{cov_type} needs a 'url' (the spec URL for import_openapi, the /graphql endpoint for import_graphql)."
    from mcp_server.scan_engine import discovery
    # reuse the spider's auth-assembly so an auth-gated schema is reachable
    from mcp_server.scan_tools.spider import _spider_discovery_auth
    auth = _spider_discovery_auth(None)
    fn = discovery.import_openapi if cov_type == "import_openapi" else discovery.import_graphql
    res = await fn(url, auth=auth)
    if res.get("error"):
        return f"{cov_type} from {url}: {res['error']}"
    extra = res.get("operations") or res.get("fields_args") or 0
    return (f"📥 {cov_type}: registered {res.get('registered', 0)} endpoint(s) / "
            f"{res.get('cells', 0)} coverage cell(s) from {extra} operation(s) at {url}. "
            "The matrix is your test plan — move to per-cell testing (or report(coverage type='sweep')).")


async def _fire_oob_ssrf_probes(target, eps, ssrf_cells, base, mode) -> list:
    """Mint a unique OOB callback per ssrf cell, embed it in the param, fire the
    probe. Returns [(cell, correlation_id)] for the poll pass."""
    import json as _json
    import uuid
    from datetime import datetime, timezone

    from core import oob as _oob
    from core.session import assets as _sess_assets
    from mcp_server.http_tools import http_probe
    from mcp_server.scan_engine.artifacts import store_artifact
    from mcp_server.scan_engine.planner import _resolve_url

    fired = []  # (cell, correlation_id)
    for c in ssrf_cells:
        ep = eps.get(c["endpoint_id"], {})
        cid = uuid.uuid4().hex[:12]
        callback = (_oob.mint_http_callback(base, cid) if mode == "http"
                    else _oob.mint_subdomain(base, cid))
        _sess_assets.update_known_assets("oob_interactions", [{
            "subdomain": callback, "correlation_id": cid, "linked_cell_id": c["id"],
            "minted_at": datetime.now(timezone.utc).isoformat(), "polled": False, "hits": 0}])
        url = _resolve_url(target, ep.get("path", ""), c.get("param", ""),
                           c.get("param_type", "query"), f"{_OOB_PAYLOAD_SCHEME}://{callback}/")
        try:
            resp = await http_probe(url, ep.get("method", "GET"))
            store_artifact("sweep_oob", _json.dumps(resp)[:8000])
        except Exception:
            pass
        fired.append((c, cid))
    return fired


async def _poll_oob_ssrf_callbacks(fired, listener, mode, eps, candidates) -> tuple[int, int]:
    """Best-effort poll of each fired probe's collaborator (callbacks lag). A hit
    appends an ssrf CANDIDATE (artifact-backed). Returns (confirmed, pending)."""
    import json as _json
    from core import oob as _oob
    from core.session import assets as _sess_assets
    from mcp_server.scan_engine.artifacts import store_artifact
    from tools import kali_runner

    confirmed = pending = 0
    for c, cid in fired:
        try:
            if mode == "http":
                purl = _oob.http_poll_url(listener.get("poll_url", ""), cid)
                raw = await kali_runner.exec_command(_oob.build_http_poll_command(purl), timeout=20) if purl else ""
                hits = _oob.parse_http_hits(raw, cid) if raw else []
            else:
                raw = await kali_runner.exec_command(
                    _oob.build_poll_command(listener.get("out_file", _oob.OOB_OUT_FILE)), timeout=20)
                hits = _oob.parse_interactions(raw, cid)
        except Exception:
            hits = []
        _sess_assets.mark_oob_polled(cid, len(hits))
        if hits:
            aid = store_artifact("oob_interaction", _json.dumps(hits, indent=2))
            ep = eps.get(c["endpoint_id"], {})
            candidates.append({"cell_id": c["id"], "injection": "ssrf",
                               "endpoint": ep.get("path", ""), "param": c.get("param", ""),
                               "artifact_id": aid,
                               "basis": "OOB callback received — blind SSRF CONFIRMED"})
            confirmed += 1
        else:
            pending += 1
    return confirmed, pending


async def _sweep_oob_ssrf(target, matrix, eps, ep_filter, max_cells, candidates) -> str:
    """CH-9: fire OOB-bearing blind-SSRF probes at pending ssrf cells and confirm
    via collaborator callback. No-op (returns '') when no OOB listener is active.
    Best-effort poll; confirmed → candidate, un-confirmed → surfaced to re-poll."""
    from core.session import assets as _sess_assets

    listener = _sess_assets.get_oob_listener()
    if not listener:
        return ""
    base, mode = listener.get("base_domain", ""), listener.get("mode", "interactsh")
    if not base:
        return ""
    ssrf_cells = [c for c in matrix.get("matrix", [])
                  if c.get("status") == "pending" and c.get("injection_type") == "ssrf"
                  and (not ep_filter or c.get("endpoint_id") == ep_filter)][:max_cells]
    if not ssrf_cells:
        return ""

    fired = await _fire_oob_ssrf_probes(target, eps, ssrf_cells, base, mode)
    confirmed, pending = await _poll_oob_ssrf_callbacks(fired, listener, mode, eps, candidates)

    note = f"OOB blind-SSRF: fired {len(fired)} probe(s), {confirmed} confirmed via callback"
    if pending:
        note += (f", {pending} awaiting a callback (they lag — re-run the sweep or "
                 "session(action='oob_poll') to re-check; no callback = not reaching an SSRF sink)")
    return note + "."


def _sweep_auth_headers() -> dict:
    """Auth material to RETRY a probe with when it hits 401/403 — the freshest captured
    JWT (``Authorization: Bearer``) and/or session cookies from known_assets. Empty when
    the scan holds no auth (an unauthenticated run stays unauthenticated)."""
    headers: dict = {}
    try:
        from core import session as scan_session
        ka = (scan_session.get() or {}).get("known_assets") or {}
        toks = ka.get("auth_tokens") or []
        if toks and isinstance(toks[-1], dict) and toks[-1].get("value"):
            headers["Authorization"] = f"Bearer {toks[-1]['value']}"
        pairs = [f"{c['name']}={c.get('value', '')}"
                 for c in (ka.get("session_cookies") or [])
                 if isinstance(c, dict) and c.get("name")]
        if pairs:
            headers["Cookie"] = "; ".join(pairs)
    except Exception:
        pass
    return headers


def _sqlmap_auth_blocked(body: str) -> bool:
    """True when sqlmap's own output shows it never got past auth (HTTP 401/403), so a
    'not injectable' verdict is a false negative — the payload never reached the DB
    layer. Specific to sqlmap's HTTP-error reporting to avoid false 'inconclusive'."""
    b = (body or "").lower()
    return any(s in b for s in (
        "error code (401)", "error code (403)",
        "401 (unauthorized)", "403 (forbidden)",
    ))


async def _run_sweep_probe(c, ep, target):
    """Build + run the probe for one cell, store the artifact, evaluate it.
    Returns (artifact_id, verdict_dict) — or None when the probe couldn't run
    (no probe built / execution error), which the caller counts as inconclusive."""
    import json as _json
    from core.coverage import sweep as _sweep
    from mcp_server.http_tools import http_probe
    from mcp_server.scan_engine import planner as _planner
    from mcp_server.scan_engine.envelope import store_artifact

    probe = _planner.build_probe(
        c["injection_type"], target, ep.get("path", ""), ep.get("method", "GET"),
        c.get("param", ""), c.get("param_type", "query"))
    if not probe:
        return None
    try:
        if probe["kind"] == "http":
            base = probe.get("headers") or {}
            resp = await http_probe(probe["url"], probe["method"], headers=base or None)
            # Self-heal auth: a 401/403 means auth blocked the payload before it reached
            # the code path under test — so RETRY once with the session's captured auth
            # (Bearer token and/or session cookies from known_assets), testing the cell
            # UNDER auth instead of recording a permanent auth-block. The sweep adds auth
            # itself when it sees the gate, rather than leaving hundreds of cells stuck.
            if resp.get("status") in (401, 403):
                auth = _sweep_auth_headers()
                if auth:
                    healed = await http_probe(probe["url"], probe["method"], headers={**base, **auth})
                    if healed.get("status") not in (401, 403):
                        resp = healed
            status, body = resp.get("status", 0), resp.get("body", "")
            content = _json.dumps(resp)[:20_000]
        else:  # kali — sqlmap runs its own oracle
            from tools import kali_runner
            import shlex as _shlex
            cmd = probe["cmd"]
            # Thread session auth into sqlmap so it tests UNDER auth. Otherwise it hits
            # 401/403, reports "not injectable", and the sweep records a FALSE
            # tested_clean — the kali branch sets status=0, which bypasses the 401/403
            # rejection guard that protects the http branch. Mirrors the http self-heal.
            auth = _sweep_auth_headers()
            if auth.get("Authorization"):
                cmd += f" --header={_shlex.quote('Authorization: ' + auth['Authorization'])}"
            if auth.get("Cookie"):
                cmd += f" --cookie={_shlex.quote(auth['Cookie'])}"
            # Bound the sub-probe: one sqlmap cell must not burn the default 600s and
            # stall the whole sweep (the model then hand-calls sweep in a loop).
            body = await kali_runner.exec_command(cmd, timeout=90)
            status, content = 0, body[:20_000]
            # Never let an auth-blocked sqlmap run masquerade as tested_clean: if the
            # output shows it never got past auth, it's inconclusive, not clean.
            if _sqlmap_auth_blocked(body):
                log.note(f"sweep: sqlmap on cell {c['id']} appears auth-blocked — inconclusive, not clean")
                return None
    except Exception as exc:  # fail-soft — one dead probe never aborts the sweep
        log.note(f"sweep probe error on cell {c['id']}: {exc}")
        return None

    artifact_id = store_artifact("sweep", content)
    v = _sweep.evaluate_probe(c["injection_type"], probe.get("payload", ""), status, body)
    return artifact_id, v


def _format_sweep_report(cells, applied, candidates, blocked, inconclusive, oob_note) -> str:
    """Render the operator-facing sweep summary + the CANDIDATES to confirm."""
    from core.prompt_fence import fence as _fence
    lines = [
        f"🧹 SWEEP: probed {len(cells)} pending cell(s) — "
        f"{applied.get('updated', 0)} auto-closed tested_clean, {len(candidates)} candidate(s), "
        f"{blocked} auth-blocked, {inconclusive} inconclusive."
    ]
    if oob_note:
        lines.append(oob_note)
    if blocked:
        lines.append("Auth-blocked cells stayed pending — re-run the sweep once authenticated.")
    if not candidates:
        lines.append("No exploitable candidates surfaced by the sweep on these cells.")
        return "\n".join(lines)
    lines.append("\nCANDIDATES — confirm each, file a finding, then close the cell vulnerable "
                 "with the linked artifact_id:")
    for cand in candidates:
        lines.append(
            f"  • cell {cand['cell_id']} [{cand['injection']}] on {_fence(cand['endpoint'])} "
            f"param {_fence(cand['param'])} — {cand['basis']} (artifact_id={cand['artifact_id']}). "
            f"report(action='finding', …) then report(action='coverage', data={{type:'tested', "
            f"cell_id:'{cand['cell_id']}', status:'vulnerable', finding_id:'<id>', artifact_id:'{cand['artifact_id']}'}})"
        )
    return "\n".join(lines)


async def _do_coverage_sweep(data, cov):
    """SM-5/SM-10: server-side probe → evaluate → auto-close-clean / flag-candidates
    for pending INJECTION cells (ssti/xss/cmdi/traversal/sqli), so the model
    doesn't hand-run every probe and thread every artifact_id — the mechanical
    bookkeeping small models drop. Auto-closes ONLY confident-clean cells
    (artifact-backed); oracle POSITIVES are returned as CANDIDATES for the model
    to confirm + file (never auto-filed — respects the finding_id gate). Opt-in,
    bounded, fail-soft."""
    from core.coverage import sweep as _sweep

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
        outcome = await _run_sweep_probe(c, ep, target)
        if outcome is None:
            inconclusive += 1
            continue
        artifact_id, v = outcome
        verdict = v["verdict"]
        if verdict == "clean":
            closures.append({"cell_id": c["id"], "status": "tested_clean",
                             "artifact_id": artifact_id, "notes": f"sweep: {v['basis']}"})
        elif verdict == "candidate":
            candidates.append({"cell_id": c["id"], "injection": c["injection_type"],
                               "endpoint": ep.get("path", ""), "param": c.get("param", ""),
                               "artifact_id": artifact_id, "basis": v["basis"]})
        elif verdict == "blocked":
            blocked += 1
        else:
            inconclusive += 1

    applied = await cov.bulk_update(closures) if closures else {"updated": 0}

    # CH-9: blind SSRF via OOB. When a collaborator is active, fire OOB-bearing
    # payloads at pending ssrf cells (which the in-band oracle can't see) and
    # confirm via callback — automating the mint→embed→fire→poll chain the model
    # otherwise hand-runs and drops. Fail-soft; appends OOB candidates + a note.
    oob_note = await _sweep_oob_ssrf(target, m, eps, ep_filter, max_cells, candidates)

    return _format_sweep_report(cells, applied, candidates, blocked, inconclusive, oob_note)


def _phase_a_deepwork_redirect(cov_type: str) -> str:
    """Phase A refuses a DRAIN op (sweep / bulk_tested / next_batch / auto_crosscutting) and
    points the model BACK to the specific deep work it still owes — un-pursued high findings,
    un-run applicable skills, unattempted exploit bridges — instead of letting it escape to
    breadth. The refusal is what keeps Phase A alive (the deep, hours-long phase the lean early
    runs did); naming the remaining work is what keeps it productive. Fail-soft: if findings /
    session can't be read, falls back to the generic deep-work nudge."""
    lines: list[str] = []
    try:
        from core import findings as _findings
        from core import session as _sess
        from core.session import phases as _phases
        data = _findings._load()
        sess = _sess.get() or {}
        chain_fids = _phases._chain_fids(data)
        unpursued = [f for f in data.get("findings", [])
                     if f.get("severity") in ("high", "critical")
                     and f.get("status", "confirmed") != "false_positive"
                     and not _phases._pursued(f, chain_fids)]
        if unpursued:
            from core.prompt_fence import fence as _fence
            sample = "; ".join(_fence(f.get("title", "")) for f in unpursued[:5])
            more = f" (+{len(unpursued) - 5} more)" if len(unpursued) > 5 else ""
            lines.append(
                f"  • {len(unpursued)} high/critical finding(s) NOT yet driven to a terminal: "
                f"{sample}{more}. Chain each onward (report(action='chain', ...)); if one truly "
                "dead-ends, dismiss its escalation_lead with a rationale.")
        worked = _phases._worked_skills(sess)
        owed = sorted({s for g in (sess.get("gates", []) or [])
                       if g.get("status") != "satisfied"
                       for s in (set(g.get("required_skills", []) or []) - worked)})
        if owed:
            lines.append(
                f"  • Applicable skill(s) not yet run: {', '.join('/' + s for s in owed)} — "
                "set_skill + invoke each; they are DEPTH work and Phase A won't advance until they have.")
        bridges = _phases.open_bridges(data)
        if bridges:
            lines.append(
                f"  • {bridges} provable exploit bridge(s) unattempted — report(action='chain', "
                "data={type:'suggest'}), then prove or dismiss each.")
    except Exception:
        pass
    body = "\n".join(lines) if lines else (
        "  • Drive every confirmed finding to its terminal and attempt every provable exploit bridge.")
    return (
        f"DEFERRED — '{cov_type}' is breadth cell-testing (Phase B work) and you are in PHASE A "
        "(deep exploitation). The matrix is being built for Phase B, but do NOT drain it yet — do "
        "the DEEP work still owed:\n" + body + "\n"
        "The scan AUTO-ADVANCES to Phase B only when depth is exhausted (all applicable skills run, "
        "every high/critical driven to a terminal or a documented dead-end, and no provable bridge "
        "left) — the sweep runs THEN. Keep hunting; don't burn cells."
    )


async def _do_coverage(data):
    from core import coverage as cov

    cov_type = data.get("type", "")
    log.note(f"coverage({cov_type}): {json.dumps(data)[:300]}")

    if not cov_type:
        cov_type = _infer_coverage_type(data)

    # THREE-PHASE: Phase A (deep hunt) BUILDS the matrix freely (endpoint / import_openapi are
    # discovery — useful for Phase B/C) but must NOT DRAIN it. The bulk breadth-testing types
    # (sweep / bulk_tested / next_batch / auto_crosscutting) are Phase B work; in Phase A they
    # redirect so the model drives findings to terminal instead of burning cells. Registration
    # and single-cell 'tested' (linking a confirmed exploit to its cell) stay allowed.
    if cov_type in ("sweep", "bulk_tested", "next_batch", "auto_crosscutting"):
        from core import session as _sess
        from core.session import phases as _phases
        if _phases.current_phase(_sess.get()) == _phases.EXPLOIT:
            return _phase_a_deepwork_redirect(cov_type)

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
    if cov_type in ("import_openapi", "import_graphql"):
        return await _do_coverage_import(cov_type, data)
    if cov_type == "auto_crosscutting":
        return await _do_coverage_auto_crosscutting(data, cov)
    return (
        f"Unknown coverage type '{cov_type}'. Use: endpoint, tested, bulk_tested, list, next_batch, "
        f"sweep, import_openapi, import_graphql, auto_crosscutting, reset. "
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
