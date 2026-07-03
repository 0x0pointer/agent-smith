"""
Coverage matrix extras: cross-cutting propagation, next-batch handoff, listing.
Split out of coverage.py for the <300-lines-per-file convention.
"""
import json

from ._common import scan_session


async def _autofile_crosscutting_findings(headers: dict, artifact_id: str,
                                          target: str, existing: list) -> int:
    """File the app-wide cross-cutting findings the response evidences (wildcard
    CORS, missing security headers) when the model hasn't already — so Phase 0
    can close those cells `vulnerable` (it links a finding for every vulnerable
    verdict, never fabricates). Idempotent: skips a type that already has a
    matching finding, so re-running on each complete attempt can't duplicate.
    Returns the number filed.
    """
    from core import findings as _fs
    from core.coverage.autoclose import _REQUIRED_SECURITY_HEADERS, _match_finding_id

    hdrs = {(k or "").lower(): (v or "") for k, v in (headers or {}).items()}
    acao = hdrs.get("access-control-allow-origin", "").strip()
    missing = [h for h in _REQUIRED_SECURITY_HEADERS if h not in hdrs]
    tgt = target or "application"
    filed = 0
    if acao == "*" and not _match_finding_id(existing, "cors"):
        await _fs.add_finding(
            title="Wildcard CORS — Access-Control-Allow-Origin: * on all responses",
            severity="medium", target=tgt,
            description=("The application returns Access-Control-Allow-Origin: * on its responses, "
                         "letting any origin read responses cross-origin."),
            evidence=f"Observed response header Access-Control-Allow-Origin: {acao} (artifact {artifact_id}).",
            tool_used="auto_crosscutting", evidence_artifact_id=artifact_id)
        filed += 1
    if missing and not _match_finding_id(existing, "security_headers"):
        await _fs.add_finding(
            title="Missing Security Headers on all responses",
            severity="low", target=tgt,
            description="Responses lack standard security headers: " + ", ".join(missing) + ".",
            evidence=f"Required headers absent (artifact {artifact_id}): {', '.join(missing)}.",
            tool_used="auto_crosscutting", evidence_artifact_id=artifact_id)
        filed += 1
    return filed


async def _do_coverage_auto_crosscutting(data, cov):
    """Propagate app-wide cross-cutting verdicts to their per-endpoint cells.

    The matrix fans every endpoint across response-property checks (cors,
    security_headers, csrf) whose verdict is app-wide. The model files the
    app-wide finding ("Wildcard CORS on all endpoints") but rarely marks the 50+
    per-endpoint cells, so coverage reads near-zero while the work is done. This
    propagates the established verdict to the cells HONESTLY: every `vulnerable`
    close links the existing finding and cites a real response artifact; CSRF on
    a safe-method (GET/HEAD/OPTIONS) endpoint is marked not_applicable. Injection
    cells are never touched (those need real per-cell detectors).

    Optional data: `artifact_id` to override the auto-picked evidence response.
    """
    import collections

    from core import paths as _paths

    matrix = cov.get_matrix()
    cells = matrix.get("matrix", [])
    endpoints = matrix.get("endpoints", [])

    findings = []
    try:
        ff = _paths.FINDINGS_FILE
        if ff.exists():
            findings = json.loads(ff.read_text()).get("findings", [])
    except Exception:
        pass

    artifact_id = (data.get("artifact_id") or "").strip()
    headers: dict = {}
    if artifact_id:
        art_file = _paths.ARTIFACTS_DIR / f"{artifact_id}.txt"
        if art_file.exists():
            _, headers = cov.parse_artifact_headers(art_file.read_text())
    if not artifact_id or not headers:
        artifact_id, headers = cov.pick_representative_artifact(str(_paths.ARTIFACTS_DIR))

    if not artifact_id:
        return (
            "No representative response artifact found (need an http_request 200 with headers). "
            "Send a plain GET to the target first, then retry — that response is the app-wide evidence."
        )

    # Phase 0.1: file the app-wide cross-cutting findings the response evidences
    # when the model hasn't — so the cors/security_headers cells can close
    # `vulnerable` (the planner links a finding for every vulnerable verdict and
    # never fabricates one). Idempotent: a type that already has a matching
    # finding is skipped, so re-running on each complete attempt won't duplicate.
    try:
        from core import session as _sess
        target = (_sess.get() or {}).get("target", "") or ""
    except Exception:
        target = ""
    if await _autofile_crosscutting_findings(headers, artifact_id, target, findings):
        try:
            findings = json.loads(_paths.FINDINGS_FILE.read_text()).get("findings", [])
        except Exception:
            pass

    closures = cov.plan_crosscutting_closures(cells, endpoints, findings, headers, artifact_id)
    if not closures:
        return (
            "No pending cross-cutting cells to auto-close. Either cors/security_headers/csrf are already "
            "addressed, or there is no app-wide finding to link a vulnerable verdict to (file the finding first)."
        )

    # Strip the diagnostic 'basis' key before applying through the honesty gates.
    updates = [{k: v for k, v in c.items() if k != "basis"} for c in closures]
    result = await cov.bulk_update(updates)
    by_status = collections.Counter(c["status"] for c in closures)
    return json.dumps({
        "auto_crosscutting": True,
        "evidence_artifact": artifact_id,
        "planned": len(closures),
        "applied": result.get("updated"),
        "rejected": result.get("rejected"),
        "by_status": dict(by_status),
        "note": (
            "Propagated app-wide cors/security_headers/csrf verdicts to their per-endpoint cells "
            "(vulnerable cells link the existing finding; GET-endpoint CSRF marked not_applicable). "
            "Injection cells untouched."
        ),
        "warnings": result.get("warnings", [])[:5],
    }, indent=2)


async def _do_coverage_next_batch(data, cov):
    """Hand the agent a FOCUSED, concrete batch of the next cells to test.

    Returns a small batch (profile-capped) of the next pending cells on one
    endpoint, each enriched with the exact test request to send, plus progress
    (this endpoint X/Y · overall X/Y). The agent runs each request, then closes
    the whole batch in one bulk_tested call citing each artifact_id — a tight
    test→close loop instead of navigating 700+ cells solo.
    """
    from mcp_server.scan_engine.budget import get_profile
    from mcp_server.scan_engine.planner import _concrete_test_command

    cap = get_profile().get("next_batch_size", 10)
    try:
        count = min(int(data.get("count", cap)), cap)
    except (TypeError, ValueError):
        count = cap
    endpoint_id = (data.get("endpoint_id") or "").strip() or None

    current = scan_session.get() or {}
    target = current.get("target", "")

    result = await cov.get_next_batch(count=max(1, count), endpoint_id=endpoint_id)
    for cell in result.get("batch", []):
        cell["test_request"] = _concrete_test_command(
            cell.get("injection_type", ""), target,
            cell.get("endpoint_path") or "", cell.get("method") or "GET",
            cell.get("param") or "_endpoint", cell.get("param_type") or "query",
        )

    n = len(result.get("batch", []))
    if n:
        prog = result.get("progress", {})
        result["next_step"] = (
            f"Test these {n} cell(s) on {result['endpoint_focus']['method']} "
            f"{result['endpoint_focus']['path']} "
            f"[{prog.get('endpoint','?')} this endpoint · {prog.get('overall','?')} overall]. "
            "Run each test_request, then CLOSE them in one call: "
            "report(action='coverage', data={type:'bulk_tested', updates:[{cell_id, status:'tested_clean|vulnerable|not_applicable', "
            "artifact_id:'<from the http/kali response>', finding_id:'<required if vulnerable>'}, ...]}). "
            "Then call this again for the next batch."
        )
    else:
        result["next_step"] = "All cells addressed — proceed to validation/reporting."
    return json.dumps(result, indent=2)


async def _do_coverage_list(data, cov):
    """Read the current matrix with optional filters. Compaction-recovery
    primitive: Smith uses this after a context reset to rebuild its
    mental model of which cells exist, what their IDs are, and where
    each one stands.

    Accepted filter keys (all optional, AND-combined):
      endpoint_path  — substring match, case-insensitive (e.g. "/login")
      method         — exact match (e.g. "POST")
      status         — exact: pending|in_progress|tested_clean|vulnerable|
                              not_applicable|skipped
      injection_type — exact: sqli|xss|ssti|cmdi|ssrf|nosqli|xxe|traversal|
                              crlf|prototype|mass_assignment|redirect|
                              auth|authz|rate_limit|cors|security_headers|csrf|
                              (LLM) prompt_injection|jailbreak|cot_forgery|
                              role_prefix_spoofing|system_prompt_leak|… (see core/taxonomy.py)
      param_name     — substring match, case-insensitive
      limit          — int, default 200, hard ceiling 1000 to keep
                       the response payload bounded
    """
    LIMIT_MAX = 1000
    try:
        limit = min(int(data.get("limit", 200)), LIMIT_MAX)
    except (TypeError, ValueError):
        limit = 200
    result = await cov.list_cells(
        endpoint_path  = (data.get("endpoint_path") or "").strip() or None,
        method         = (data.get("method") or "").strip() or None,
        status         = (data.get("status") or "").strip() or None,
        injection_type = (data.get("injection_type") or "").strip() or None,
        param_name     = (data.get("param_name") or "").strip() or None,
        limit          = limit,
    )
    return json.dumps(result, indent=2)
