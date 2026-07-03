"""
Consolidated report tool — replaces reporting.py

Split into a package for the <300-lines-per-file convention. This facade keeps
the public import surface identical: `import mcp_server.report_tools` still
registers the `@mcp.tool()` `report` dispatcher, and every name previously
importable from the module is re-exported here.
"""
import json
from typing import Any

from mcp_server._app import mcp

# ── Shared state + helpers (re-exported for consumers/tests) ────────────────────
from ._common import (
    findings_store,
    log,
    scan_session,
    _background_tasks,
    _WS_RE,
    _norm_text,
    _norm_target,
    _safe,
    _MERMAID_ESCAPES,
    _mermaid_label,
    _safe_port,
    _AUTH_KEYWORDS,
    _AUTH_WEAKNESS_KEYWORDS,
    _CLOUD_KEYWORDS,
    _CLOUD_METADATA_PREFIX,
    _GATE_BENIGN_MARKERS,
    _INTERNAL_NET_KEYWORDS,
    _K8S_KEYWORDS,
    _RCE_KEYWORDS,
    _SPECULATION_MARKERS,
)
from .gates import (
    _auto_trigger_finding_gates,
    _auto_trigger_note_gates,
)
from .findings import (
    _validate_trace_field,
    _find_duplicate,
    _dedup_message,
    _FINDING_INJECTION_PATTERNS,
    _infer_injection_type,
    _autolink_finding_to_cell,
    _do_finding,
    _log_adjudication_verdict,
    _coerce_finding_adjudication,
    _do_update_finding,
    _do_delete_finding,
)
from .diagrams import (
    _do_diagram,
    _chain_mermaid,
    _do_chain,
    _do_note,
    _do_dashboard,
    _DASHBOARD_CANONICAL_PORT,
    _LEGACY_DASHBOARD_PORTS,
)
from .coverage import (
    _coerce_endpoint_params,
    _infer_coverage_type,
    _do_coverage_endpoint,
    _do_coverage_tested,
    _do_coverage_bulk,
    _do_coverage_reset,
    _do_coverage,
    _autofile_crosscutting_findings,
    _do_coverage_auto_crosscutting,
    _do_coverage_next_batch,
    _do_coverage_list,
    _do_coverage_sweep,
    _emit_coverage_event,
)


@mcp.tool()
async def report(action: str, data: Any) -> str:
    """Log findings, diagrams, notes, or coverage matrix updates.

    action : finding | update_finding | delete_finding | diagram | note | dashboard | coverage

    finding data:
      title, severity (critical|high|medium|low|info), target,
      description, evidence, tool_used=, cve=, business_impact=,
      artifact_id= (optional) the artifact_id of the tool call that proves this
        finding — links the proof so adjudication can REUSE it instead of making
        you re-run the attack. If omitted, the session's most-recent tool
        artifact is auto-linked.
      reproduction= {type: http|command|script|manual, command: "...", expected: "..."},
      trace= (optional, WHITE-BOX findings) source data flow as an ordered list
        [{kind: entrypoint|propagation|sink, file, line, scope, description}] —
        first step entrypoint, last step sink, >=2 steps. When a codebase is
        pinned (session set_codebase), each cited file:line is RESOLVED against
        the repo and a citation that doesn't exist is REJECTED. Omit for
        black-box findings. Duplicate findings (same target+title+severity, not a
        prior false_positive) are deduplicated — re-file distinct issues with a
        more specific title.

    update_finding data:
      id (required), plus any fields to update:
      severity, title, description, evidence, status (confirmed|false_positive|draft),
      gh_issue, remediation, reproduction, escalation_leads,
      adjudication ({reproducible, artifact_id, original_severity, revised_severity, rationale} —
      the final senior-review verdict; rationale is required, and artifact_id (an
      artifact that exists on disk) is required when reproducible=true)

    delete_finding data:
      id — moves the finding to the archived[] array (not permanently deleted)

    diagram data:
      title, mermaid (valid Mermaid source)

    note data:
      message

    chain data:
      name, steps=[{from_finding_id, to_finding_id, transition_artifact_id, mitre_technique}],
      terminal_impact=, combined_severity=
      — records a PROVEN exploit chain: every step's transition_artifact_id must
      exist on disk (the artifact proving step N's output feeds step N+1), else the
      chain is rejected. Auto-renders a MITRE-labelled Mermaid kill-chain diagram.
      • data={type:'suggest'} — returns GRAPH-DERIVED candidate chains (from the
        knowledge graph of findings/creds/hosts) for you to prove and then file.

    dashboard data:
      port=7777

    coverage data:
      type: endpoint | tested | bulk_tested | sweep | reset

      endpoint — register an endpoint and auto-generate test cells:
        path, method, params=[{name, type, value_hint}], discovered_by=spider, auth_context=none

      tested — mark a single cell as tested:
        cell_id, status (tested_clean|vulnerable|not_applicable|skipped), notes=, finding_id=

      bulk_tested — mark multiple cells:
        updates=[{cell_id, status, notes=, finding_id=}]

      sweep — SERVER-SIDE probe + evaluate for pending injection cells
        (ssti/xss/cmdi/traversal/sqli): options max_cells=25, endpoint_id=. The
        server runs each probe, stores the artifact, AUTO-CLOSES confident-clean
        cells, and returns oracle-positive cells as CANDIDATES for you to confirm,
        file a finding, and close vulnerable. Use this to close injection coverage
        fast instead of hand-running every probe — then handle the candidates.

      import_openapi / import_graphql — register EVERY operation of a schema in
        ONE call (vs hand-transcribing each): data.url = the spec URL (OpenAPI/
        Swagger) or the /graphql endpoint. Auth is pulled from known_assets.

      reset — clear the entire matrix (no additional fields)
    """
    try:
        if isinstance(data, str):
            data = json.loads(data)
    except (json.JSONDecodeError, TypeError) as exc:
        log.note(f"report({action}) data parse error: {exc} — raw: {str(data)[:200]}")
        return f"Error: could not parse data as JSON: {exc}"
    if not isinstance(data, dict):
        log.note(f"report({action}) data is not a dict: {type(data).__name__}")
        return f"Error: data must be a JSON object/dict, got {type(data).__name__}"
    if action == "finding":
        return await _do_finding(data)
    elif action == "update_finding":
        return await _do_update_finding(data)
    elif action == "delete_finding":
        return await _do_delete_finding(data)
    elif action == "diagram":
        return await _do_diagram(data)
    elif action == "note":
        return _do_note(data)
    elif action == "dashboard":
        return await _do_dashboard(data)
    elif action == "coverage":
        return await _do_coverage(data)
    elif action == "chain":
        return await _do_chain(data)
    else:
        return f"Unknown action '{action}'. Use: finding, update_finding, delete_finding, diagram, note, dashboard, coverage, chain"
