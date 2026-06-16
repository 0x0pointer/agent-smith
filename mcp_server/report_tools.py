"""
Consolidated report tool — replaces reporting.py
"""
import asyncio
import json
from typing import Any

from core import findings as findings_store
from core import logger as log
from core import session as scan_session
from mcp_server._app import mcp

_background_tasks: set[asyncio.Task] = set()  # keeps fire-and-forget tasks alive


# ── Gate auto-triggers ────────────────────────────────────────────────────────
# Keywords in finding titles/descriptions that indicate RCE — triggers post-exploit gate.
_RCE_KEYWORDS = (
    "command injection", "rce", "remote code execution", "code execution",
    "ssti", "server-side template injection", "deserialization",
    "os command", "shell injection", "eval injection",
)

# Keywords in notes that indicate container/K8s environment — triggers container gate.
_K8S_KEYWORDS = (
    "kubernetes", "kubepods", "/.dockerenv", "dockerenv",
    "sa token", "serviceaccount", "k8s", "containerd", "cri-o",
)

# Keywords in notes that indicate cloud metadata access — triggers cloud gate.
_CLOUD_KEYWORDS = (
    "metadata service", "imds", "cloud metadata",
    "iam role", "instance profile", "link-local metadata",
)
# Cloud metadata IPs checked separately to avoid hardcoded-IP linting rules.
_CLOUD_METADATA_PREFIX = "169.254."

# Keywords in notes that indicate internal network discovery — triggers network gate.
# Deliberately broad: agents write notes in many styles ("172.18.0.0/24", "host at 10.",
# "docker network", "reachable from DB container", etc.) — all should fire the gate.
_INTERNAL_NET_KEYWORDS = (
    # Explicit phrasing
    "internal subnet", "internal network", "non-public subnet",
    "live hosts on 10.", "live hosts on 172.", "live hosts on 192.168.",
    # Natural phrasing agents actually write
    "docker network", "container network", "host at 10.", "host at 172.",
    "hosts at 10.", "hosts at 172.", "hosts at 192.168.",
    "reachable from", "pivot", "10.0.", "10.1.", "10.2.", "10.10.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "192.168.", "subnet /24", "subnet /16",
)

# Keywords that indicate auth services — triggers credential-audit gate.
_AUTH_KEYWORDS = (
    "ssh", "ftp", "smb", "rdp", "vnc", "telnet",
    "login form", "basic auth", "admin panel", "management console",
    "mysql", "postgres", "mssql", "mongodb", "redis", "ldap",
)


@mcp.tool()
async def report(action: str, data: Any) -> str:
    """Log findings, diagrams, notes, or coverage matrix updates.

    action : finding | update_finding | delete_finding | diagram | note | dashboard | coverage

    finding data:
      title, severity (critical|high|medium|low|info), target,
      description, evidence, tool_used=, cve=, business_impact=,
      reproduction= {type: http|command|script|manual, command: "...", expected: "..."}

    update_finding data:
      id (required), plus any fields to update:
      severity, title, description, evidence, status (confirmed|false_positive|draft),
      gh_issue, remediation, reproduction, escalation_leads,
      adjudication ({reproducible, original_severity, revised_severity, rationale} —
      the final senior-review verdict; rationale is required for it to count)

    delete_finding data:
      id — moves the finding to the archived[] array (not permanently deleted)

    diagram data:
      title, mermaid (valid Mermaid source)

    note data:
      message

    dashboard data:
      port=7777

    coverage data:
      type: endpoint | tested | bulk_tested | reset

      endpoint — register an endpoint and auto-generate test cells:
        path, method, params=[{name, type, value_hint}], discovered_by=spider, auth_context=none

      tested — mark a single cell as tested:
        cell_id, status (tested_clean|vulnerable|not_applicable|skipped), notes=, finding_id=

      bulk_tested — mark multiple cells:
        updates=[{cell_id, status, notes=, finding_id=}]

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
    else:
        return f"Unknown action '{action}'. Use: finding, update_finding, delete_finding, diagram, note, dashboard, coverage"


async def _do_finding(data):
    severity = data.get("severity", "").lower()
    if severity not in ("critical", "high", "medium", "low", "info"):
        return f"Invalid severity '{severity}'. Use: critical, high, medium, low, info"
    title = data.get("title", "")
    target = data.get("target", "")
    await findings_store.add_finding(
        title=title, severity=severity, target=target,
        description=data.get("description", ""),
        evidence=data.get("evidence", ""),
        tool_used=data.get("tool_used", ""),
        cve=data.get("cve", ""),
        business_impact=data.get("business_impact", ""),
        reproduction=data.get("reproduction"),
        escalation_leads=data.get("escalation_leads"),
    )
    log.finding(severity, title, target)

    # Append FINDING entry to quick_log
    try:
        from core.quick_log import quick_log as _qlog
        _t = asyncio.create_task(_qlog.append({
            "type":     "FINDING",
            "severity": severity,
            "title":    title,
            "target":   target,
        }))
        _background_tasks.add(_t)
        _t.add_done_callback(_background_tasks.discard)
    except Exception:
        pass

    # ── Auto-trigger gates based on finding content ──────────────────────────
    gates_triggered = _auto_trigger_finding_gates(title, severity, data.get("description", ""))
    msg = f"Finding logged: [{severity.upper()}] {title}"
    if gates_triggered:
        msg += f"\n\nGATE(S) TRIGGERED: {', '.join(gates_triggered)}. These skills are now mandatory before completion."
    return msg


def _auto_trigger_finding_gates(title: str, severity: str, description: str) -> list[str]:
    """Check finding content and trigger appropriate gates. Returns list of triggered gate IDs."""
    triggered: list[str] = []
    text = f"{title} {description}".lower()

    # RCE-class finding → post-exploit is mandatory
    if severity in ("critical", "high") and any(kw in text for kw in _RCE_KEYWORDS):
        scan_session.trigger_gate(
            "post_exploit_rce",
            f"RCE confirmed: {title}",
            ["post-exploit"],
        )
        triggered.append("post_exploit_rce")

    # Auth service finding → credential-audit is mandatory
    if any(kw in text for kw in _AUTH_KEYWORDS):
        current = scan_session.get()
        depth = current.get("depth", "standard") if current else "standard"
        if depth in ("standard", "thorough"):
            scan_session.trigger_gate(
                "credential_audit",
                f"Auth service detected: {title}",
                ["credential-audit"],
            )
            triggered.append("credential_audit")

    return triggered


async def _do_update_finding(data):
    finding_id = data.get("id", "")
    if not finding_id:
        return "Missing required field: id"
    fields = {k: v for k, v in data.items() if k != "id"}
    if not fields:
        return "No fields to update. Provide severity, title, description, evidence, status, etc."

    # Normalise the adjudication audit trail so every senior-review verdict
    # (especially a downgrade) is stored in a consistent, explainable shape.
    # A verdict with no rationale is dropped — it must not falsely satisfy the
    # completion-time adjudication gate (see adjunction/).
    adjudication_dropped = False
    if "adjudication" in fields:
        from core.adjunction import coerce_adjudication
        current = next(
            (f for f in findings_store._load().get("findings", []) if f.get("id") == finding_id),
            None,
        )
        coerced = coerce_adjudication(fields.get("adjudication"), current)
        if coerced is None:
            fields.pop("adjudication", None)
            adjudication_dropped = True
        else:
            fields["adjudication"] = coerced

    updated = await findings_store.update_finding(finding_id, **fields)
    if updated:
        msg = f"Finding updated: {finding_id} — fields: {', '.join(fields.keys())}"
        if adjudication_dropped:
            msg += (
                "\n\nNOTE: adjudication was ignored — it needs a non-empty 'rationale'. "
                "Re-send with adjudication={reproducible, original_severity, revised_severity, "
                "rationale} for it to count toward completion."
            )
        else:
            adj = fields.get("adjudication")
            if adj:
                try:
                    from core.adjunction.log import log_verdict
                    log_verdict(
                        finding_id=finding_id,
                        title=updated.get("title", finding_id),
                        original_severity=str(adj.get("original_severity", "")),
                        revised_severity=str(adj.get("revised_severity", "")),
                        reproducible=adj.get("reproducible", ""),
                        rationale=str(adj.get("rationale", "")),
                    )
                except Exception:
                    pass
        return msg
    return f"Finding not found: {finding_id}"


async def _do_delete_finding(data):
    finding_id = data.get("id", "")
    if not finding_id:
        return "Missing required field: id"
    archived = await findings_store.delete_finding(finding_id)
    if archived:
        return f"Finding archived: {finding_id} — moved to archived[] in findings.json"
    return f"Finding not found: {finding_id}"


async def _do_diagram(data):
    title = data.get("title", "")
    mermaid = data.get("mermaid", "")
    await findings_store.add_diagram(title=title, mermaid=mermaid)
    log.diagram(title)
    return f"Diagram saved: {title}"


def _do_note(data):
    message = data.get("message", "")
    log.note(message)

    # ── Auto-trigger gates based on note content ─────────────────────────────
    gates_triggered = _auto_trigger_note_gates(message)
    if gates_triggered:
        return f"Logged.\n\nGATE(S) TRIGGERED: {', '.join(gates_triggered)}. These skills are now mandatory before completion."
    return "Logged."


def _auto_trigger_note_gates(message: str) -> list[str]:
    """Check note content and trigger environment-specific gates. Returns list of triggered gate IDs."""
    triggered: list[str] = []
    text = message.lower()

    # Only trigger environment gates if an RCE gate already exists (we have access)
    rce_gate_exists = any(g["id"] == "post_exploit_rce" for g in (scan_session.get() or {}).get("gates", []))

    if rce_gate_exists:
        # K8s/container indicators → container-k8s-security mandatory
        if any(kw in text for kw in _K8S_KEYWORDS):
            scan_session.trigger_gate(
                "container_k8s",
                "Container/K8s environment detected",
                ["container-k8s-security"],
            )
            triggered.append("container_k8s")

        # Cloud metadata indicators → cloud-security mandatory
        if any(kw in text for kw in _CLOUD_KEYWORDS) or _CLOUD_METADATA_PREFIX in text:
            scan_session.trigger_gate(
                "cloud_pivot",
                "Cloud metadata service reachable",
                ["cloud-security"],
            )
            triggered.append("cloud_pivot")

        # Internal network indicators → network-assess mandatory
        if any(kw in text for kw in _INTERNAL_NET_KEYWORDS):
            scan_session.trigger_gate(
                "internal_network",
                "Internal network reachable from compromised host",
                ["network-assess"],
            )
            triggered.append("internal_network")

    # Auth service indicators in notes (e.g. from nmap service detection)
    if any(kw in text for kw in _AUTH_KEYWORDS):
        current = scan_session.get()
        depth = current.get("depth", "standard") if current else "standard"
        if depth in ("standard", "thorough"):
            scan_session.trigger_gate(
                "credential_audit",
                "Auth service detected in recon",
                ["credential-audit"],
            )
            triggered.append("credential_audit")

    return triggered


# Single source of truth for the dashboard port. Match the launchd plist,
# the install scripts, CLAUDE.md docs, and the api_server.serve() default —
# every reference in this repo says 7777.
_DASHBOARD_CANONICAL_PORT = 7777

# Ports we silently rewrite to the canonical one. The skills submodule
# pentester*.md files hard-code `data={"port": 5000}` which dates back to
# an earlier convention. Rather than wait for a submodule-bump PR + cascade
# every operator's `~/.config/opencode/opencode.json` to a new port, we
# normalize the legacy values here so Smith's call lands on the port the
# operator's browser is already pointed at. Add new aliases here as
# upstream skill repos drift.
_LEGACY_DASHBOARD_PORTS = {5000, 8000, 8080}


def _safe_port(value, default: int) -> int:
    """Coerce a user-supplied port value to a valid int in the IANA range.

    Defense against SonarQube python:S5145 (log injection): the result is a
    sanitized int that's safe to interpolate into log lines. Invalid input
    (non-int, non-numeric string, negative, > 65535) falls back to the
    default — we never log the raw value back to the operator, which would
    let a malicious tool-call payload write fake log entries by embedding
    newlines.
    """
    try:
        v = int(value)
    except (TypeError, ValueError):
        return default
    if 0 < v < 65536:
        return v
    return default


async def _do_dashboard(data):
    try:
        from core import api_server
        # Sanitize at the boundary — `requested` is now guaranteed to be an
        # int in [1, 65535], safe to interpolate into log lines and audit
        # trails without S5145 (log injection) exposure.
        requested = _safe_port(data.get("port"), _DASHBOARD_CANONICAL_PORT)
        if requested in _LEGACY_DASHBOARD_PORTS:
            log.tool_result(
                "dashboard",
                f"port {requested} normalized to {_DASHBOARD_CANONICAL_PORT} "
                "(canonical agent-smith dashboard port)",
            )
            port = _DASHBOARD_CANONICAL_PORT
        else:
            port = requested
        log.tool_call("dashboard", {"port": port, "requested": requested})
        url = await api_server.serve(port)
        log.tool_result("dashboard", url)
        return f"Dashboard running — open {url}"
    except BaseException as exc:
        # Defense against S5145: don't echo the raw exception message into
        # the audit log or the return string — its content could come from
        # user-controlled input (e.g. a malformed port value). The exception
        # type alone is enough for Smith to diagnose. Full traceback still
        # goes via Python's standard logger which uses parameter binding,
        # not string interpolation, so log-injection is prevented there too.
        safe_err = f"Dashboard failed: {type(exc).__name__}"
        log.tool_result("dashboard", safe_err)
        return safe_err
        return err


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
    return (
        f"Unknown coverage type '{cov_type}'. Use: endpoint, tested, bulk_tested, list, reset. "
        f"Example: report(action='coverage', data={{type:'endpoint', path:'/login', method:'GET', "
        f"params:[{{name:'user', type:'query', value_hint:'string'}}]}})"
    )


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
                              auth|authz|rate_limit|cors|security_headers|csrf
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


async def _emit_coverage_event() -> None:
    """Append a COVERAGE entry to quick_log with current matrix totals."""
    try:
        from core.quick_log import quick_log as _qlog
        from core import coverage as _cov
        matrix    = _cov.get_matrix()
        meta      = matrix.get("meta", {})
        all_cells = matrix.get("matrix", [])
        await _qlog.append({
            "type":           "COVERAGE",
            "registered":     len(matrix.get("endpoints", [])),
            "pending":        sum(1 for c in all_cells if c["status"] == "pending"),
            "tested":         meta.get("tested", 0),
            "vulnerable":     meta.get("vulnerable", 0),
            "not_applicable": sum(1 for c in all_cells if c["status"] == "not_applicable"),
            "skipped":        sum(1 for c in all_cells if c["status"] == "skipped"),
            "na_untooled":    sum(1 for c in all_cells
                                  if c["status"] == "not_applicable" and not c.get("tested_by")),
            "untooled":       sum(1 for c in all_cells
                                  if c["status"] in ("tested_clean", "vulnerable")
                                  and not c.get("tested_by")),
        })
    except Exception:
        pass
