"""
Consolidated report tool — replaces reporting.py
"""
import json
from typing import Any

from core import findings as findings_store
from core import logger as log
from core import session as scan_session
from mcp_server._app import mcp


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
_INTERNAL_NET_KEYWORDS = (
    "internal subnet", "internal network", "live hosts on 10.",
    "live hosts on 172.", "live hosts on 192.168.",
    "non-public subnet", "pivot",
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
      description, evidence, tool_used=, cve=,
      reproduction= {type: http|command|script|manual, command: "...", expected: "..."}

    update_finding data:
      id (required), plus any fields to update:
      severity, title, description, evidence, status (confirmed|false_positive|draft),
      gh_issue, remediation, reproduction, escalation_leads

    delete_finding data:
      id — moves the finding to the archived[] array (not permanently deleted)

    diagram data:
      title, mermaid (valid Mermaid source)

    note data:
      message

    dashboard data:
      port=5000

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
        reproduction=data.get("reproduction"),
        escalation_leads=data.get("escalation_leads"),
    )
    log.finding(severity, title, target)

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
    updated = await findings_store.update_finding(finding_id, **fields)
    if updated:
        return f"Finding updated: {finding_id} — fields: {', '.join(fields.keys())}"
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


async def _do_dashboard(data):
    try:
        from core import api_server
        port = data.get("port", 5000)
        log.tool_call("dashboard", {"port": port})
        url = await api_server.serve(port)
        log.tool_result("dashboard", url)
        return f"Dashboard running — open {url}"
    except BaseException as exc:
        err = f"Dashboard failed: {type(exc).__name__}: {exc}"
        log.tool_result("dashboard", err)
        return err


async def _do_coverage(data):
    from core import coverage as cov

    cov_type = data.get("type", "")
    log.note(f"coverage({cov_type}): {json.dumps(data)[:300]}")

    # --- Resilience: auto-detect type from data shape ---
    if not cov_type:
        if "path" in data:
            cov_type = "endpoint"
        elif "cell_id" in data:
            cov_type = "tested"
        elif "updates" in data:
            cov_type = "bulk_tested"

    if cov_type == "endpoint":
        path = data.get("path", "")
        if not path:
            return "Error: 'path' is required for endpoint registration. Example: report(action='coverage', data={type:'endpoint', path:'/login', method:'GET', params:[{name:'q', type:'query', value_hint:'string'}]})"

        # Resilience: coerce params from various model formats
        params = data.get("params", [])
        if isinstance(params, str):
            try:
                params = json.loads(params)
            except json.JSONDecodeError:
                params = []
        if not isinstance(params, list):
            params = []
        # Ensure each param has the required fields
        clean_params = []
        for p in params:
            if isinstance(p, str):
                clean_params.append({"name": p, "type": "query", "value_hint": "string"})
            elif isinstance(p, dict):
                clean_params.append({
                    "name": p.get("name", p.get("param", "")),
                    "type": p.get("type", p.get("param_type", "query")),
                    "value_hint": p.get("value_hint", p.get("hint", "string")),
                })

        result = await cov.add_endpoint(
            path=path,
            method=data.get("method", "GET"),
            params=clean_params,
            discovered_by=data.get("discovered_by", "spider"),
            auth_context=data.get("auth_context", "none"),
        )
        if result["dedup"]:
            return f"Endpoint already registered (dedup): {path} {data.get('method', 'GET')}"
        return (
            f"Endpoint registered: {data.get('method', 'GET')} {path} — "
            f"{result['new_cells']} test cells auto-generated"
        )

    elif cov_type == "tested":
        result = await cov.update_cell(
            cell_id=data.get("cell_id", ""),
            status=data.get("status", ""),
            notes=data.get("notes", ""),
            finding_id=data.get("finding_id"),
            tested_by=data.get("tested_by", ""),
        )
        if result is False:
            return f"Cell not found: {data.get('cell_id')}"
        if isinstance(result, str):
            # Integrity warning — cell was updated but with a warning
            return f"Cell updated: {data.get('cell_id')} — {result}"
        return f"Cell updated: {data.get('cell_id')}"

    elif cov_type == "bulk_tested":
        result = await cov.bulk_update(data.get("updates", []))
        msg = f"Bulk update: {result['updated']} cell(s) updated"
        if result["warnings"]:
            msg += f"\n\nINTEGRITY WARNINGS ({len(result['warnings'])}):\n"
            msg += "\n".join(f"  - {w}" for w in result["warnings"])
        return msg

    elif cov_type == "reset":
        current = scan_session.get()
        if current and current.get("status") == "running":
            log.note("coverage reset BLOCKED — scan is active. Do NOT reset the matrix mid-scan.")
            return (
                "BLOCKED: Cannot reset coverage matrix while a scan is running. "
                "The matrix tracks your testing progress — resetting it mid-scan destroys that state. "
                "If you need to re-register endpoints, just call coverage(type='endpoint') again — "
                "duplicates are automatically ignored."
            )
        await cov.reset()
        return "Coverage matrix reset."

    else:
        return (
            f"Unknown coverage type '{cov_type}'. Use: endpoint, tested, bulk_tested, reset. "
            f"Example: report(action='coverage', data={{type:'endpoint', path:'/login', method:'GET', "
            f"params:[{{name:'user', type:'query', value_hint:'string'}}]}})"
        )
