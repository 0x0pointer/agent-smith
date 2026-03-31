"""
Consolidated report tool — replaces reporting.py
"""
import json
from typing import Any

from core import findings as findings_store
from core import logger as log
from mcp_server._app import mcp


@mcp.tool()
async def report(action: str, data: Any) -> str:
    """Log findings, diagrams, notes, or coverage matrix updates.

    action : finding | diagram | note | dashboard | coverage

    finding data:
      title, severity (critical|high|medium|low|info), target,
      description, evidence, tool_used=, cve=,
      reproduction= {type: http|command|script|manual, command: "...", expected: "..."}

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
    if isinstance(data, str):
        data = json.loads(data)
    if action == "finding":
        return await _do_finding(data)
    elif action == "diagram":
        return await _do_diagram(data)
    elif action == "note":
        return _do_note(data)
    elif action == "dashboard":
        return await _do_dashboard(data)
    elif action == "coverage":
        return await _do_coverage(data)
    else:
        return f"Unknown action '{action}'. Use: finding, diagram, note, dashboard, coverage"


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
    return f"Finding logged: [{severity.upper()}] {title}"


async def _do_diagram(data):
    title = data.get("title", "")
    mermaid = data.get("mermaid", "")
    await findings_store.add_diagram(title=title, mermaid=mermaid)
    log.diagram(title)
    return f"Diagram saved: {title}"


def _do_note(data):
    message = data.get("message", "")
    log.note(message)
    return "Logged."


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

    if cov_type == "endpoint":
        result = await cov.add_endpoint(
            path=data.get("path", ""),
            method=data.get("method", "GET"),
            params=data.get("params", []),
            discovered_by=data.get("discovered_by", "spider"),
            auth_context=data.get("auth_context", "none"),
        )
        if result["dedup"]:
            return f"Endpoint already registered (dedup): {data.get('path')} {data.get('method', 'GET')}"
        return (
            f"Endpoint registered: {data.get('method', 'GET')} {data.get('path')} — "
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
        await cov.reset()
        return "Coverage matrix reset."

    else:
        return f"Unknown coverage type '{cov_type}'. Use: endpoint, tested, bulk_tested, reset"
