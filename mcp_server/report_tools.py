"""
Consolidated report tool — replaces reporting.py
"""
from core import findings as findings_store
from core import logger as log
from mcp_server._app import mcp


@mcp.tool()
async def report(action: str, data: dict) -> str:
    """Log findings, diagrams, or notes.

    action : finding | diagram | note | dashboard

    finding data:
      title, severity (critical|high|medium|low|info), target,
      description, evidence, tool_used=, cve=

    diagram data:
      title, mermaid (valid Mermaid source)

    note data:
      message

    dashboard data:
      port=5000
    """
    if action == "finding":
        return await _do_finding(data)
    elif action == "diagram":
        return await _do_diagram(data)
    elif action == "note":
        return _do_note(data)
    elif action == "dashboard":
        return await _do_dashboard(data)
    else:
        return f"Unknown action '{action}'. Use: finding, diagram, note, dashboard"


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
