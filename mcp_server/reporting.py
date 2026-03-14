"""
Reporting tools
===============
report_finding, report_diagram, and start_dashboard.
"""
from core import findings as findings_store
from core import logger as log
from mcp_server._app import mcp


@mcp.tool()
async def report_finding(
    title:       str,
    severity:    str,
    target:      str,
    description: str,
    evidence:    str,
    tool_used:   str = "",
    cve:         str = "",
) -> str:
    """
    Log a confirmed vulnerability to findings.json (shown in the live dashboard).
    Call this whenever you are confident a real vulnerability exists.

    severity : critical | high | medium | low | info
    evidence : raw tool output, HTTP request/response, or proof of exploitability
    """
    severity = severity.lower()
    if severity not in ("critical", "high", "medium", "low", "info"):
        return f"Invalid severity '{severity}'. Use: critical, high, medium, low, info"
    await findings_store.add_finding(
        title=title, severity=severity, target=target,
        description=description, evidence=evidence,
        tool_used=tool_used, cve=cve,
    )
    log.finding(severity, title, target)
    return f"Finding logged: [{severity.upper()}] {title}"


@mcp.tool()
async def report_diagram(title: str, mermaid: str) -> str:
    """
    Save a Mermaid architecture/network diagram to findings.json.

    title   : short label, e.g. "Network topology" or "Web app data flow"
    mermaid : valid Mermaid source, e.g.:
                graph TD
                  Internet --> WAF
                  WAF --> WebServer
                  WebServer --> DB[(MySQL)]
    """
    await findings_store.add_diagram(title=title, mermaid=mermaid)
    log.diagram(title)
    return f"Diagram saved: {title}"


@mcp.tool()
async def start_dashboard(port: int = 5000) -> str:
    """Start the findings dashboard at http://localhost:PORT"""
    from core import api_server
    log.tool_call("start_dashboard", {"port": port})
    url = await api_server.serve(port)
    log.tool_result("start_dashboard", url)
    return f"Dashboard running — open {url}"
