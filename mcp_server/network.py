"""
Network recon tools
===================
Passive and active network discovery: port scanning, subdomain enumeration.
"""
from mcp_server._app import mcp, _run


@mcp.tool()
async def run_nmap(host: str, ports: str = "top-1000", flags: str = "") -> str:
    """Port scanner. Args: host, ports (top-1000 | full | '80,443'), flags."""
    return await _run("nmap", host=host, ports=ports, flags=flags)


@mcp.tool()
async def run_naabu(host: str, ports: str = "top-100", flags: str = "") -> str:
    """Fast port scanner. Args: host, ports (top-100 | full | '1-10000'), flags."""
    return await _run("naabu", host=host, ports=ports, flags=flags)


@mcp.tool()
async def run_subfinder(domain: str, flags: str = "") -> str:
    """Subdomain discovery. Args: domain, flags."""
    return await _run("subfinder", domain=domain, flags=flags)
