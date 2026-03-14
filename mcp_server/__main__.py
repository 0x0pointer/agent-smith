"""
Pentest Agent MCP Server
========================
Thin entry point — loads .env, imports all tool modules, starts the server.

Tool modules (grouped by function):
  server/network.py      — run_nmap, run_naabu, run_subfinder
  server/web.py          — run_httpx, run_nuclei, run_ffuf, run_spider
  server/code_analysis.py— run_semgrep, run_trufflehog, set_codebase_target
  server/exploitation.py — http_request, save_poc, kali_exec
  server/ai_red_team.py  — run_fuzzyai, run_pyrit
  server/scan.py         — start_scan, complete_scan, log_note
  server/reporting.py    — report_finding, report_diagram, start_dashboard
  server/infra.py        — start_kali, stop_kali, pull_images

Register with Claude Code (run once):
  claude mcp add pentest-agent -- poetry -C ~/Desktop/agent-smith run python -m server
"""
from mcp_server._app import _load_dotenv
_load_dotenv()

import mcp_server.network        # noqa: F401
import mcp_server.web            # noqa: F401
import mcp_server.code_analysis  # noqa: F401
import mcp_server.exploitation   # noqa: F401
import mcp_server.ai_red_team    # noqa: F401
import mcp_server.scan           # noqa: F401
import mcp_server.reporting      # noqa: F401
import mcp_server.infra          # noqa: F401

from mcp_server._app import mcp

mcp.run()
