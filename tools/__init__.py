"""
Tool registry — single source of truth for all lightweight Docker tools.

To add a new tool:
  1. Create tools/<toolname>.py following the pattern in any existing tool file
     (define _build_args, _parse, and TOOL = Tool(...))
  2. Add one import line below
  3. Add one entry in the REGISTRY dict
  4. Add one @mcp.tool() function in mcp_server.py
"""
from __future__ import annotations

from tools.ffuf       import TOOL as _ffuf
from tools.httpx      import TOOL as _httpx
from tools.naabu      import TOOL as _naabu
from tools.nmap       import TOOL as _nmap
from tools.nuclei     import TOOL as _nuclei
from tools.semgrep    import TOOL as _semgrep
from tools.subfinder  import TOOL as _subfinder
from tools.trufflehog import TOOL as _trufflehog

# fmt: off
REGISTRY = {
    _nmap.name:       _nmap,        # nmap       — port scanner
    _naabu.name:      _naabu,       # naabu      — fast port scanner
    _httpx.name:      _httpx,       # httpx      — HTTP probe
    _nuclei.name:     _nuclei,      # nuclei     — template vuln scanner
    _ffuf.name:       _ffuf,        # ffuf       — web fuzzer
    _subfinder.name:  _subfinder,   # subfinder  — subdomain discovery
    _semgrep.name:    _semgrep,     # semgrep    — static code analysis
    _trufflehog.name: _trufflehog,  # trufflehog — secret scanner
}
# fmt: on

__all__ = ["REGISTRY"]
