from __future__ import annotations

# Parser: kept — semgrep's raw JSON is extremely verbose (full AST paths,
# metadata, source ranges per finding). Without this parser, the context
# window fills with noise and Claude loses focus on the actual findings.
# The parser extracts the 5 fields that matter: rule_id, path, line,
# severity, message, code.

import json

from tools.base import Tool

_SEVERITY_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "info"}


# ---------------------------------------------------------------------------
# Arg builder
# ---------------------------------------------------------------------------

def _build_args(path: str = "/target", flags: str = "") -> list[str]:
    # /target is the mount point inside the container (see needs_mount=True)
    args = ["--config=auto", "--json", path]
    if flags:
        args += flags.split()
    return args


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def _parse(stdout: str, stderr: str) -> list[dict]:
    """Parse semgrep JSON output."""
    findings: list[dict] = []

    try:
        data = json.loads(stdout)
        for result in data.get("results", []):
            findings.append({
                "rule_id":  result.get("check_id", ""),
                "path":     result.get("path", ""),
                "line":     result.get("start", {}).get("line"),
                "severity": _SEVERITY_MAP.get(
                    result.get("extra", {}).get("severity", "INFO"), "info"
                ),
                "message":  result.get("extra", {}).get("message", ""),
                "code":     result.get("extra", {}).get("lines", ""),
            })
    except json.JSONDecodeError:
        pass

    return findings


# ---------------------------------------------------------------------------
# Exported instance
# ---------------------------------------------------------------------------

TOOL = Tool(
    name            = "semgrep",
    image           = "semgrep/semgrep",
    build_args      = _build_args,
    parser          = _parse,
    default_timeout = 300,
    risk_level      = "safe",
    needs_mount     = True,
    max_output      = 20_000,  # parser already strips AST noise; 20K covers ~100 findings
    description     = (
        "Static code analysis — finds security bugs in source code. "
        "Mounts the local codebase (set via set_codebase_target). "
        "Args: path (default /target), flags (e.g. '--config=p/owasp-top-ten')"
    ),
)
