from __future__ import annotations

# Parser: kept — semgrep's raw JSON is extremely verbose (full AST paths,
# metadata, source ranges per finding). Without this parser, the context
# window fills with noise and Claude loses focus on the actual findings.
# The parser extracts the 5 fields that matter: rule_id, path, line,
# severity, message, code.

import json

from tools.base import Tool

_SEVERITY_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "info"}
_TARGET_MOUNT = "/target"


# ---------------------------------------------------------------------------
# Arg builder
# ---------------------------------------------------------------------------

def _build_args(path: str = _TARGET_MOUNT, flags: str = "") -> list[str]:
    # _TARGET_MOUNT is the mount point inside the container (see needs_mount=True).
    # The semgrep/semgrep image has no ENTRYPOINT, so the binary name must lead.
    # User-supplied host paths are remapped to _TARGET_MOUNT since only the mount is visible inside the container.
    if path != _TARGET_MOUNT and not path.startswith(_TARGET_MOUNT):
        path = _TARGET_MOUNT
    # --config=auto is invalid when --metrics=off (semgrep requires metrics for auto-detection).
    # p/python is a stable registry config that works with metrics disabled.
    # User-supplied flags can add further --config values or override behavior.
    args = ["semgrep", "--config=p/python", "--json", "--metrics=off", path]
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
    network         = "none",   # analyzes untrusted mounted code, needs no network (AS-13)
    image           = "semgrep/semgrep:latest",
    build_args      = _build_args,
    parser          = _parse,
    default_timeout = 900,
    risk_level      = "safe",
    needs_mount     = True,
    max_output      = 12_000,  # parser strips AST noise; 12K aligns with other structured tools
    description     = (
        "Static code analysis — finds security bugs in source code. "
        "Mounts the local codebase (set via set_codebase_target). "
        "Args: path (default /target), flags (e.g. '--config=p/owasp-top-ten')"
    ),
)
