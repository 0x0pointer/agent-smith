from __future__ import annotations

# mobsfscan — static analysis for mobile app SOURCE trees (Android/Java/Kotlin,
# iOS/Swift/Obj-C). Lightweight ephemeral scanner (like semgrep/trufflehog): mounts
# the source, runs the CLI, returns MASVS/OWASP-MASVS-tagged findings. For a built
# APK/IPA binary use scan(tool='mobsf') instead — this is the source-code path,
# typically chained from /codebase.
#
# Parser: mobsfscan's raw JSON nests every match under its rule id with verbose
# metadata; we flatten to the fields that matter (rule, path, line, severity,
# masvs, message) so the context window isn't buried.

import json

from tools.base import Tool

_SEVERITY_MAP = {"ERROR": "high", "HIGH": "high", "WARNING": "medium", "INFO": "info"}
_TARGET_MOUNT = "/target"


def _build_args(path: str = _TARGET_MOUNT, flags: str = "") -> list[str]:
    # Only the mount is visible inside the container — remap host paths to /target.
    if path != _TARGET_MOUNT and not path.startswith(_TARGET_MOUNT):
        path = _TARGET_MOUNT
    args = ["mobsfscan", "--json", path]
    if flags:
        args += flags.split()
    return args


def _parse(stdout: str, stderr: str) -> list[dict]:
    """Flatten mobsfscan JSON: {results: {rule_id: {files:[...], metadata:{...}}}}."""
    findings: list[dict] = []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return findings
    results = data.get("results", {}) or {}
    for rule_id, entry in results.items():
        meta = entry.get("metadata", {}) or {}
        severity = _SEVERITY_MAP.get(str(meta.get("severity", "")).upper(), "medium")
        files = entry.get("files", []) or []
        if not files:
            findings.append({
                "rule_id": rule_id, "path": "", "line": None,
                "severity": severity, "masvs": meta.get("masvs", ""),
                "message": meta.get("description", ""),
            })
        for f in files:
            findings.append({
                "rule_id":  rule_id,
                "path":     f.get("file_path", ""),
                "line":     f.get("match_lines"),
                "severity": severity,
                "masvs":    meta.get("masvs", ""),
                "owasp":    meta.get("owasp-mobile", ""),
                "message":  meta.get("description", ""),
            })
    return findings


TOOL = Tool(
    name            = "mobsfscan",
    network         = "none",   # analyzes untrusted mobile source, needs no network (AS-13)
    image           = "opensecurity/mobsfscan:latest",
    build_args      = _build_args,
    parser          = _parse,
    default_timeout = 600,
    risk_level      = "safe",
    needs_mount     = True,
    max_output      = 12_000,
    description     = (
        "Static analysis of mobile app SOURCE code (Android/iOS) — insecure "
        "storage, weak crypto, cleartext traffic, WebView/JS-bridge misuse, etc., "
        "tagged with MASVS/OWASP-Mobile. Mounts the local source (set via "
        "set_codebase). For a built APK/IPA use scan(tool='mobsf'). "
        "Args: path (default /target), flags."
    ),
)
