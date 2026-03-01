from __future__ import annotations

# Parser: kept — trufflehog's raw JSON includes full plaintext secret values
# (API keys, private keys, passwords). Passing those untruncated through
# Claude's context means they end up in API logs and conversation history.
# The parser truncates Raw to 80 chars so Claude can identify the finding
# type and location without exposing the full credential.

import json

from tools.base import Tool


# ---------------------------------------------------------------------------
# Arg builder
# ---------------------------------------------------------------------------

def _build_args(path: str = "/target", flags: str = "") -> list[str]:
    args = ["filesystem", path, "--json", "--no-verification"]
    if flags:
        args += flags.split()
    return args


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def _parse(stdout: str, stderr: str) -> list[dict]:
    """Parse trufflehog JSON-lines output. Raw secret values are truncated."""
    findings: list[dict] = []

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            findings.append({
                "detector": entry.get("DetectorName", ""),
                "file":     (
                    entry.get("SourceMetadata", {})
                    .get("Data", {})
                    .get("Filesystem", {})
                    .get("file", "")
                ),
                "line":     (
                    entry.get("SourceMetadata", {})
                    .get("Data", {})
                    .get("Filesystem", {})
                    .get("line")
                ),
                # Truncate to avoid logging full secret values
                "raw":      entry.get("Raw", "")[:80],
                "verified": entry.get("Verified", False),
            })
        except json.JSONDecodeError:
            pass

    return findings


# ---------------------------------------------------------------------------
# Exported instance
# ---------------------------------------------------------------------------

TOOL = Tool(
    name            = "trufflehog",
    image           = "trufflesecurity/trufflehog",
    build_args      = _build_args,
    parser          = _parse,
    default_timeout = 120,
    risk_level      = "safe",
    needs_mount     = True,
    max_output      = 8_000,   # parser already truncates secret values to 80 chars
    description     = (
        "Secret and credential scanner. "
        "Mounts the local codebase (set via set_codebase_target). "
        "Args: path (default /target), flags (optional)"
    ),
)
