from __future__ import annotations

# Templates note: projectdiscovery/nuclei v3 does NOT bundle templates in the image.
# We mount ~/.nuclei-templates as a persistent volume so templates are downloaded
# once on first use and reused on subsequent runs. -ut keeps them up to date.

import json as _json

from tools.base import Tool


def _parse(stdout: str, stderr: str) -> list[dict]:
    """Extract actionable fields from nuclei JSONL, drop verbose metadata."""
    findings: list[dict] = []
    for line in (stdout or "").strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            obj = _json.loads(line)
            info = obj.get("info", {})
            classification = info.get("classification", {})
            findings.append({
                "template":  obj.get("template-id", ""),
                "severity":  info.get("severity", ""),
                "name":      info.get("name", ""),
                "matched":   obj.get("matched-at", ""),
                "type":      obj.get("type", ""),
                "host":      obj.get("host", ""),
                "cve":       classification.get("cve-id") if classification else "",
            })
        except (_json.JSONDecodeError, AttributeError):
            continue
    return findings

# Persistent template cache on the host — shared across all nuclei runs.
_TEMPLATES_VOLUME = ("~/.nuclei-templates", "/root/nuclei-templates")


def _build_args(
    url:       str,
    templates: str = "cve,exposure,misconfig,default-login",
    flags:     str = "",
) -> list[str]:
    # -ut  : update/download templates on first use (no-op if already current)
    # -tags: filter by template metadata tags (works even after dir renames across nuclei versions)
    # -ud  : point nuclei at the mounted volume so it reads/writes templates there
    args = ["-u", url, "-jsonl", "-ut", "-ud", "/root/nuclei-templates", "-silent"]
    if templates:
        args += ["-tags", templates]
    if flags:
        args += flags.split()
    return args


TOOL = Tool(
    name            = "nuclei",
    image           = "projectdiscovery/nuclei",
    build_args      = _build_args,
    parser          = _parse,
    default_timeout = 900,   # nuclei can run long on large targets; first run downloads templates
    risk_level      = "intrusive",
    max_output      = 4_000,  # raw portion only; parser extracts structured findings separately
    extra_volumes   = [_TEMPLATES_VOLUME],
    description     = (
        "Template-based vulnerability scanner. "
        "Args: url (required), templates (comma-separated tags: cve, exposure, "
        "misconfig, default-login, takeover, tech — first run downloads templates), "
        "flags (optional, e.g. '-severity high,critical')"
    ),
)
