from __future__ import annotations

# Parser: not needed — nuclei outputs JSON lines with -jsonl flag,
# including severity, template-id, and matched URL. Claude reads this natively.
# Raw stdout is returned directly.
#
# Templates note: projectdiscovery/nuclei v3 does NOT bundle templates in the image.
# We mount ~/.nuclei-templates as a persistent volume so templates are downloaded
# once on first use and reused on subsequent runs. -ut keeps them up to date.

from tools.base import Tool

# Persistent template cache on the host — shared across all nuclei runs.
_TEMPLATES_VOLUME = ("~/.nuclei-templates", "/root/nuclei-templates")


def _build_args(
    url:       str,
    templates: str = "cve,exposure,misconfig,default-login",
    flags:     str = "",
) -> list[str]:
    # -ut  : update/download templates on first use (no-op if already current)
    # -tags: filter by template metadata tags (works even after dir renames across nuclei versions)
    # -home-dir: point nuclei at the mounted volume so it reads/writes templates there
    args = ["-u", url, "-jsonl", "-ut", "-home-dir", "/root", "-silent"]
    if templates:
        args += ["-tags", templates]
    if flags:
        args += flags.split()
    return args


TOOL = Tool(
    name            = "nuclei",
    image           = "projectdiscovery/nuclei",
    build_args      = _build_args,
    default_timeout = 360,   # first run downloads templates (~1–2 min extra)
    risk_level      = "intrusive",
    max_output      = 12_000,
    extra_volumes   = [_TEMPLATES_VOLUME],
    description     = (
        "Template-based vulnerability scanner. "
        "Args: url (required), templates (comma-separated tags: cve, exposure, "
        "misconfig, default-login, takeover, tech — first run downloads templates), "
        "flags (optional, e.g. '-severity high,critical')"
    ),
)
