from __future__ import annotations

# Parser: not needed — nuclei outputs JSON lines with -json flag,
# including severity, template-id, and matched URL. Claude reads this natively.
# Raw stdout is returned directly.

from tools.base import Tool


def _build_args(
    url:       str,
    templates: str = "default-logins,cves,exposures,misconfiguration",
    flags:     str = "",
) -> list[str]:
    args = ["-u", url, "-json", "-t", templates, "-silent"]
    if flags:
        args += flags.split()
    return args


TOOL = Tool(
    name            = "nuclei",
    image           = "projectdiscovery/nuclei",
    build_args      = _build_args,
    default_timeout = 300,
    risk_level      = "intrusive",
    max_output      = 12_000,  # each finding is ~200 chars; 12K covers ~60 findings
    description     = (
        "Template-based vulnerability scanner. "
        "Args: url (required), templates (comma-separated: cves, exposures, "
        "misconfiguration, default-logins, takeovers, technologies, dns), flags (optional)"
    ),
)
