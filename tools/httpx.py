from __future__ import annotations

# Parser: not needed — httpx outputs JSON lines with -json flag,
# which Claude reads directly without a translation layer.
# Raw stdout is returned directly.

from tools.base import Tool


def _build_args(url: str, flags: str = "") -> list[str]:
    args = [
        "-u", url,
        "-json", "-title", "-tech-detect",
        "-status-code", "-content-length", "-server",
        "-follow-redirects",
    ]
    if flags:
        args += flags.split()
    return args


TOOL = Tool(
    name            = "httpx",
    image           = "projectdiscovery/httpx",
    build_args      = _build_args,
    default_timeout = 300,
    risk_level      = "safe",
    max_output      = 6_000,   # one JSON line per URL; 6K covers ~30 URLs comfortably
    description     = (
        "HTTP probe — detects status code, title, tech stack, web server. "
        "Args: url (required), flags (optional)"
    ),
)
