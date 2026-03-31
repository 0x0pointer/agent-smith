from __future__ import annotations

# Parser: not needed — output is one subdomain per line,
# the simplest possible format. Raw stdout is returned directly.

from tools.base import Tool


def _build_args(domain: str, flags: str = "") -> list[str]:
    args = ["-d", domain, "-silent"]
    if flags:
        args += flags.split()
    return args


TOOL = Tool(
    name            = "subfinder",
    image           = "projectdiscovery/subfinder@sha256:5e62f2c278b6b32c957b8afd6bbefaed3e1ae0fd5b3c67a4d08eb15c65531399",
    build_args      = _build_args,
    default_timeout = 600,
    risk_level      = "safe",
    max_output      = 4_000,   # one subdomain per line; 4K covers ~130 subdomains
    description     = "Subdomain discovery. Args: domain (required), flags (optional)",
)
