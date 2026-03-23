from __future__ import annotations

# Parser: not needed — output is host:port per line, trivially readable.
# Raw stdout is returned directly.

from tools.base import Tool


def _build_args(host: str, ports: str = "top-100", flags: str = "") -> list[str]:
    args = ["-host", host, "-json"]
    if ports.startswith("top-"):
        args += ["-top-ports", ports.split("-", 1)[1]]
    elif ports == "full":
        args += ["-p", "-"]
    else:
        args += ["-p", ports]
    if flags:
        args += flags.split()
    return args


TOOL = Tool(
    name            = "naabu",
    image           = "projectdiscovery/naabu",
    build_args      = _build_args,
    default_timeout = 600,
    risk_level      = "intrusive",
    max_output      = 4_000,   # one "host:port" line per open port — very compact
    description     = (
        "Fast port scanner. "
        "Args: host (required), ports (top-100 | full | '1-10000'), flags (optional)"
    ),
)
