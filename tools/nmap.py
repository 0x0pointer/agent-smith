from __future__ import annotations

# Parser: not needed — Claude reads nmap greppable output natively.
# Raw stdout is returned directly.

from tools.base import Tool


def _build_args(host: str, ports: str = "top-1000", flags: str = "") -> list[str]:
    # --open: show only open ports — drops all "filtered/closed" noise, ~10x output reduction
    args = ["-oG", "-", "--open"]
    if ports == "top-1000":
        args += ["--top-ports", "1000"]
    elif ports == "full":
        args += ["-p-"]
    else:
        args += ["-p", ports]
    if flags:
        args += flags.split()
    args.append(host)
    return args


TOOL = Tool(
    name            = "nmap",
    image           = "instrumentisto/nmap",
    build_args      = _build_args,
    default_timeout = 900,
    risk_level      = "intrusive",
    max_output      = 8_000,   # --open keeps output compact; 8K is plenty
    description     = (
        "Port scanner. "
        "Args: host (required), ports (top-1000 | full | '80,443'), flags (optional nmap flags)"
    ),
)
