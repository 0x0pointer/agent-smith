from __future__ import annotations

# Parser: not needed — Claude reads nmap greppable output natively.
# Raw stdout is returned directly.

from tools.base import Tool


def _build_args(host: str, ports: str = "top-1000", flags: str = "") -> list[str]:
    # --open: show only open ports — drops all "filtered/closed" noise, ~10x output reduction
    args = ["-oG", "-", "--open"]
    if ports == "top-1000":
        args += ["--top-ports", "1000"]
    elif ports == "full":                      # every TCP port (1-65535) — the deep pass
        args += ["-p-"]
    elif ports == "udp":                        # UDP top-100 — SNMP/DNS/NTP/NetBIOS/TFTP/IKE/…
        args += ["-sU", "--top-ports", "100"]
    elif ports == "udp-full":                   # every UDP port (slow — opt-in)
        args += ["-sU", "-p-"]
    else:
        args += ["-p", ports]
    if flags:
        args += flags.split()
    args.append(host)
    return args


TOOL = Tool(
    name            = "nmap",
    cap_add         = ["NET_RAW", "NET_ADMIN"],   # raw-socket scans under --cap-drop=ALL (AS-13)
    image           = "instrumentisto/nmap@sha256:96f6ed194519b62421a1a1c57809e65a7f94d2aa1c8c25676f247e5e148c0827",
    build_args      = _build_args,
    default_timeout = 1800,   # full (-p-) and UDP scans are far slower than a top-ports sweep
    risk_level      = "intrusive",
    max_output      = 8_000,   # --open keeps output compact; 8K is plenty
    description     = (
        "Port scanner. "
        "Args: host (required), ports (top-1000 | full | udp | udp-full | '80,443'), "
        "flags (optional nmap flags). Use full for the all-TCP-ports deep pass and "
        "udp for the UDP top-100 — a top-ports sweep alone misses high-port and UDP services."
    ),
)
