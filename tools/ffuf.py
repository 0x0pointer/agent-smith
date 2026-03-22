from __future__ import annotations

# Parser: not needed — ffuf outputs JSON with -of json flag,
# which Claude reads directly. Raw stdout is returned directly.

from tools.base import Tool


def _build_args(
    url:        str,
    wordlist:   str = "/usr/share/seclists/Discovery/Web-Content/common.txt",
    extensions: str = "",
    flags:      str = "",
) -> list[str]:
    args = ["-u", f"{url}/FUZZ", "-w", wordlist, "-of", "json", "-o", "/dev/stdout", "-s",
            "-rate", "50"]  # 50 req/s — avoid DoS on target
    if extensions:
        args += ["-e", extensions]
    if flags:
        args += flags.split()
    return args


TOOL = Tool(
    name            = "ffuf",
    image           = "ghcr.io/ffuf/ffuf",
    build_args      = _build_args,
    default_timeout = 14400,  # 4 hours — rate-limited at 50 req/s
    risk_level      = "intrusive",
    max_output      = 8_000,   # matched paths only (JSON); tail-biased clip keeps last results
    description     = (
        "Web directory/file fuzzer. "
        "Args: url (required), wordlist (container path), "
        "extensions (e.g. .php,.html,.bak), flags (e.g. '-mc 200,301 -fc 404')"
    ),
)
