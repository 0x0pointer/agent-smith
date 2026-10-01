from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

# Prefix that marks a tool result as a BROKEN scan (non-ok container exit, or a
# timeout, or a missing-codebase mount). wrap() detects this prefix and emits a
# failure envelope (anomaly + warning) instead of letting a tool-specific
# summarizer silently render it as a clean "0 results" — issue #178. Using a
# NUL-delimited sentinel (not plain "[...]") so it can't collide with, or be
# swallowed by, summarizers that drop "["-prefixed / non-JSON lines (net.py).
SCAN_FAILED_SENTINEL = "\x00SCAN_FAILED\x00"


@dataclass
class Tool:
    name:            str
    image:           str
    build_args:      Callable[..., list[str]]
    parser:          Callable[[str, str], list[dict]] | None = None
    default_timeout: int  = 600
    risk_level:      str  = "intrusive"
    needs_mount:     bool = False
    description:     str  = ""
    max_output:      int  = 12_000   # chars clipped before returning to Claude
    # Extra volume mounts: list of (host_path, container_path) tuples
    extra_volumes:   list[tuple[str, str]] = field(default_factory=list)
    # Host env vars to forward into the container (e.g. API keys)
    forward_env:     list[str] = field(default_factory=list)
    # Container network mode (AS-13): "host" (default — target-probing tools),
    # "bridge", or "none" (untrusted-code analyzers that need no network at all).
    network:         str  = "host"
    # Capabilities to add back after the runner's --cap-drop=ALL (e.g. NET_RAW so
    # raw-socket scanners still work under the hardened default).
    cap_add:         list[str] = field(default_factory=list)
    # Container exit codes that mean "the scan RAN" (clean OR with findings).
    # Any OTHER exit code is a BROKEN scan (crash / OOM-137 / config error) and
    # is surfaced as a failure envelope rather than reported as empty/clean
    # (issue #178). Default (0,) is correct for every current tool — verified:
    #   semgrep   : 0 even with findings (no --error); real errors are >=2
    #   trufflehog: 0 even with secrets (no --fail); 183 only if --fail is added
    #   nuclei/httpx/naabu/nmap/subfinder/mobsfscan: 0 on success incl. findings
    #     (mobsfscan would exit 1 on findings only with --exit-warning, unused)
    # A tool that is ever invoked with a findings->nonzero flag must widen this.
    ok_exit_codes:   tuple[int, ...] = (0,)
