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
    # Build context (dir with a Dockerfile) for a CUSTOM image that has no registry
    # to pull from. When set and `image` is absent locally, the runner builds it
    # from here on first use instead of pulling (e.g. pentest-agent/semgrep bakes
    # in the offline rules bundle). None → pull `image` from a registry as usual.
    build_context:   str | None = None
    # Container exit codes that are "clean even with no output". A code OUTSIDE
    # this set is treated as a BROKEN scan (crash / OOM-137 / config error) ONLY
    # when the run also produced no usable output — see _format_run_result, which
    # parses FIRST so a tool that exits non-zero *because* it found issues keeps
    # its findings (issue #178). Default (0,) fits every current tool: on a clean
    # or empty run they all exit 0 (semgrep/trufflehog don't pass --error/--fail;
    # mobsfscan doesn't pass --no-fail). The parse-first rule means we don't have
    # to enumerate each tool's findings->nonzero code here; set this only to
    # whitelist a NON-zero code that a tool legitimately returns with NO output.
    ok_exit_codes:   tuple[int, ...] = (0,)
