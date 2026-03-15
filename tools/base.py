from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


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
