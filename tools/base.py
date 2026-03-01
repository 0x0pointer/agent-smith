from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass
class Tool:
    name:            str
    image:           str
    build_args:      Callable[..., list[str]]
    parser:          Callable[[str, str], list[dict]] | None = None
    default_timeout: int  = 120
    risk_level:      str  = "intrusive"
    needs_mount:     bool = False
    description:     str  = ""
    max_output:      int  = 12_000   # chars clipped before returning to Claude
