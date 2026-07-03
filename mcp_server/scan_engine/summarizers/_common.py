"""Shared types for scan_engine summarizers.

`SummaryResult` is the common return type every per-tool summarizer produces.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SummaryResult:
    summary: str = ""
    facts: list[str] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    required: list[str] = field(default_factory=list)
    recommended: list[str] = field(default_factory=list)
