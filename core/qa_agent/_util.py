"""QA agent — shared pure helpers (no package state, safe to import anywhere)."""
from __future__ import annotations

from datetime import datetime


def _ts_age_secs(ts: str, now: datetime) -> float:
    try:
        return (now - datetime.fromisoformat(ts)).total_seconds()
    except Exception:
        return 0.0
