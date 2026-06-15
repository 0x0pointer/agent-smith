"""
QA agent — anti-shortcut checks.

Catch corner-cutting on the coverage matrix: bulk N/A marking, tested cells
with no tool evidence, impossibly fast cell closures, and N/A over-use.
``_check_bulk_marking`` / ``_check_coverage_integrity`` are blocking (gate
completion); the other two inject a steering directive and warn.
"""
from __future__ import annotations

from datetime import datetime, timezone

import core.qa_agent as _qa
from ._util import _ts_age_secs


def _check_bulk_marking(entries: list[dict]) -> dict | None:
    """Block completion when >10 N/A cells have no tested_by tool."""
    cov_entries = [e for e in entries if e.get("type") == "COVERAGE"]
    if not cov_entries:
        return None
    na_untooled = cov_entries[-1].get("na_untooled", 0)
    if na_untooled <= 10:
        return None
    return {
        "code": "BULK_MARKING", "urgency": "high", "blocking": True,
        "message": f"Bulk-marking detected: {na_untooled} N/A cells have no tested_by tool — run actual tools before marking N/A",
    }


def _check_coverage_integrity(entries: list[dict]) -> dict | None:
    """Block completion when tested/vulnerable cells have no tested_by tool."""
    cov_entries = [e for e in entries if e.get("type") == "COVERAGE"]
    if not cov_entries:
        return None
    untooled = cov_entries[-1].get("untooled", 0)
    if untooled == 0:
        return None
    return {
        "code": "COVERAGE_INTEGRITY", "urgency": "high", "blocking": True,
        "message": f"Coverage integrity: {untooled} tested/vulnerable cells lack a tested_by tool — cite the artifact before closing",
    }


def _check_suspicious_speed(entries: list[dict]) -> dict | None:
    """Detect >20 coverage cells closed in <10 min — impossible at real test pace."""
    cov_entries = [e for e in entries if e.get("type") == "COVERAGE"]
    if len(cov_entries) < 2:
        return None
    now = datetime.now(timezone.utc)
    window = [
        e for e in cov_entries
        if _ts_age_secs(e.get("ts", ""), now) <= 600
    ]
    cells_closed = sum(e.get("cells_closed", 0) for e in window)
    if cells_closed <= 20:
        return None
    if not _qa._has_pending_directives():
        from core.steering import steering_queue, RESUME_TESTING
        steering_queue.add_directive(
            code=RESUME_TESTING,
            message=(
                f"STOP — {cells_closed} cells closed in under 10 min. "
                "That pace is impossible with real tool runs. "
                "Pick your last 5 closed cells and re-test them with actual scanner output. "
                "Do not close another cell until you have run a tool and can cite the artifact_id."
            ),
            priority="high", skill=None, trigger="SUSPICIOUS_SPEED",
        )
    return {
        "code": "SUSPICIOUS_SPEED", "urgency": "high", "blocking": False,
        "message": f"Speed anomaly: {cells_closed} cells closed in <10 min — re-verify with real tool runs",
    }


def _check_na_abuse(coverage_data: dict) -> dict | None:
    """Detect N/A rate >35% of addressed cells."""
    matrix = coverage_data.get("matrix", [])
    if not matrix:
        return None
    addressed = [c for c in matrix if c.get("status") not in ("pending", None, "")]
    if len(addressed) < 10:
        return None
    na_count = sum(1 for c in addressed if c.get("status") == "not_applicable")
    rate = na_count / len(addressed)
    if rate <= 0.35:
        return None
    pct = int(rate * 100)
    if not _qa._has_pending_directives():
        from core.steering import steering_queue, RESUME_TESTING
        steering_queue.add_directive(
            code=RESUME_TESTING,
            message=(
                f"N/A rate is {pct}% — too high. "
                "Pick 3 recent N/A cells and verify them with actual tools. "
                "N/A is only valid when the injection type structurally cannot apply "
                "(e.g. SSRF on a boolean param). Run a tool and cite the result before re-marking."
            ),
            priority="high", skill=None, trigger="NA_ABUSE",
        )
    return {
        "code": "NA_ABUSE", "urgency": "high", "blocking": False,
        "message": f"N/A abuse: {pct}% of addressed cells marked N/A ({na_count}/{len(addressed)}) — verify 3 recent N/A cells with tools",
    }
