"""
QA coverage-discipline checks — testing should be backed by registered endpoints.

The foundation of good coverage is exhaustive discovery — spider, mine JS, parse
the OpenAPI/Swagger spec, and register every endpoint (with its params) into the
matrix — then test each cell. ``_check_unregistered_findings`` catches the
inversion of that order: findings filed against endpoints that were never
registered.

This used to fire a high-priority steering directive saying "STOP opening new
ground" and become a hard completion blocker. That actively suppressed creative
exploration — a finding on an endpoint the model discovered by ad-hoc probing
(which is exactly what produced the deepest, most valuable bugs historically)
would freeze the scan until the model went back and "registered" everything.

The check is now an **advisory nudge**: a low-urgency, non-blocking alert that
encourages registering the endpoint after the fact, without halting the scan or
discouraging further ad-hoc exploitation. The steering directive is gone.
"""
from __future__ import annotations


def _check_unregistered_findings(findings_data: dict, coverage_data: dict) -> dict | None:
    """Nudge (no steer, no block) when findings reference endpoints absent from the matrix."""
    from core.coverage import unregistered_finding_paths

    paths = unregistered_finding_paths(findings_data, coverage_data)
    if not paths:
        return None

    sample = ", ".join(paths[:5]) + (" ..." if len(paths) > 5 else "")

    return {
        "code": "DISCOVERY_GAP", "urgency": "low", "blocking": False,
        "message": (
            f"Advisory: {len(paths)} finding(s) reference endpoint(s) not registered in the "
            f"coverage matrix ({sample}). Adding them after the fact via "
            "report(action='coverage', type='endpoint') keeps the matrix complete, but does "
            "not block completion — the finding stands on its own evidence."
        ),
    }
