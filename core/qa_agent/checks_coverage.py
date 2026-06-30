"""
QA coverage-discipline checks — testing must not outrun discovery.

The foundation of good coverage is exhaustive discovery FIRST: spider, mine JS,
parse the OpenAPI/Swagger spec, and register every endpoint (with its params)
into the matrix — then test each cell. ``_check_unregistered_findings`` catches
the inversion of that order: findings filed against endpoints that were never
registered. That is a source-agnostic signal that recon was skipped, regardless
of how the endpoint was discovered (spider, JS, or spec).

It fires an early steering directive (register the full surface before testing
more) and returns a high-urgency blocking alert, which ``_qa_blockers`` in
session_tools turns into a hard completion block.
"""
from __future__ import annotations

import core.qa_agent as _qa


def _check_unregistered_findings(findings_data: dict, coverage_data: dict) -> dict | None:
    """Block/steer when findings reference endpoints absent from the matrix."""
    from core.coverage import unregistered_finding_paths

    paths = unregistered_finding_paths(findings_data, coverage_data)
    if not paths:
        return None

    sample = ", ".join(paths[:5]) + (" ..." if len(paths) > 5 else "")

    # Active steer once the gap is unambiguous (>=3 unregistered endpoints): tell
    # the agent to stop opening new ground and finish registration first.
    if len(paths) >= 3 and not _qa._has_pending_directives():
        from core.steering import RESUME_TESTING, steering_queue
        steering_queue.add_directive(
            code=RESUME_TESTING,
            message=(
                f"DISCOVERY GAP — you filed findings on {len(paths)} endpoint(s) that are NOT in the "
                f"coverage matrix ({sample}). Recon was not finished before testing started. STOP opening "
                "new ground. First register the FULL attack surface — every spider result, every operation "
                "in the OpenAPI/Swagger spec, and JS-mined routes — each via "
                "report(action='coverage', type='endpoint') WITH its params (query/body/path). The coverage "
                "matrix is your test plan: build it completely, then test each cell and cite the artifact_id."
            ),
            priority="high", skill=None, trigger="DISCOVERY_GAP",
        )

    return {
        "code": "DISCOVERY_GAP", "urgency": "high", "blocking": True,
        "message": (
            f"Discovery gap: {len(paths)} endpoint(s) have findings but were never registered in the "
            f"coverage matrix ({sample}). Register the full attack surface (spider + API spec + JS routes) "
            "with params before completing — the matrix must reflect what you actually tested."
        ),
    }
