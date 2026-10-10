"""GET /api/skill-usage — per-skill invocation counts + the advisory surface-coverage
ledger (PR-C). Consumed by the dashboard's skill-usage view (PR-E).

Response shape (per skill):
    {
      "<skill>": {
        "invocations": <int>,          # times set_skill recorded it (skill_history)
        "unit":        "<str>",        # the surface unit this skill covers (or "instance")
        "discovered":  [<instance_key>...],
        "covered":     [<instance_key>...],
        "pending":     [<instance_key>...]   # discovered − covered
      },
      ...
    }

Auth: gated by the shared ``/api/*`` bearer-token middleware (core.api_server), same
as every other /api route — no per-route auth needed. Read-only; reads session.json
via ``_api._read_json`` so it is patchable/testable exactly like the other routes."""
from __future__ import annotations

from fastapi.responses import JSONResponse

import core.api_server as _api
from core.session.surface_ledger import SKILL_UNITS

from ._common import router


def _skill_invocation_counts(session: dict) -> dict[str, int]:
    """Count how many times each skill appears in skill_history (set_skill records)."""
    counts: dict[str, int] = {}
    for entry in session.get("skill_history", []) or []:
        if isinstance(entry, dict):
            skill = entry.get("skill")
            if skill:
                counts[skill] = counts.get(skill, 0) + 1
    return counts


@router.get("/api/skill-usage")
async def api_skill_usage() -> JSONResponse:
    session = _api._read_json(_api._SESSION_FILE)
    invocations = _skill_invocation_counts(session)
    coverage = session.get("surface_coverage", {}) or {}

    # Union of skills that were invoked and skills that have a ledger entry — the
    # skills with any activity this session.
    skills = set(invocations) | {s for s in coverage if isinstance(coverage.get(s), dict)}

    out: dict[str, dict] = {}
    for skill in sorted(skills):
        entry = coverage.get(skill) if isinstance(coverage.get(skill), dict) else {}
        discovered = list(entry.get("discovered", []) or [])
        covered = list(entry.get("covered", []) or [])
        covered_set = set(covered)
        out[skill] = {
            "invocations": invocations.get(skill, 0),
            "unit": entry.get("unit") or SKILL_UNITS.get(skill, "instance"),
            "discovered": discovered,
            "covered": covered,
            "pending": [k for k in discovered if k not in covered_set],
        }
    return JSONResponse(out)
