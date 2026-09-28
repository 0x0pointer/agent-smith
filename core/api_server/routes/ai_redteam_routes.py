"""AI red-team read API — feeds the dashboard's AI Red Team tab.

Serves the AI-specific store (garak attack-success rates, filter-bypass map,
calibration status, feedback-attack transcripts). The OWASP coverage grid and
per-finding k/N are derived client-side from /api/coverage and /api/findings.
"""
from __future__ import annotations

from fastapi.responses import JSONResponse

from ._common import router


@router.get("/api/ai-redteam")
async def api_ai_redteam() -> JSONResponse:
    from core import ai_redteam
    data = ai_redteam.get()
    # Live toolchain readiness (engines + garak + MCP tools) — cached in the store.
    try:
        data["readiness"] = ai_redteam.toolchain_status()
    except Exception:
        data["readiness"] = None
    try:
        data["taxonomy"] = ai_redteam.taxonomy_overview()
    except Exception:
        data["taxonomy"] = None
    return JSONResponse(data)
