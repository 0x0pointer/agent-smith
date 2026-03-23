"""
Coverage matrix store
=====================
Thread-safe read/write of coverage_matrix.json.

Tracks every (endpoint × param × injection type) cell so the agent
systematically tests all applicable combinations instead of hoping it
remembers to circle back.

Schema
------
{
  "meta":      { "created": "<ISO>", "target": "", "total_cells": 0,
                 "tested": 0, "vulnerable": 0, "not_applicable": 0, "skipped": 0 },
  "endpoints": [ { id, path, method, params, discovered_by, discovered_at, auth_context } ],
  "matrix":    [ { id, endpoint_id, param, param_type, injection_type,
                   status, notes, finding_id, tested_at } ]
}

Used by mcp_server/report_tools.py (coverage action) and session_tools.py.
"""
from __future__ import annotations

import asyncio
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

COVERAGE_FILE = Path(__file__).parent.parent / "coverage_matrix.json"

_lock = asyncio.Lock()


# ---------------------------------------------------------------------------
# Applicability rules — which injection types apply to each param type
# ---------------------------------------------------------------------------

_APPLICABILITY: dict[str, list[str]] = {
    # param_type/value_hint
    "path/integer":      ["sqli", "idor", "traversal"],
    "path/string":       ["sqli", "xss", "ssti", "traversal", "cmdi", "idor"],
    "query/default":     ["sqli", "xss", "ssti", "ssrf", "cmdi", "traversal", "redirect", "nosqli", "crlf"],
    "body_form/default": ["sqli", "xss", "ssti", "ssrf", "cmdi", "xxe", "nosqli"],
    "body_json/default": ["nosqli", "prototype", "mass_assignment", "sqli"],
    "header/default":    ["crlf", "xss", "ssrf", "smuggling"],
    "cookie/default":    ["sqli", "xss", "deserial"],
    "endpoint/default":  ["cors", "csrf", "security_headers", "rate_limit", "method_tampering", "cache", "jwt", "race"],
}

# Fallback: if no specific hint matches, use param_type/default
_FALLBACK_KEY = "{type}/default"


# ---------------------------------------------------------------------------
# Internal I/O
# ---------------------------------------------------------------------------

def _load() -> dict:
    if COVERAGE_FILE.exists():
        try:
            return json.loads(COVERAGE_FILE.read_text())
        except Exception:
            pass
    return {
        "meta": {
            "created": datetime.now(timezone.utc).isoformat(),
            "target": "",
            "total_cells": 0,
            "tested": 0,
            "vulnerable": 0,
            "not_applicable": 0,
            "skipped": 0,
        },
        "endpoints": [],
        "matrix": [],
    }


def _save(data: dict) -> None:
    COVERAGE_FILE.write_text(json.dumps(data, indent=2))


def _recount(data: dict) -> None:
    """Recompute meta counters from the matrix."""
    cells = data["matrix"]
    data["meta"]["total_cells"] = len(cells)
    data["meta"]["tested"] = sum(1 for c in cells if c["status"] in ("tested_clean", "vulnerable"))
    data["meta"]["in_progress"] = sum(1 for c in cells if c["status"] == "in_progress")
    data["meta"]["vulnerable"] = sum(1 for c in cells if c["status"] == "vulnerable")
    data["meta"]["not_applicable"] = sum(1 for c in cells if c["status"] == "not_applicable")
    data["meta"]["skipped"] = sum(1 for c in cells if c["status"] == "skipped")


def _normalize_path(path: str) -> str:
    """Collapse numeric/uuid segments to placeholders for dedup.

    /profile/1  → /profile/{id}
    /profile/2  → /profile/{id}
    /api/users/550e8400-e29b-41d4-a716-446655440000 → /api/users/{id}
    """
    # UUID segments
    path = re.sub(
        r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        '/{id}', path, flags=re.IGNORECASE,
    )
    # Pure numeric segments
    path = re.sub(r'/\d+', '/{id}', path)
    return path


def _applicable_types(param_type: str, value_hint: str) -> list[str]:
    """Return list of injection types applicable to a param."""
    key = f"{param_type}/{value_hint}" if value_hint else f"{param_type}/default"
    if key in _APPLICABILITY:
        return list(_APPLICABILITY[key])
    fallback = f"{param_type}/default"
    return list(_APPLICABILITY.get(fallback, _APPLICABILITY["query/default"]))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def add_endpoint(
    path: str,
    method: str,
    params: list[dict],
    discovered_by: str = "spider",
    auth_context: str = "none",
) -> dict:
    """Register an endpoint and auto-generate matrix cells.

    params: [{"name": "id", "type": "path", "value_hint": "integer"}, ...]

    Returns {"endpoint_id": ..., "new_cells": N, "dedup": bool}.
    """
    norm_path = _normalize_path(path)
    method_upper = method.upper()

    async with _lock:
        data = _load()

        # Dedup on (normalized_path, method)
        for ep in data["endpoints"]:
            if ep["_normalized"] == norm_path and ep["method"] == method_upper:
                return {"endpoint_id": ep["id"], "new_cells": 0, "dedup": True}

        ep_id = f"ep-{uuid.uuid4().hex[:12]}"
        endpoint = {
            "id": ep_id,
            "path": path,
            "_normalized": norm_path,
            "method": method_upper,
            "params": params,
            "discovered_by": discovered_by,
            "discovered_at": datetime.now(timezone.utc).isoformat(),
            "auth_context": auth_context,
        }
        data["endpoints"].append(endpoint)

        # Auto-generate matrix cells
        new_cells = 0

        # Per-parameter cells
        for param in params:
            p_name = param.get("name", "")
            p_type = param.get("type", "query")
            p_hint = param.get("value_hint", "")
            for inj_type in _applicable_types(p_type, p_hint):
                cell = {
                    "id": f"cell-{uuid.uuid4().hex[:12]}",
                    "endpoint_id": ep_id,
                    "param": p_name,
                    "param_type": p_type,
                    "injection_type": inj_type,
                    "status": "pending",
                    "notes": "",
                    "finding_id": None,
                    "tested_at": None,
                }
                data["matrix"].append(cell)
                new_cells += 1

        # Endpoint-level cells (CORS, CSRF, headers, etc.)
        for inj_type in _APPLICABILITY["endpoint/default"]:
            cell = {
                "id": f"cell-{uuid.uuid4().hex[:12]}",
                "endpoint_id": ep_id,
                "param": "_endpoint",
                "param_type": "endpoint",
                "injection_type": inj_type,
                "status": "pending",
                "notes": "",
                "finding_id": None,
                "tested_at": None,
            }
            data["matrix"].append(cell)
            new_cells += 1

        _recount(data)
        _save(data)

    return {"endpoint_id": ep_id, "new_cells": new_cells, "dedup": False}


async def update_cell(
    cell_id: str,
    status: str,
    notes: str = "",
    finding_id: str | None = None,
) -> bool:
    """Update a single matrix cell. Returns True if found and updated."""
    valid = {"pending", "in_progress", "tested_clean", "vulnerable", "not_applicable", "skipped"}
    if status not in valid:
        return False
    async with _lock:
        data = _load()
        for cell in data["matrix"]:
            if cell["id"] == cell_id:
                cell["status"] = status
                cell["notes"] = notes
                if finding_id:
                    cell["finding_id"] = finding_id
                cell["tested_at"] = datetime.now(timezone.utc).isoformat()
                _recount(data)
                _save(data)
                return True
    return False


async def bulk_update(updates: list[dict]) -> int:
    """Update multiple cells. Each update: {cell_id, status, notes?, finding_id?}.

    Returns count of successfully updated cells.
    """
    valid = {"pending", "in_progress", "tested_clean", "vulnerable", "not_applicable", "skipped"}
    async with _lock:
        data = _load()
        cell_map = {c["id"]: c for c in data["matrix"]}
        count = 0
        for upd in updates:
            cid = upd.get("cell_id", "")
            st = upd.get("status", "")
            if st not in valid or cid not in cell_map:
                continue
            cell = cell_map[cid]
            cell["status"] = st
            cell["notes"] = upd.get("notes", "")
            if upd.get("finding_id"):
                cell["finding_id"] = upd["finding_id"]
            cell["tested_at"] = datetime.now(timezone.utc).isoformat()
            count += 1
        _recount(data)
        _save(data)
    return count


def get_matrix() -> dict:
    """Synchronous read for API server."""
    return _load()


async def get_pending(endpoint_id: str | None = None) -> list[dict]:
    """Return pending and in_progress cells, optionally filtered by endpoint."""
    async with _lock:
        data = _load()
    cells = [c for c in data["matrix"] if c["status"] in ("pending", "in_progress")]
    if endpoint_id:
        cells = [c for c in cells if c["endpoint_id"] == endpoint_id]
    return cells


async def reset() -> None:
    """Clear the entire coverage matrix."""
    async with _lock:
        _save({
            "meta": {
                "created": datetime.now(timezone.utc).isoformat(),
                "target": "",
                "total_cells": 0,
                "tested": 0,
                "vulnerable": 0,
                "not_applicable": 0,
                "skipped": 0,
            },
            "endpoints": [],
            "matrix": [],
        })
