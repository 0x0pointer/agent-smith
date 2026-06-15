"""
Coverage matrix — public operations.

Endpoint registration, cell updates (single + bulk), and the read/query
primitives. All mutations take ``core.coverage._lock`` and persist through
``core.coverage._save``; reads go through ``core.coverage._load``. Those are
reached via ``import core.coverage as _cov`` so the lock and file path stay
patchable from the package namespace.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import core.coverage as _cov
from .classify import _APPLICABILITY, _applicable_types, _normalize_path, classify_endpoint
from .validation import (
    _integrity_warning_for_status,
    _validate_artifact,
    _validate_auth_response,
    _validate_finding_link,
)


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

    async with _cov._lock:
        data = _cov._load()

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
                    "tested_by": "",
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
                "tested_by": "",
            }
            data["matrix"].append(cell)
            new_cells += 1

        _cov._recount(data)
        _cov._save(data)

    # Open a mandatory gate for high-value endpoint types (outside the lock — pure session state)
    ep_type = classify_endpoint(path)
    if ep_type:
        from core.session import open_trigger_gate
        open_trigger_gate(ep_type, path)

    return {"endpoint_id": ep_id, "new_cells": new_cells, "dedup": False}


async def update_cell(
    cell_id: str,
    status: str,
    notes: str = "",
    finding_id: str | None = None,
    tested_by: str = "",
    artifact_id: str = "",
) -> bool | str:
    """Update a single matrix cell.

    Returns True if updated, False if cell not found, or a rejection/warning string.

    Hard rules:
    - tested_clean / vulnerable require a real artifact_id that exists on disk.
    - The legacy tested_by field is still stored for human-readable context but
      is no longer the enforcement mechanism — artifact_id is.
    """
    valid = {"pending", "in_progress", "tested_clean", "vulnerable", "not_applicable", "skipped"}
    if status not in valid:
        return False
    rejection = _validate_artifact(artifact_id, status)
    if rejection:
        return rejection
    # Vulnerable closures require an existing finding_id — Smith must call
    # report(action='finding') first. Auto-filing on Smith's behalf produced
    # per-cell-granularity duplicates that polluted the export.
    link_reject = _validate_finding_link(status, finding_id)
    if link_reject:
        return link_reject

    async with _cov._lock:
        data = _cov._load()
        for cell in data["matrix"]:
            if cell["id"] == cell_id:
                # Auth-failure block: a 401/403 on an injection cell is not clean,
                # it's untested. Force Smith to authenticate and retry.
                auth_reject = _validate_auth_response(artifact_id, status, cell)
                if auth_reject:
                    return auth_reject
                warning = _integrity_warning_for_status(
                    cell_id, cell["status"], status,
                    cell.get("injection_type", ""), notes,
                )
                cell["status"]      = status
                cell["notes"]       = notes
                cell["tested_by"]   = tested_by
                cell["artifact_id"] = artifact_id
                if finding_id:
                    cell["finding_id"] = finding_id
                cell["tested_at"] = datetime.now(timezone.utc).isoformat()
                _cov._recount(data)
                _cov._save(data)
                return warning if warning else True
    return False


def _apply_bulk_cell(cell: dict, upd: dict, warnings: list[str]) -> None:
    """Apply one bulk-update entry to a cell in-place, appending any warnings.

    Caller is expected to have already vetted the (artifact, auth, finding-link)
    gates in bulk_update — this only handles the mutation + integrity warning.
    """
    st = upd.get("status", "")
    notes_text = upd.get("notes", "")
    warning = _integrity_warning_for_status(
        cell["id"], cell["status"], st,
        cell.get("injection_type", ""), notes_text,
    )
    if warning:
        warnings.append(warning)
    cell["status"]      = st
    cell["notes"]       = notes_text
    cell["tested_by"]   = upd.get("tested_by", "")
    cell["artifact_id"] = upd.get("artifact_id", "")
    if upd.get("finding_id"):
        cell["finding_id"] = upd["finding_id"]
    cell["tested_at"] = datetime.now(timezone.utc).isoformat()


async def bulk_update(updates: list[dict]) -> dict:
    """Update multiple cells.

    Each update: {cell_id, status, notes?, finding_id?, tested_by?, artifact_id?}.
    Returns {"updated": N, "rejected": N, "warnings": [str]}.

    Hard rules (reject without applying):
    - tested_clean or vulnerable requires artifact_id that exists on disk.
    """
    valid = {"pending", "in_progress", "tested_clean", "vulnerable", "not_applicable", "skipped"}
    _TESTED_FINAL = {"tested_clean", "vulnerable"}

    async with _cov._lock:
        data = _cov._load()
        cell_map = {c["id"]: c for c in data["matrix"]}
        count = 0
        rejected = 0
        warnings: list[str] = []
        for upd in updates:
            cid = upd.get("cell_id", "")
            st  = upd.get("status", "")
            if st not in valid or cid not in cell_map:
                continue
            if st in _TESTED_FINAL:
                rejection = _validate_artifact(upd.get("artifact_id", ""), st)
                if rejection:
                    warnings.append(f"REJECTED cell {cid}: {rejection}")
                    rejected += 1
                    continue
                auth_reject = _validate_auth_response(
                    upd.get("artifact_id", ""), st, cell_map[cid],
                )
                if auth_reject:
                    warnings.append(f"REJECTED cell {cid}: {auth_reject}")
                    rejected += 1
                    continue
                # Vulnerable cells must already have a finding_id — force Smith
                # to call report(action='finding') first instead of auto-filing.
                link_reject = _validate_finding_link(st, upd.get("finding_id", ""))
                if link_reject:
                    warnings.append(f"REJECTED cell {cid}: {link_reject}")
                    rejected += 1
                    continue
            _apply_bulk_cell(cell_map[cid], upd, warnings)
            count += 1
        _cov._recount(data)
        _cov._save(data)
    return {"updated": count, "rejected": rejected, "warnings": warnings}


def get_matrix() -> dict:
    """Synchronous read for API server."""
    return _cov._load()


async def get_pending(endpoint_id: str | None = None) -> list[dict]:
    """Return pending and in_progress cells, optionally filtered by endpoint."""
    async with _cov._lock:
        data = _cov._load()
    cells = [c for c in data["matrix"] if c["status"] in ("pending", "in_progress")]
    if endpoint_id:
        cells = [c for c in cells if c["endpoint_id"] == endpoint_id]
    return cells


async def list_cells(
    endpoint_path: str | None = None,
    method:        str | None = None,
    status:        str | None = None,
    injection_type:str | None = None,
    param_name:    str | None = None,
    limit:         int        = 200,
) -> dict:
    """Compaction-recovery primitive: return cells with joined endpoint
    context so Smith can rebuild its mental model after context reset.

    Smith's context window can be compacted mid-scan, dropping the cell IDs
    it was carrying. Without a read-back API the only options are (a) re-
    register endpoints (creates duplicates) or (b) guess. This function
    lets Smith fetch the current matrix state and find the cell ID it
    needs by matching against (endpoint_path, method, param_name,
    injection_type).

    Filters are AND-combined. Substring matching on endpoint_path and
    param_name (case-insensitive); exact match on method, status, and
    injection_type. ``limit`` caps the response size — set high for a
    full rebuild, low for a targeted lookup.

    Returns ``{"cells": [...], "total": N, "filtered": M}`` where:
      - cells is the slice of matching cells (each with endpoint context)
      - total is the matrix-wide cell count (for sanity)
      - filtered is the count after filters BEFORE limit truncation
    """
    async with _cov._lock:
        data = _cov._load()

    endpoints_by_id = {ep["id"]: ep for ep in data.get("endpoints", [])}
    all_cells = data.get("matrix", [])

    def _matches(cell: dict) -> bool:
        ep = endpoints_by_id.get(cell.get("endpoint_id"), {})
        if endpoint_path and endpoint_path.lower() not in (ep.get("path") or "").lower():
            return False
        if method and method.upper() != (ep.get("method") or "").upper():
            return False
        if status and status != cell.get("status"):
            return False
        if injection_type and injection_type != cell.get("injection_type"):
            return False
        if param_name and param_name.lower() not in (cell.get("param") or "").lower():
            return False
        return True

    matched = [c for c in all_cells if _matches(c)]

    # Project each cell with its endpoint context so Smith doesn't have to
    # cross-reference two lists. Keep response shape stable: same keys for
    # every cell, null for fields that aren't set.
    out = []
    for cell in matched[:max(0, limit)]:
        ep = endpoints_by_id.get(cell.get("endpoint_id"), {})
        out.append({
            "cell_id":         cell.get("id"),
            "endpoint_path":   ep.get("path"),
            "method":          ep.get("method"),
            "param_name":      cell.get("param"),
            "param_type":      cell.get("param_type"),
            "injection_type":  cell.get("injection_type"),
            "status":          cell.get("status"),
            "finding_id":      cell.get("finding_id"),
            "tested_by":       cell.get("tested_by"),
            "tested_at":       cell.get("tested_at"),
            "auth_context":    ep.get("auth_context"),
            "notes":           cell.get("notes"),
        })

    return {"cells": out, "total": len(all_cells), "filtered": len(matched)}


async def reset() -> None:
    """Clear the entire coverage matrix."""
    async with _cov._lock:
        _cov._save({
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
