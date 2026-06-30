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


def _tested_by_from_artifact(artifact_id: str) -> str:
    """Derive the tool name from a tool-prefixed artifact_id so artifact-backed
    closures aren't falsely flagged 'untooled' (artifact_id is the real evidence
    gate). Format: <tool>_<digits>_<hex> — e.g. 'http_request_134016_d4fd92c3'
    -> 'http_request', 'garak_134016_730a2dab' -> 'garak'."""
    if not artifact_id:
        return ""
    parts = artifact_id.rsplit("_", 2)
    return parts[0] if len(parts) == 3 else artifact_id


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

        # Endpoint-level cells (CORS, CSRF, headers, etc.). AI endpoints also
        # get the endpoint-level LLM weakness cells (RAG poisoning, embedding
        # manipulation) which apply per-endpoint rather than per-param.
        endpoint_level_types = list(_APPLICABILITY["endpoint/default"])
        if classify_endpoint(path) == "ai-redteam":
            endpoint_level_types += _APPLICABILITY.get("llm_endpoint/default", [])
        for inj_type in endpoint_level_types:
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
                # Artifact-reuse block: a single request can't legitimately test
                # multiple distinct injection types — see _validate_artifact_reuse.
                from core.coverage.validation import _validate_artifact_reuse
                reuse_reject = _validate_artifact_reuse(artifact_id, status, cell, data["matrix"])
                if reuse_reject:
                    return reuse_reject
                warning = _integrity_warning_for_status(
                    cell_id, cell["status"], status,
                    cell.get("injection_type", ""), notes,
                )
                cell["status"]      = status
                cell["notes"]       = notes
                cell["tested_by"]   = tested_by or _tested_by_from_artifact(artifact_id)
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
    cell["tested_by"]   = upd.get("tested_by") or _tested_by_from_artifact(upd.get("artifact_id", ""))
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
                # Artifact-reuse block. Pre-apply the in-flight cell's artifact_id
                # onto its matrix entry so updates later in THIS batch citing the
                # same artifact see prior closures and get rejected accordingly.
                from core.coverage.validation import _validate_artifact_reuse
                reuse_reject = _validate_artifact_reuse(
                    upd.get("artifact_id", ""), st, cell_map[cid], data["matrix"],
                )
                if reuse_reject:
                    warnings.append(f"REJECTED cell {cid}: {reuse_reject}")
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


# Injection-type test priority for the focused batch — high-signal types first
# (mirrors the planner's ordering in scan_engine/planner.py).
_BATCH_INJECTION_PRIORITY = [
    "sqli", "xss", "ssti", "cmdi", "ssrf", "xxe", "nosqli", "idor",
    "traversal", "crlf", "mass_assignment", "prototype", "redirect",
]


def _endpoint_closed_count(matrix: list, endpoint_id: str) -> int:
    return sum(1 for c in matrix
              if c.get("endpoint_id") == endpoint_id and c.get("status") in _cov.ADDRESSED_STATUSES)


def _choose_focus_endpoint(pending: list, matrix: list, ep_order: dict) -> str:
    """Pick the endpoint to focus on: one already started (has a closed or
    in_progress cell) before opening new ground, tie-broken by registration order."""
    candidates = list({c["endpoint_id"] for c in pending})

    def _started(eid: str) -> bool:
        if _endpoint_closed_count(matrix, eid) > 0:
            return True
        return any(c["endpoint_id"] == eid and c["status"] == "in_progress" for c in pending)

    candidates.sort(key=lambda eid: (0 if _started(eid) else 1, ep_order.get(eid, 1 << 30)))
    return candidates[0]


def select_next_batch(data: dict, count: int = 10, endpoint_id: str | None = None) -> dict:
    """Pure (no-I/O) focused-batch selection over a loaded matrix dict.

    Groups by endpoint (finish one before opening the next), orders by
    high-signal injection type, and returns per-endpoint + overall progress so
    testing is a paced step-by-step loop instead of navigating 700+ cells solo.

    Returns ``{batch, endpoint_focus, progress:{endpoint, overall}, remaining}``;
    each batch cell carries the context to test+close it. Sync so the (sync)
    scan-engine planner can reuse it; ``get_next_batch`` is the async wrapper.
    The mcp_server layer enriches each cell with a concrete test request.
    """
    matrix = data.get("matrix", [])
    endpoints_by_id = {ep["id"]: ep for ep in data.get("endpoints", [])}
    ep_order = {ep["id"]: i for i, ep in enumerate(data.get("endpoints", []))}

    overall_total = len(matrix)
    overall_closed = sum(1 for c in matrix if c.get("status") in _cov.ADDRESSED_STATUSES)
    pending = [c for c in matrix if c.get("status") in ("pending", "in_progress")]

    if not pending:
        return {"batch": [], "endpoint_focus": None, "remaining": 0,
                "progress": {"endpoint": "0/0", "overall": f"{overall_closed}/{overall_total}"}}

    focus_id = endpoint_id or _choose_focus_endpoint(pending, matrix, ep_order)
    ep = endpoints_by_id.get(focus_id, {})

    def _prio(cell: dict) -> int:
        it = cell.get("injection_type", "")
        return _BATCH_INJECTION_PRIORITY.index(it) if it in _BATCH_INJECTION_PRIORITY else len(_BATCH_INJECTION_PRIORITY)

    focus_pending = sorted((c for c in pending if c["endpoint_id"] == focus_id), key=_prio)
    chosen = focus_pending[:max(1, count)]

    ep_total = sum(1 for c in matrix if c.get("endpoint_id") == focus_id)
    ep_closed = _endpoint_closed_count(matrix, focus_id)

    batch = [{
        "cell_id":        c.get("id"),
        "endpoint_id":    focus_id,
        "endpoint_path":  ep.get("path"),
        "method":         ep.get("method"),
        "param":          c.get("param"),
        "param_type":     c.get("param_type"),
        "injection_type": c.get("injection_type"),
        "auth_context":   ep.get("auth_context"),
    } for c in chosen]

    return {
        "batch": batch,
        "endpoint_focus": {"endpoint_id": focus_id, "path": ep.get("path"), "method": ep.get("method")},
        "progress": {"endpoint": f"{ep_closed}/{ep_total}", "overall": f"{overall_closed}/{overall_total}"},
        "remaining": len(pending),
    }


async def get_next_batch(count: int = 10, endpoint_id: str | None = None) -> dict:
    """Async wrapper around ``select_next_batch`` — loads the matrix under lock."""
    async with _cov._lock:
        data = _cov._load()
    return select_next_batch(data, count, endpoint_id)


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
