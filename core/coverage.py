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
                   status, notes, finding_id, tested_at, tested_by } ]
}

Integrity rules
---------------
1. Cells that resolve to tested_clean/vulnerable MUST pass through in_progress first.
   Direct pending → tested_clean is rejected (returns a warning string instead of True).
2. Every cell tracks `tested_by` — the tool or method used for testing.
3. Marking a cell `not_applicable` for injection types with known bypass techniques
   (xxe, sqli, xss, ssti) requires the notes to mention what bypass was ruled out.
   An empty or generic note triggers a warning.

Used by mcp_server/report_tools.py (coverage action) and session_tools.py.
"""
from __future__ import annotations

import asyncio
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

COVERAGE_FILE  = (Path(__file__).parent.parent / "coverage_matrix.json").resolve()
_ARTIFACTS_DIR = (Path(__file__).parent.parent / "artifacts").resolve()

_lock = asyncio.Lock()


# ---------------------------------------------------------------------------
# Which statuses count as "addressed" for coverage percentage purposes.
# skipped is intentionally excluded — it is a deferral, not evidence of testing.
# ---------------------------------------------------------------------------

ADDRESSED_STATUSES: frozenset[str] = frozenset({"tested_clean", "vulnerable", "not_applicable"})


# ---------------------------------------------------------------------------
# Injection types that have known bypass techniques — marking these N/A
# requires the notes to explain WHY the bypass doesn't apply.
# ---------------------------------------------------------------------------

_BYPASS_REQUIRED_TYPES: dict[str, str] = {
    "xxe":  "Content-Type switching to application/xml",
    "sqli": "blind boolean/time-based, second-order, or encoding bypass",
    "xss":  "encoding bypass, DOM sinks, or stored via other endpoint",
    "ssti": "alternative template syntax (${}, <%%>, #{}, *{})",
}


# ---------------------------------------------------------------------------
# Applicability rules — which injection types apply to each param type
# ---------------------------------------------------------------------------

_APPLICABILITY: dict[str, list[str]] = {
    # param_type/value_hint
    "path/integer":      ["sqli", "idor", "traversal"],
    "path/string":       ["sqli", "xss", "ssti", "traversal", "cmdi", "idor"],
    "query/default":     ["sqli", "xss", "ssti", "ssrf", "cmdi", "traversal", "redirect", "nosqli", "crlf"],
    "body_form/default": ["sqli", "xss", "ssti", "ssrf", "cmdi", "xxe", "nosqli"],
    "body_json/default": ["sqli", "nosqli", "xss", "ssti", "ssrf", "cmdi", "prototype", "mass_assignment"],
    "header/default":    ["crlf", "xss", "ssrf", "smuggling"],
    "cookie/default":    ["sqli", "xss", "deserial"],
    "endpoint/default":  ["cors", "csrf", "security_headers", "rate_limit", "method_tampering", "cache", "jwt", "race", "bfla"],
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
    # COVERAGE_FILE is derived from __file__ at module load — it is not user-controlled.
    # Suppression below silences the false-positive S2083 path-construction rule.
    Path(COVERAGE_FILE).write_text(json.dumps(data, indent=2))  # NOSONAR


def _recount(data: dict) -> None:
    """Recompute meta counters from the matrix."""
    cells = data["matrix"]
    data["meta"]["total_cells"]    = len(cells)
    data["meta"]["tested"]         = sum(1 for c in cells if c["status"] in ("tested_clean", "vulnerable"))
    data["meta"]["in_progress"]    = sum(1 for c in cells if c["status"] == "in_progress")
    data["meta"]["vulnerable"]     = sum(1 for c in cells if c["status"] == "vulnerable")
    data["meta"]["not_applicable"] = sum(1 for c in cells if c["status"] == "not_applicable")
    data["meta"]["skipped"]        = sum(1 for c in cells if c["status"] == "skipped")
    data["meta"]["addressed"]      = sum(1 for c in cells if c["status"] in ADDRESSED_STATUSES)


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


_TYPE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'/graphql\b',                   re.IGNORECASE), "graphql"),
    (re.compile(r'/graph\b',                     re.IGNORECASE), "graphql"),
    (re.compile(r'/(?:login|logout|signin|signup|register|auth|oauth|token|sso)\b', re.IGNORECASE), "auth"),
    (re.compile(r'/admin\b',                     re.IGNORECASE), "admin"),
    (re.compile(r'/(?:upload|file|attachment|media|import)\b', re.IGNORECASE), "upload"),
    (re.compile(r'/(?:payment|invoice|checkout|billing|transaction|transfer|balance|wallet)\b', re.IGNORECASE), "financial"),
    (re.compile(r'/(?:ws|websocket|socket)\b', re.IGNORECASE), "websocket"),
    (re.compile(r'(?:/api\b|/v\d+\b)',                  re.IGNORECASE), "api"),
]


def classify_endpoint(path: str) -> str | None:
    """Return an endpoint type tag for trigger-gate routing, or None if unclassified.

    Checks path patterns in priority order; first match wins.
    """
    for pattern, tag in _TYPE_PATTERNS:
        if pattern.search(path):
            return tag
    return None


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

        _recount(data)
        _save(data)

    # Open a mandatory gate for high-value endpoint types (outside the lock — pure session state)
    ep_type = classify_endpoint(path)
    if ep_type:
        from core.session import open_trigger_gate
        open_trigger_gate(ep_type, path)

    return {"endpoint_id": ep_id, "new_cells": new_cells, "dedup": False}


def _integrity_warning_for_status(
    cell_id: str, prev_status: str, status: str, inj_type: str, notes: str
) -> str:
    """Return an integrity warning string, or empty string if no violation."""
    final_statuses = {"tested_clean", "vulnerable"}
    if status in final_statuses and prev_status not in ("in_progress", "tested_clean", "vulnerable"):
        return (
            f"INTEGRITY WARNING: cell {cell_id} went {prev_status} -> {status} "
            f"without passing through in_progress first. "
            f"This usually means the cell was bulk-marked without actually being tested. "
            f"Mark the cell in_progress BEFORE running your test tool."
        )
    return _na_bypass_warning(status, inj_type, notes)


def _na_bypass_warning(status: str, inj_type: str, notes: str) -> str:
    """Return a warning if N/A is set without bypass justification, else empty string."""
    if status != "not_applicable" or inj_type not in _BYPASS_REQUIRED_TYPES:
        return ""
    bypass_technique = _BYPASS_REQUIRED_TYPES[inj_type]
    keywords = bypass_technique.lower().split(", ")
    if any(kw in notes.lower() for kw in keywords) or len(notes) >= 40:
        return ""
    return (
        f"INTEGRITY WARNING: marking {inj_type} as N/A without explaining "
        f"why bypass techniques don't apply. For {inj_type}, you should test: "
        f"{bypass_technique}. Add this to your notes or actually test before "
        f"marking N/A."
    )


def _validate_artifact(artifact_id: str, status: str) -> str:
    """Return rejection string if artifact_id is missing or invalid, else empty string.

    Hard rules for tested_clean / vulnerable:
    1. artifact_id must be non-empty.
    2. The artifact file must exist on disk (proves the tool actually ran).
    3. The tool prefix encoded in the artifact_id must not be empty.
    """
    if status not in ("tested_clean", "vulnerable"):
        return ""
    if not artifact_id or not artifact_id.strip():
        return (
            f"REJECTED: closing a cell as '{status}' requires an artifact_id. "
            "Run the test tool first, capture the artifact_id from its response, "
            "then pass it here. Free-text tested_by is no longer accepted."
        )
    artifact_file = _ARTIFACTS_DIR / f"{artifact_id}.txt"
    if not artifact_file.exists():
        return (
            f"REJECTED: artifact_id '{artifact_id}' not found on disk. "
            "The tool must actually run and produce an artifact before the cell can close. "
            "Check that you are using the artifact_id from the tool response, not a placeholder."
        )
    return ""


# Injection cell types where 401/403 is meaningless evidence of cleanliness —
# the test payload was never evaluated because auth blocked the request first.
# Excluded: auth/access-control cell types where 401/403 IS the finding signal.
_AUTH_GATED_TYPES = {
    "sqli", "nosqli", "xss", "ssti", "cmdi", "ssrf", "xxe",
    "traversal", "crlf", "prototype", "mass_assignment", "redirect",
}


# Default severity inferred from injection_type when Smith doesn't file a
# finding. These are reasonable defaults — Smith can later upgrade via
# report(action='update_finding').
_SEVERITY_BY_INJECTION = {
    "sqli":             "critical",
    "nosqli":           "critical",
    "cmdi":             "critical",
    "ssti":             "critical",
    "xxe":              "high",
    "ssrf":             "high",
    "traversal":        "high",
    "idor":             "high",
    "bfla":             "high",
    "jwt":              "high",
    "mass_assignment":  "high",
    "prototype":        "high",
    "xss":              "high",
    "crlf":             "medium",
    "redirect":         "medium",
    "csrf":             "medium",
    "race":             "medium",
    "cors":             "medium",
    "method_tampering": "low",
    "rate_limit":       "low",
    "security_headers": "low",
    "cache":            "low",
}


def _autofile_finding_for_cell(
    cell: dict, endpoint_path: str, artifact_id: str, notes: str,
) -> str | None:
    """When Smith marks a cell vulnerable without filing a formal report
    via report(action='finding'), auto-create a self-contained finding so
    no vulnerability is lost. Returns the new finding_id, or None if the
    auto-file fails (in which case the cell still gets marked vulnerable
    but without a linked finding).

    The auto-filed finding pulls evidence directly from the artifact body
    so it stands on its own without requiring Smith to enrich it later.
    """
    try:
        import json as _json
        from core import findings as findings_store

        inj  = cell.get("injection_type", "unknown")
        param = cell.get("param", "")
        cell_id = cell.get("id", "")
        sev = _SEVERITY_BY_INJECTION.get(inj, "medium")

        # Pull a body excerpt from the artifact as concrete evidence
        evidence_body = ""
        if artifact_id:
            art_path = _ARTIFACTS_DIR / f"{artifact_id}.txt"
            if art_path.exists():
                try:
                    art_data = _json.loads(art_path.read_text(encoding="utf-8"))
                    status_code = art_data.get("status", "")
                    body_snip   = (art_data.get("body", "") or "")[:600]
                    evidence_body = (
                        f"artifact_id={artifact_id} | response_status={status_code}\n"
                        f"response_body[:600]={body_snip}"
                    )
                except Exception:
                    evidence_body = f"artifact_id={artifact_id} (binary or non-JSON artifact)"
            else:
                evidence_body = f"artifact_id={artifact_id} (artifact file missing)"

        # Build a descriptive title and description
        title = (
            f"{inj.upper()} on {endpoint_path}"
            + (f" param={param}" if param and param != "_endpoint" else "")
        )
        description = (
            (notes or f"Cell {cell_id} marked vulnerable for {inj} on {endpoint_path}.")
            + f"\n\nAuto-filed by coverage tool because Smith marked the cell vulnerable "
            + f"without invoking report(action='finding'). Smith can enrich via "
            + f"report(action='update_finding', data={{id: <finding_id>, ...}})."
        )

        # findings.add_finding is async — run it in a loop-safe way.
        import asyncio
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        async def _do():
            entry = await findings_store.add_finding(
                title=title,
                severity=sev,
                target=endpoint_path,
                description=description,
                evidence=evidence_body or "no artifact evidence captured",
                tool_used="coverage_autofile",
            )
            return entry.get("id")

        if loop and loop.is_running():
            # Schedule the coroutine and wait for it via run_coroutine_threadsafe
            # only if we're in a thread. In the normal MCP async path, the caller
            # is already inside the event loop — we await directly from update_cell
            # via a task. Simplest: create a task and let it run in background;
            # but we need the finding_id NOW to link the cell. Use asyncio.run_coroutine_threadsafe
            # would not work from the same loop. So instead, run synchronously
            # using a temporary loop in another thread is also complex.
            #
            # Solution: extract the synchronous portion. add_finding is a thin
            # wrapper over _load/_save with a lock. Recreate the write here
            # without awaiting the async lock — file writes are atomic enough
            # for an append-only findings.json.
            return _sync_add_finding(title, sev, endpoint_path, description, evidence_body)
        else:
            return asyncio.run(_do())
    except Exception:
        return None


def _sync_add_finding(
    title: str, severity: str, target: str, description: str, evidence: str,
) -> str | None:
    """Synchronous append to findings.json — used by auto-file path that runs
    inside the MCP event loop where awaiting findings_store.add_finding would
    require restructuring. The schema is identical."""
    try:
        import json as _json
        from core import findings as findings_store

        entry = {
            "id":          str(uuid.uuid4()),
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "title":       title,
            "severity":    severity,
            "target":      target,
            "description": description,
            "evidence":    evidence,
            "tool_used":   "coverage_autofile",
            "cve":         "",
        }
        fp = findings_store.FINDINGS_FILE
        if fp.exists():
            try:
                data = _json.loads(fp.read_text(encoding="utf-8"))
            except Exception:
                data = {"meta": {"created": "", "target": ""}, "findings": [], "diagrams": []}
        else:
            data = {"meta": {"created": "", "target": ""}, "findings": [], "diagrams": []}
        data.setdefault("findings", []).append(entry)
        fp.write_text(_json.dumps(data, indent=2), encoding="utf-8")
        return entry["id"]
    except Exception:
        return None


def _validate_auth_response(
    artifact_id: str, status: str, cell: dict | None,
) -> str:
    """Reject tested_clean when the artifact response was 401/403 on an injection cell.

    An HTTP 401/403 means "we never even ran your injection payload — auth blocked
    you at the door". Marking the cell tested_clean on that basis silently skips
    real testing. Force Smith to authenticate and re-test.

    Only enforces for injection-class cells (sqli, xss, ssti, etc.) — auth/cors/
    rate_limit/jwt cells legitimately use 401/403 as the test signal.
    """
    import json
    if status != "tested_clean":
        return ""
    if not cell:
        return ""
    inj_type = cell.get("injection_type", "")
    if inj_type not in _AUTH_GATED_TYPES:
        return ""
    artifact_file = _ARTIFACTS_DIR / f"{artifact_id}.txt"
    if not artifact_file.exists():
        return ""  # _validate_artifact already handled this
    # Only inspect http_request artifacts (other tools have different schemas)
    if not artifact_id.startswith("http_request_"):
        return ""
    try:
        data = json.loads(artifact_file.read_text(encoding="utf-8"))
    except Exception:
        return ""
    response_status = data.get("status")
    if response_status not in (401, 403):
        return ""
    return (
        f"REJECTED: cannot mark cell {cell.get('id', '?')} ({inj_type}) tested_clean — "
        f"artifact {artifact_id} shows HTTP {response_status}. An auth failure is NOT "
        f"evidence the injection payload was filtered; the server never evaluated it. "
        f"Required steps before closing this cell:\n"
        f"  1. Check known_assets.auth_tokens / known_assets.credentials for a valid JWT or login.\n"
        f"  2. If none, POST to the login endpoint and capture the Authorization: Bearer <jwt>.\n"
        f"  3. Re-send the {inj_type} payload with the Authorization header.\n"
        f"  4. THEN mark the cell based on the AUTHENTICATED response (2xx/4xx/5xx that is NOT 401/403).\n"
        f"Cell status remains in_progress."
    )


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

    async with _lock:
        data = _load()
        ep_map = {ep["id"]: ep.get("path", "?") for ep in data.get("endpoints", [])}
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
                # Auto-file a finding when Smith marks vulnerable without one.
                # Closes the gap where vulnerable cells lack a corresponding
                # findings.json entry (caught 43 lost findings in prod).
                if status == "vulnerable" and not finding_id:
                    ep_path = ep_map.get(cell.get("endpoint_id", ""), "?")
                    auto_id = _autofile_finding_for_cell(
                        cell, ep_path, artifact_id, notes,
                    )
                    if auto_id:
                        finding_id = auto_id
                cell["status"]      = status
                cell["notes"]       = notes
                cell["tested_by"]   = tested_by
                cell["artifact_id"] = artifact_id
                if finding_id:
                    cell["finding_id"] = finding_id
                cell["tested_at"] = datetime.now(timezone.utc).isoformat()
                _recount(data)
                _save(data)
                return warning if warning else True
    return False


def _apply_bulk_cell(cell: dict, upd: dict, warnings: list[str], ep_path: str = "?") -> None:
    """Apply one bulk-update entry to a cell in-place, appending any warnings."""
    st = upd.get("status", "")
    notes_text = upd.get("notes", "")
    warning = _integrity_warning_for_status(
        cell["id"], cell["status"], st,
        cell.get("injection_type", ""), notes_text,
    )
    if warning:
        warnings.append(warning)
    finding_id = upd.get("finding_id", "")
    artifact_id = upd.get("artifact_id", "")
    # Auto-file finding for vulnerable cells without finding_id (same as update_cell)
    if st == "vulnerable" and not finding_id:
        auto_id = _autofile_finding_for_cell(cell, ep_path, artifact_id, notes_text)
        if auto_id:
            finding_id = auto_id
    cell["status"]      = st
    cell["notes"]       = notes_text
    cell["tested_by"]   = upd.get("tested_by", "")
    cell["artifact_id"] = artifact_id
    if finding_id:
        cell["finding_id"] = finding_id
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

    async with _lock:
        data = _load()
        cell_map = {c["id"]: c for c in data["matrix"]}
        ep_map = {ep["id"]: ep.get("path", "?") for ep in data.get("endpoints", [])}
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
            ep_path = ep_map.get(cell_map[cid].get("endpoint_id", ""), "?")
            _apply_bulk_cell(cell_map[cid], upd, warnings, ep_path)
            count += 1
        _recount(data)
        _save(data)
    return {"updated": count, "rejected": rejected, "warnings": warnings}


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
