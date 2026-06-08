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
def _validate_finding_link(status: str, finding_id: str | None) -> str:
    """Reject closing a cell as 'vulnerable' without a finding_id.

    Replaces the old auto-file path: instead of creating a finding on
    Smith's behalf (which produced per-cell-granularity duplicates for
    app-wide misconfigs like security_headers/cors/rate_limit — 33×
    inflation observed), force Smith to call report(action='finding')
    first and pass the returned id back here.

    Tested_clean / not_applicable / skipped cells don't trigger this —
    only vulnerable closures. If finding_id is already populated (Smith
    is updating notes on an existing link), pass through unchanged.
    """
    if status != "vulnerable":
        return ""
    if finding_id and finding_id.strip():
        return ""
    return (
        "REJECTED: closing a cell as 'vulnerable' requires a finding_id. "
        "First call report(action='finding', data={title, severity, target, "
        "description, evidence, tool_used, ...}) — capture the returned 'id' "
        "from that response — then pass it back here as finding_id alongside "
        "the artifact_id. This avoids creating duplicate findings for app-wide "
        "misconfigs and keeps the finding/cell linkage honest. "
        "Cell status will remain in_progress until the link exists."
    )


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
    # Bound the JSON read: an http_request artifact JSON should never be
    # larger than a few hundred KB. Reject anything anomalously large
    # rather than risk a DoS by trying to json.loads a gigabyte.
    _MAX_ARTIFACT_BYTES = 10 * 1024 * 1024  # 10 MB ceiling
    try:
        if artifact_file.stat().st_size > _MAX_ARTIFACT_BYTES:
            return ""  # too big to safely parse; let the cell close
        data = json.loads(artifact_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
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
    # Vulnerable closures require an existing finding_id — Smith must call
    # report(action='finding') first. Auto-filing on Smith's behalf produced
    # per-cell-granularity duplicates that polluted the export.
    link_reject = _validate_finding_link(status, finding_id)
    if link_reject:
        return link_reject

    async with _lock:
        data = _load()
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
                _recount(data)
                _save(data)
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

    async with _lock:
        data = _load()
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
