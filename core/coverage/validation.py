"""
Coverage matrix — integrity and closure-gate validation.

These functions decide whether a cell update is allowed and, if so, whether
it deserves an integrity warning. They read ``_ARTIFACTS_DIR`` from the
package namespace (``core.coverage``) at call time so the path stays
patchable from one place.
"""
from __future__ import annotations

import json

import core.coverage as _cov
from core import taxonomy as _tax


# ---------------------------------------------------------------------------
# Injection types that have known bypass techniques — marking these N/A
# requires the notes to explain WHY the bypass doesn't apply.
# ---------------------------------------------------------------------------

_BYPASS_REQUIRED_TYPES = _tax.BYPASS_REQUIRED_TYPES


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
    artifact_file = _cov._ARTIFACTS_DIR / f"{artifact_id}.txt"
    if not artifact_file.exists():
        return (
            f"REJECTED: artifact_id '{artifact_id}' not found on disk. "
            "The tool must actually run and produce an artifact before the cell can close. "
            "Check that you are using the artifact_id from the tool response, not a placeholder."
        )
    return ""


# Cells whose evidence legitimately comes from inspecting a single response
# (no payload required). These types may share one artifact across many cells
# because a plain GET legitimately surfaces the missing security headers / the
# CORS reflection behavior for that whole endpoint.
_RESPONSE_HEADER_CELL_TYPES = {"security_headers", "cors"}


def _validate_artifact_reuse(artifact_id: str, status: str, target_cell: dict, matrix: list[dict]) -> str:
    """Reject single-artifact mass-closure across unrelated cells.

    One HTTP request was being used to close 36 different injection cells
    (sqli, xss, ssti, ssrf, cmdi, traversal, redirect, nosqli, crlf, ...) on a
    single endpoint with three params. That's mathematically impossible — each
    injection type needs its own discriminating payload. The artifact-existence
    check alone (``_validate_artifact``) doesn't catch this.

    Rule: per-artifact reuse cap = 2 cells, with two exceptions:
      a. Cells whose injection_type is response-header-derived
         (security_headers, cors) may share an artifact across the endpoint —
         a single response truthfully surfaces both.
      b. Cells on the SAME endpoint + SAME param + SAME injection_type may
         share (e.g. a re-confirmation of an already-closed cell).
    """
    if status not in ("tested_clean", "vulnerable") or not artifact_id:
        return ""

    target_id = target_cell.get("id")
    inj = target_cell.get("injection_type", "")
    if inj in _RESPONSE_HEADER_CELL_TYPES:
        return ""

    # Existing cells already closed against this artifact (excluding the target)
    siblings = [
        c for c in matrix
        if c.get("artifact_id") == artifact_id
        and c.get("id") != target_id
        and c.get("status") in ("tested_clean", "vulnerable")
    ]
    if not siblings:
        return ""

    # Allow the response-header-only siblings to not count against the budget —
    # they're plausibly evidenced by the same response.
    counted = [s for s in siblings if s.get("injection_type") not in _RESPONSE_HEADER_CELL_TYPES]
    if len(counted) < 2:
        return ""

    sample = ", ".join(s.get("id", "?") for s in counted[:3])
    return (
        f"REJECTED: artifact_id '{artifact_id}' is already cited by {len(counted)} other "
        f"injection-type cell(s) ({sample}{', ...' if len(counted) > 3 else ''}). "
        "A single HTTP request cannot legitimately test multiple distinct injection types "
        "(sqli/xss/ssti/cmdi/ssrf/...) — each needs its own discriminating payload. "
        "Re-run the test with a payload SPECIFIC to this cell's injection_type and pass the "
        "fresh artifact_id from that response. (Response-header-only cells like "
        "security_headers/cors are exempt and don't count toward this cap.)"
    )


def cell_has_test_evidence(cell: dict) -> bool:
    """True if a closed cell carries real test evidence.

    ``artifact_id`` is THE enforcement mechanism — ``_validate_artifact``
    rejects any tested_clean/vulnerable closure whose artifact doesn't exist
    on disk, so a closed cell with an ``artifact_id`` provably ran a tool.
    ``tested_by`` is retained only as human-readable context ("Free-text
    tested_by is no longer accepted" — see ``_validate_artifact``).

    A cell is evidenced if it has EITHER. The completion gates used to key on
    ``tested_by`` alone, which made a cell closed with a real artifact but an
    empty ``tested_by`` permanently un-completable: the proof was on disk, yet
    the gate demanded the deprecated field. After a context compaction Smith
    loses the cell IDs and can't backfill that field, so the whole scan
    deadlocks short of completion. Gate on the artifact, with ``tested_by`` as
    a back-compat fallback for older matrices.
    """
    return bool(cell.get("artifact_id") or cell.get("tested_by"))


def _finding_norm_path(finding) -> str | None:
    """Normalized URL path of a non-false-positive finding, or None to skip it."""
    if not isinstance(finding, dict) or finding.get("status") == "false_positive":
        return None
    from urllib.parse import urlparse

    from core.coverage.classify import _normalize_path
    try:
        path = urlparse(finding.get("target", "")).path or "/"
    except Exception:
        return None
    return _normalize_path(path) or None


def unregistered_finding_paths(findings_data, coverage_data) -> list[str]:
    """Normalized endpoint paths that have findings but are NOT in the matrix.

    A non-empty result means testing outran discovery — the agent filed findings
    against endpoints it never registered, so the coverage matrix doesn't reflect
    the real attack surface (the recon-before-testing discipline was skipped).
    Drives the QA ``DISCOVERY_GAP`` check (early steer + completion block).

    Returns ``[]`` when no endpoints are registered at all — that "zero endpoints"
    state is a different signal handled by its own check, and treating every
    finding as unregistered there would just be noise.
    """
    from core.coverage.classify import _normalize_path

    endpoints = (coverage_data or {}).get("endpoints", []) if isinstance(coverage_data, dict) else []
    if not endpoints:
        return []
    registered = {
        ep.get("_normalized") or _normalize_path(ep.get("path", ""))
        for ep in endpoints if isinstance(ep, dict)
    }
    findings = findings_data if isinstance(findings_data, list) else (findings_data or {}).get("findings", [])
    unregistered = {p for f in findings if (p := _finding_norm_path(f)) and p not in registered}
    return sorted(unregistered)


# Injection cell types where 401/403 is meaningless evidence of cleanliness —
# the test payload was never evaluated because auth blocked the request first.
# Excluded: auth/access-control cell types where 401/403 IS the finding signal.
_AUTH_GATED_TYPES = _tax.AUTH_GATED_TYPES


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
    if status != "tested_clean":
        return ""
    if not cell:
        return ""
    inj_type = cell.get("injection_type", "")
    if inj_type not in _AUTH_GATED_TYPES:
        return ""
    artifact_file = _cov._ARTIFACTS_DIR / f"{artifact_id}.txt"
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
