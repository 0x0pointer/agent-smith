"""Phase-0 cross-cutting auto-close — propagate app-wide verdicts to their cells.

The matrix fans every endpoint across app-wide "response-property" checks —
``cors``, ``security_headers``, ``csrf`` — so a 54-endpoint app carries 54 cors
cells, 54 security_headers cells, etc. (the cross-cutting types are ~58% of all
cells). Those verdicts are app-wide: ONE real HTTP response shows the CORS policy
and the security-header set for the whole app, and the HTTP method decides CSRF
applicability. In practice the model files the app-wide FINDING ("Wildcard CORS
on all endpoints") but never propagates it to the per-endpoint cells, so coverage
reads near-zero while the work is actually done.

This module PROPAGATES those already-established verdicts to the cells honestly:

  * every closure cites a real response ``artifact_id`` (the evidence on disk);
  * every ``vulnerable`` closure links the existing finding (no auto-filing);
  * CSRF on a safe method (GET/HEAD/OPTIONS) is ``not_applicable`` — CSRF is
    irrelevant to a non-state-changing request;
  * a verdict is only emitted when the evidence supports it — a wildcard-CORS
    cell with no matching finding stays ``pending`` rather than being fabricated.

It claims NO new testing — it records verdicts the scan already reached. Injection
cells (sqli/xss/ssti/…) are deliberately NOT touched here; those need real
per-cell detectors (Phase 1), not propagation, so they can never be
false-closed by this path.
"""
from __future__ import annotations

# Modern response security headers (lowercased for case-insensitive lookup). A
# response missing any of these is a real, app-wide security-headers gap.
_REQUIRED_SECURITY_HEADERS = (
    "x-frame-options",
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
)

# CSRF only matters for state-changing requests; these methods can't change state.
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# The cross-cutting types this propagator is allowed to close. Injection types
# are intentionally excluded — see module docstring.
CROSSCUTTING_TYPES = ("cors", "security_headers", "csrf")


def _match_finding_id(findings: list | None, inj_type: str) -> str | None:
    """Id of the live app-wide finding for this cross-cutting type, or None.

    Matches on title keyword sets so a real verdict can be linked to its cells.
    Skips findings already adjudicated false_positive.
    """
    keysets = {
        "cors": (("cors",),),
        "security_headers": (("security", "header"), ("missing", "header")),
        "csrf": (("csrf",),),
    }
    for f in findings or []:
        if f.get("status") == "false_positive":
            continue
        title = (f.get("title") or "").lower()
        for keys in keysets.get(inj_type, ()):
            if all(k in title for k in keys):
                return f.get("id")
    return None


def plan_crosscutting_closures(
    matrix: list | None,
    endpoints: list | None,
    findings: list | None,
    response_headers: dict | None,
    artifact_id: str,
) -> list[dict]:
    """Plan honest closures for pending app-wide cross-cutting cells.

    Pure — no I/O. Returns a list of update dicts ready for ``bulk_update``:
    ``{cell_id, status, finding_id?, artifact_id, notes, basis}``. ``basis`` is
    diagnostic ("artifact" | "method" | "finding") so the caller can show the
    evidence chain. Only ``pending`` cross-cutting cells are considered; a verdict
    is emitted only when the evidence supports it (otherwise the cell stays
    pending). Returns [] when there is no response evidence.
    """
    if not artifact_id:
        return []
    hdrs = {(k or "").lower(): (v or "") for k, v in (response_headers or {}).items()}
    ep_by_id = {e.get("id"): e for e in (endpoints or [])}

    acao = hdrs.get("access-control-allow-origin", "").strip()
    cors_wildcard = acao == "*"
    missing_headers = [h for h in _REQUIRED_SECURITY_HEADERS if h not in hdrs]
    sh_missing = bool(missing_headers)
    fid = {t: _match_finding_id(findings, t) for t in CROSSCUTTING_TYPES}

    closures: list[dict] = []
    for cell in matrix or []:
        if cell.get("status") != "pending":
            continue
        inj = cell.get("injection_type")
        cid = cell.get("id")
        if inj == "cors":
            if cors_wildcard and fid["cors"]:
                closures.append({"cell_id": cid, "status": "vulnerable",
                                 "finding_id": fid["cors"], "artifact_id": artifact_id,
                                 "notes": f"Wildcard CORS app-wide (Access-Control-Allow-Origin: {acao})",
                                 "basis": "artifact"})
            elif not cors_wildcard:
                closures.append({"cell_id": cid, "status": "tested_clean",
                                 "artifact_id": artifact_id,
                                 "notes": f"No wildcard CORS (ACAO: {acao or 'absent'})",
                                 "basis": "artifact"})
            # wildcard but no finding to link → leave pending (don't fabricate a vuln close)
        elif inj == "security_headers":
            if sh_missing and fid["security_headers"]:
                closures.append({"cell_id": cid, "status": "vulnerable",
                                 "finding_id": fid["security_headers"], "artifact_id": artifact_id,
                                 "notes": f"Missing security headers app-wide: {', '.join(missing_headers)}",
                                 "basis": "artifact"})
            elif not sh_missing:
                closures.append({"cell_id": cid, "status": "tested_clean",
                                 "artifact_id": artifact_id,
                                 "notes": "All required security headers present",
                                 "basis": "artifact"})
        elif inj == "csrf":
            ep = ep_by_id.get(cell.get("endpoint_id"), {})
            method = (ep.get("method") or "GET").upper()
            if method in _SAFE_METHODS:
                closures.append({"cell_id": cid, "status": "not_applicable",
                                 "notes": f"CSRF not applicable to non-state-changing {method} request",
                                 "basis": "method"})
            elif fid["csrf"]:
                closures.append({"cell_id": cid, "status": "vulnerable",
                                 "finding_id": fid["csrf"], "artifact_id": artifact_id,
                                 "notes": "No CSRF protection on state-changing endpoint (app-wide finding)",
                                 "basis": "finding"})
            # state-changing but no csrf finding → leave pending
    return closures


def parse_artifact_headers(artifact_text: str) -> tuple[int | None, dict]:
    """Extract ``(status, headers)`` from a stored http_request artifact (JSON)."""
    import json
    try:
        d = json.loads(artifact_text)
        if isinstance(d, dict) and isinstance(d.get("headers"), dict):
            return d.get("status"), d["headers"]
    except Exception:
        pass
    return None, {}


def pick_representative_artifact(artifacts_dir) -> tuple[str | None, dict]:
    """Newest http_request artifact that is a 200 with headers — app-wide evidence.

    Returns ``(artifact_id, headers)`` or ``(None, {})``. The artifact_id is the
    filename without its ``.txt`` suffix, matching how cells cite artifacts.
    """
    import os
    try:
        names = sorted(
            (f for f in os.listdir(artifacts_dir)
             if f.startswith("http_request") and f.endswith(".txt")),
            reverse=True,
        )
        for fn in names:
            with open(os.path.join(artifacts_dir, fn)) as fh:
                status, headers = parse_artifact_headers(fh.read())
            if headers and status == 200:
                return fn[:-4], headers
    except Exception:
        pass
    return None, {}
