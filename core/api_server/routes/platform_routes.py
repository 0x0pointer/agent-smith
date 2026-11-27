"""Platform (cross-scan) routes: every scan, every finding, every app in one view.

The per-scan pages read one run's snapshots through a run-scoped token. The
platform pages (Home, Scans, Findings, Apps) need the same data across ALL runs,
so these endpoints are operator-only and aggregate the control-plane database:

* ``GET /api/platform/overview`` — one row per scan (status, progress, finding
  counts, what needs the operator), totals, and scans grouped into apps.
* ``GET /api/platform/findings`` — every finding of every scan, flattened and
  tagged with the scan and app it belongs to.

The scan driven from the client without the control plane (repo-root
``session.json`` / ``findings.json``) is included as the pseudo-run ``local`` so
its results are not lost from view when the platform is switched on.
"""
from __future__ import annotations

import logging
from urllib.parse import urlparse

from fastapi import Request
from fastapi.responses import JSONResponse

import core.api_server as _api

from ._common import router

_LOG = logging.getLogger(__name__)

LOCAL_RUN_ID = "local"
_MAX_RUNS = 300
_SEVERITIES = ("critical", "high", "medium", "low", "info")
_ACTIVE = {"starting", "running", "intervention_required"}
_OPEN_WISH = {"", "open", "pending", "requested"}


def _is_operator(request: Request) -> bool:
    return getattr(request.state, "role", "") == "operator"


def app_key(target: str) -> str:
    """The app a target belongs to: its host (plus a non-default port).

    ``https://shop.example.com/login`` and ``shop.example.com`` are the same
    app; ``localhost:3000`` and ``localhost:8080`` are not.
    """
    raw = str(target or "").strip()
    if not raw:
        return "unknown"
    try:
        parsed = urlparse(raw if "://" in raw else f"//{raw}")
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        return raw.lower()[:120]
    if not host:
        return raw.lower()[:120]
    default = {"http": 80, "https": 443}.get(parsed.scheme or "")
    return f"{host}:{port}" if port and port != default else host


def _severity(finding: dict) -> str:
    sev = str(finding.get("severity") or "info").strip().lower()
    return sev if sev in _SEVERITIES else "info"


def _is_open(finding: dict) -> bool:
    return str(finding.get("status") or "").lower() != "false_positive"


def _finding_counts(findings: list) -> dict:
    counts = {sev: 0 for sev in _SEVERITIES}
    for f in findings:
        if isinstance(f, dict) and _is_open(f):
            counts[_severity(f)] += 1
    counts["total"] = sum(counts[sev] for sev in _SEVERITIES)
    return counts


def _coverage_progress(coverage: dict | None) -> dict:
    cells = (coverage or {}).get("matrix") or []
    total = len(cells)
    done = sum(1 for c in cells if isinstance(c, dict) and str(c.get("status") or "pending") != "pending")
    return {"total": total, "done": done, "pct": round(100 * done / total) if total else 0}


def _needs_you(status: str, session: dict, wishlist: dict | None) -> list[str]:
    """Plain-language reasons this scan is waiting for the operator."""
    reasons: list[str] = []
    if status == "intervention_required" or isinstance(session.get("intervention"), dict):
        reasons.append("Paused: Smith is waiting for your answer")
    if status == "idle":
        reasons.append("Idle: the agent stopped; resume it or complete the scan")
    open_items = [i for i in ((wishlist or {}).get("items") or [])
                  if isinstance(i, dict) and str(i.get("status") or "").lower() in _OPEN_WISH]
    if open_items:
        n = len(open_items)
        reasons.append(f"{n} resource request{'s' if n != 1 else ''} from Smith")
    return reasons


def _run_summary(row: dict, session: dict, findings: dict, coverage: dict | None,
                 cost: dict | None, wishlist: dict | None) -> dict:
    status = str(row.get("status") or session.get("status") or "unknown")
    target = str(row.get("target") or session.get("target") or "")
    return {
        "run_id": row.get("run_id"),
        "target": target,
        "app": app_key(target),
        "status": status,
        "active": status in _ACTIVE,
        "depth": row.get("depth") or session.get("depth") or "",
        "created_at": row.get("created_at") or session.get("started") or "",
        "updated_at": row.get("updated_at") or session.get("finished") or "",
        "skill": session.get("skill") or "",
        "step": session.get("current_step") or "",
        "source": ((session.get("source_instance") or {}).get("name")
                   if isinstance(session.get("source_instance"), dict) else "") or "",
        "findings": _finding_counts(findings.get("findings") or []),
        "coverage": _coverage_progress(coverage),
        "cost_usd": round(float((cost or {}).get("est_cost_usd") or (cost or {}).get("cost_usd") or 0), 2),
        "needs_you": _needs_you(status, session, wishlist),
        "local": bool(row.get("local")),
        "whitebox": _is_whitebox(row),
    }


def _is_whitebox(row: dict) -> bool:
    """True when the scan was started with a source-code folder."""
    from control_plane import orchestrator

    return bool(orchestrator.run_codebase(row.get("workdir")))


def _local_run() -> tuple[dict, dict, dict] | None:
    """The client-driven scan stored at the repo root, if there is one."""
    session = _api._read_json(_api._SESSION_FILE) or {}
    findings = _api._read_json(_api._FINDINGS_FILE) or {}
    if not isinstance(session, dict) or not isinstance(findings, dict):
        return None
    if not session.get("target") and not (findings.get("findings") or []):
        return None
    row = {
        "run_id": LOCAL_RUN_ID,
        "target": session.get("target") or (findings.get("meta") or {}).get("target") or "Local scan",
        "status": session.get("status") or "complete",
        "depth": session.get("depth") or "",
        "created_at": session.get("started") or (findings.get("meta") or {}).get("created") or "",
        "updated_at": session.get("finished") or session.get("started") or "",
        "local": True,
    }
    return row, session, findings


def _collect() -> list[dict]:
    """Every scan with the documents the platform pages need."""
    from control_plane import orchestrator
    from core import db as _db

    out: list[dict] = []
    repo = _db.get_repository()
    if repo is not None:
        for row in orchestrator.list_runs()[:_MAX_RUNS]:
            run_id = str(row.get("run_id") or "")
            if not run_id:
                continue

            def snap(kind: str, _run_id: str = run_id) -> dict:
                try:
                    data = repo.load_snapshot(_run_id, kind)
                except Exception:
                    data = None
                return data if isinstance(data, dict) else {}

            out.append({"row": row, "session": snap("session"), "findings": snap("findings"),
                        "coverage": snap("coverage"), "cost": snap("cost"), "wishlist": snap("wishlist")})
    local = _local_run()
    if local:
        row, session, findings = local
        coverage = _api._read_json(_api._COVERAGE_FILE)
        out.append({"row": row, "session": session, "findings": findings,
                    "coverage": coverage if isinstance(coverage, dict) else {},
                    "cost": _api._read_json(_api._COST_FILE) or {}, "wishlist": {}})
    return out


def _apps(runs: list[dict]) -> list[dict]:
    apps: dict[str, dict] = {}
    for run in sorted(runs, key=lambda r: str(r.get("created_at") or "")):
        app = apps.setdefault(run["app"], {
            "app": run["app"], "targets": [], "scans": 0, "active": 0,
            "findings": {sev: 0 for sev in (*_SEVERITIES, "total")},
            "last_run_id": "", "last_target": "", "last_depth": "", "last_status": "", "last_scan_at": "",
        })
        app["scans"] += 1
        app["active"] += 1 if run["active"] else 0
        if run["target"] and run["target"] not in app["targets"]:
            app["targets"].append(run["target"])
        # Sorted oldest-first, so the last one written is the most recent scan.
        app.update(last_run_id=run["run_id"], last_target=run["target"], last_depth=run["depth"],
                   last_status=run["status"], last_scan_at=run["created_at"])
    return sorted(apps.values(), key=lambda a: str(a["last_scan_at"]), reverse=True)


@router.get("/api/platform/overview")
async def api_platform_overview(request: Request) -> JSONResponse:
    if not _is_operator(request):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    try:
        collected = _collect()
    except RuntimeError:
        _LOG.exception("platform overview failed")
        return JSONResponse({"error": "service unavailable"}, status_code=503)

    runs = [_run_summary(c["row"], c["session"], c["findings"], c["coverage"], c["cost"], c["wishlist"])
            for c in collected]
    runs.sort(key=lambda r: str(r.get("created_at") or ""), reverse=True)

    apps = _apps(runs)
    by_app = {a["app"]: a for a in apps}
    # An app's open findings are those of its MOST RECENT scan that produced any:
    # summing every scan would count the same issue once per re-scan.
    for run in sorted(runs, key=lambda r: str(r.get("created_at") or "")):
        if run["findings"]["total"] or not by_app[run["app"]]["findings"]["total"]:
            by_app[run["app"]]["findings"] = dict(run["findings"])

    totals = {sev: sum(a["findings"][sev] for a in apps) for sev in (*_SEVERITIES, "total")}
    return JSONResponse({
        "runs": runs,
        "apps": apps,
        "totals": {
            "scans": len(runs),
            "active": sum(1 for r in runs if r["active"]),
            "needs_you": sum(1 for r in runs if r["needs_you"]),
            "apps": len(apps),
            "findings": totals,
        },
    })


@router.get("/api/platform/findings")
async def api_platform_findings(request: Request) -> JSONResponse:
    if not _is_operator(request):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    try:
        collected = _collect()
    except RuntimeError:
        _LOG.exception("platform findings failed")
        return JSONResponse({"error": "service unavailable"}, status_code=503)

    out: list[dict] = []
    for c in collected:
        row = c["row"]
        run_target = str(row.get("target") or "")
        for f in c["findings"].get("findings") or []:
            if not isinstance(f, dict) or not f.get("id"):
                continue
            out.append({
                "id": f.get("id"),
                "title": str(f.get("title") or "Untitled finding"),
                "severity": _severity(f),
                "status": str(f.get("status") or ""),
                "target": str(f.get("target") or ""),
                "timestamp": str(f.get("timestamp") or ""),
                "cve": str(f.get("cve") or ""),
                "tool_used": str(f.get("tool_used") or ""),
                "summary": " ".join(str(f.get("description") or "").split())[:240],
                "run_id": row.get("run_id"),
                "run_target": run_target,
                "run_status": str(row.get("status") or ""),
                "app": app_key(run_target),
            })
    rank = {sev: i for i, sev in enumerate(_SEVERITIES)}
    out.sort(key=lambda f: f["timestamp"], reverse=True)
    out.sort(key=lambda f: rank[f["severity"]])
    return JSONResponse({"findings": out})
