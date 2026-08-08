"""Scan-start helpers: coverage-matrix lifecycle, prior-findings brief, routing."""
import re

from core import findings as findings_store
from core import logger as log

import mcp_server.session_tools as _st


def _reset_coverage_matrix(target: str, prev_target: str, has_data: bool) -> bool:
    """Reset/init coverage matrix. Returns True if this is a resume of the same target."""
    from core.coverage import COVERAGE_FILE, _save as _cov_save, get_matrix
    from datetime import datetime, timezone
    import shutil

    if prev_target and prev_target != target and has_data:
        # Different target — archive the old matrix AND archive (not delete) quick_log + qa_state
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        archive_dir = COVERAGE_FILE.parent / "logs"
        archive_dir.mkdir(exist_ok=True)
        archive_path = archive_dir / f"coverage_matrix_{ts}.json"
        shutil.copy2(COVERAGE_FILE, archive_path)
        log.note(f"Coverage matrix archived to {archive_path.name} (previous target: {prev_target})")
        for stale in ("quick_log.json", _st._QA_STATE_FILENAME):
            p = COVERAGE_FILE.parent / stale
            if p.exists():
                archive_stale = archive_dir / f"{p.stem}_{ts}.json"
                shutil.copy2(p, archive_stale)
                p.unlink()
        _cov_save({
            "meta": {
                "created": datetime.now(timezone.utc).isoformat(),
                "target": target,
                "total_cells": 0, "tested": 0, "in_progress": 0,
                "vulnerable": 0, "not_applicable": 0, "skipped": 0,
            },
            "endpoints": [],
            "matrix": [],
        })
    elif not has_data and not COVERAGE_FILE.exists():
        # No coverage file at all — create an empty one
        _cov_save({
            "meta": {
                "created": datetime.now(timezone.utc).isoformat(),
                "target": target,
                "total_cells": 0, "tested": 0, "in_progress": 0,
                "vulnerable": 0, "not_applicable": 0, "skipped": 0,
            },
            "endpoints": [],
            "matrix": [],
        })
    # Same target with existing data — keep matrix as-is (resume or view results)
    return bool(prev_target and prev_target == target and has_data)


def _norm_target(s) -> str:
    """Normalise a target so http://x/ and HTTP://X compare equal (mirrors report_tools)."""
    return re.sub(r"\s+", " ", str(s or "").strip().lower()).rstrip("/")


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _prior_findings_brief(target: str) -> str:
    """Compact 'already known — don't re-file' brief for prior findings on this target.

    findings.json persists across runs; surfacing what is already recorded lets a
    re-run skip known issues and weight effort toward untested coverage instead of
    re-discovering (and the dedup gate re-blocking) the same app-wide misconfig.
    Prior false_positives are excluded — they should NOT discourage a re-test.
    """
    try:
        data = findings_store._load()
    except Exception:
        return ""
    ntg = _norm_target(target)
    if not ntg:
        return ""
    prior = [
        f for f in data.get("findings", [])
        if _norm_target(f.get("target")) == ntg
        and str(f.get("status") or "").strip().lower() != "false_positive"
    ]
    if not prior:
        return ""
    prior.sort(key=lambda f: _SEV_ORDER.get(str(f.get("severity", "")).lower(), 5))
    lines = [
        f"KNOWN FINDINGS for this target ({len(prior)} on record from prior run(s) — do NOT re-file; "
        "the server deduplicates same target+title+severity). Weight THIS run toward untested "
        "coverage cells and gaps the prior run(s) missed:",
    ]
    lines += [
        f"  - [{str(f.get('severity', '')).upper()}] {f.get('title', '')} (id={f.get('id', '?')})"
        for f in prior[:12]
    ]
    if len(prior) > 12:
        lines.append(f"  - (+{len(prior) - 12} more — see findings.json)")
    return "\n".join(lines)


def _start_first_move(classification: dict, target: str) -> str:
    """Advisory 'recommended first tool call' line, by target kind."""
    kind = classification["kind"]
    if kind == "codebase":
        return f"  session(action='set_codebase', options={{'path': '{target}'}}) then scan(tool='semgrep', target='{target}')"
    if kind == "network":
        return f"  scan(tool='naabu', target='{target}')"
    if kind == "cloud":
        return f"  Invoke {classification['skill_prior']} (cloud posture — no httpx web scan)"
    return f"  scan(tool='httpx', target='{target}')"  # api / web
