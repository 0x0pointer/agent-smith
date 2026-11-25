#!/usr/bin/env python3
"""
build_engagement_digest.py — Phase 0 of the prior-engagement knowledge store.

Turns a finished/stopped scan's on-disk state (session.json + a coverage matrix
snapshot + findings.json, plus the raw artifact bundle under
logs/smith-events/<id>/) into a durable, self-contained engagement store:

    engagements/<name>/
      known_assets.json   # creds/tokens/endpoints/tech/ports discovered
      coverage.json       # the coverage matrix (what was tested + result)
      findings.json       # confirmed findings for the target
      resume.json         # compact machine payload the ingest (Phase 1) consumes
      digest.md           # human- + agent-readable summary

`resume.json` is the contract Phase 1 (`session` prior_context ingest) reads:
    { target, generated_from, known_assets, endpoints,
      tested_clean_cells:[cell...], vulnerable_cells:[cell...],
      findings:[{id,title,severity,target}...], stats:{...} }

Trust model note: `tested_clean_cells` is what a `mode=resume` ingest skips. That
is only safe for YOUR OWN recently-stopped scan against an unchanged target — a
digest carries `generated_from`/timestamps so a stale store is obvious.

Pure stdlib. Read-only against the source; only writes under the output dir.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import shutil
import sys
from datetime import datetime, timezone


def _load_json(path: str):
    with open(path) as fh:
        return json.load(fh)


def _slug(text: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9._-]+", "-", (text or "").strip().lower()).strip("-")
    return s or "engagement"


def _pick_coverage(explicit: str | None, target: str | None) -> str | None:
    """Explicit path wins; else the newest coverage snapshot whose meta.target
    matches the session target; else the newest snapshot overall."""
    if explicit:
        return explicit
    snaps = sorted(glob.glob("logs/coverage_matrix_*.json"), key=os.path.getmtime, reverse=True)
    if not snaps:
        return None
    if target:
        tnorm = target.strip().lower()
        for s in snaps:
            try:
                m = _load_json(s).get("meta", {})
            except Exception:
                continue
            if (m.get("target") or "").strip().lower() == tnorm:
                return s
    return snaps[0]


def _bundle_dir(session_id: str | None) -> str | None:
    if not session_id:
        return None
    d = os.path.join("logs", "smith-events", session_id)
    return d if os.path.isdir(d) else None


def _asset_counts(ka: dict) -> dict:
    return {k: (len(v) if isinstance(v, list) else v) for k, v in (ka or {}).items()}


def build(session_path: str, coverage_path: str | None, findings_path: str | None,
          name: str | None, out_dir: str | None) -> str:
    session = _load_json(session_path) if os.path.exists(session_path) else {}
    target = session.get("target") or "unknown-target"
    session_id = session.get("id")
    known_assets = session.get("known_assets", {}) or {}

    cov_path = _pick_coverage(coverage_path, target)
    coverage = _load_json(cov_path) if cov_path and os.path.exists(cov_path) else {"meta": {}, "endpoints": [], "matrix": []}

    fpath = findings_path or "findings.json"
    findings_doc = _load_json(fpath) if os.path.exists(fpath) else {"findings": []}
    all_findings = findings_doc.get("findings", findings_doc) if isinstance(findings_doc, dict) else findings_doc

    # Keep findings whose target relates to this engagement (substring either way);
    # fall back to ALL when nothing matches so a mismatched target label loses nothing.
    tnorm = (target or "").strip().lower()
    def _rel(ft: str) -> bool:
        ft = (ft or "").strip().lower()
        return bool(ft) and (ft in tnorm or tnorm in ft or ft.split("/")[0] in tnorm)
    findings = [f for f in all_findings if _rel(f.get("target", ""))] or all_findings

    matrix = coverage.get("matrix", [])
    endpoints = coverage.get("endpoints", [])
    tested_clean = [c for c in matrix if c.get("status") == "tested_clean"]
    vulnerable = [c for c in matrix if c.get("status") == "vulnerable"]
    not_applicable = [c for c in matrix if c.get("status") == "not_applicable"]
    pending = [c for c in matrix if c.get("status") in ("pending", "in_progress", "")]

    name = name or _slug(target)
    out = out_dir or os.path.join("engagements", name)
    os.makedirs(out, exist_ok=True)

    # ── copies (self-contained store) ────────────────────────────────────────
    with open(os.path.join(out, "known_assets.json"), "w") as fh:
        json.dump(known_assets, fh, indent=2)
    with open(os.path.join(out, "coverage.json"), "w") as fh:
        json.dump(coverage, fh, indent=2)
    with open(os.path.join(out, "findings.json"), "w") as fh:
        json.dump({"findings": findings}, fh, indent=2)

    # ── resume.json — the Phase-1 ingest contract ────────────────────────────
    resume = {
        "target": target,
        "generated_from": {
            "session_json": os.path.abspath(session_path),
            "session_id": session_id,
            "coverage_snapshot": os.path.abspath(cov_path) if cov_path else None,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "source_status": session.get("status"),
            "stop_reason": session.get("stop_reason"),
        },
        "known_assets": known_assets,
        "endpoints": endpoints,
        "tested_clean_cells": [
            {"endpoint_id": c.get("endpoint_id"), "param": c.get("param"),
             "injection_type": c.get("injection_type"), "notes": c.get("notes", "")}
            for c in tested_clean
        ],
        "vulnerable_cells": [
            {"endpoint_id": c.get("endpoint_id"), "param": c.get("param"),
             "injection_type": c.get("injection_type"), "finding_id": c.get("finding_id")}
            for c in vulnerable
        ],
        "findings": [
            {"id": f.get("id"), "title": f.get("title"), "severity": f.get("severity"),
             "target": f.get("target"), "cve": f.get("cve")}
            for f in findings
        ],
        "stats": {
            "endpoints": len(endpoints),
            "cells_total": len(matrix),
            "tested_clean": len(tested_clean),
            "vulnerable": len(vulnerable),
            "not_applicable": len(not_applicable),
            "pending": len(pending),
            "findings": len(findings),
        },
    }
    with open(os.path.join(out, "resume.json"), "w") as fh:
        json.dump(resume, fh, indent=2)

    # ── digest.md — human + agent context ────────────────────────────────────
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "informational": 4}
    fsorted = sorted(findings, key=lambda f: sev_rank.get(str(f.get("severity", "")).lower(), 5))
    lines: list[str] = []
    lines.append(f"# Engagement digest — {target}")
    lines.append("")
    lines.append(f"- Source session: `{session_id}` (status: {session.get('status')}"
                 f"{', stopped: ' + str(session.get('stop_reason')) if session.get('stop_reason') else ''})")
    lines.append(f"- Generated: {resume['generated_from']['generated_at']}")
    lines.append(f"- Coverage snapshot: `{os.path.basename(cov_path) if cov_path else 'none'}`")
    bd = _bundle_dir(session_id)
    if bd:
        n_art = len([x for x in os.listdir(bd) if not x.endswith(".json")])
        lines.append(f"- Raw artifact bundle: `{bd}` ({n_art} artifacts)")
    lines.append("")
    lines.append("> RESUME NOTE: the tested-clean cells below are what a `mode=resume` "
                 "ingest SKIPS. Only trust them for an unchanged target — re-verify if the "
                 "app may have changed since the source session.")
    lines.append("")

    lines.append("## Coverage")
    st = resume["stats"]
    lines.append(f"- Endpoints: **{st['endpoints']}** | cells: **{st['cells_total']}** "
                 f"(tested_clean {st['tested_clean']}, vulnerable {st['vulnerable']}, "
                 f"n/a {st['not_applicable']}, **pending {st['pending']}**)")
    lines.append(f"- Pending cells are where a resumed scan should spend its effort.")
    lines.append("")

    lines.append(f"## Confirmed findings ({len(findings)})")
    if fsorted:
        for f in fsorted[:60]:
            cve = f" [{f.get('cve')}]" if f.get("cve") else ""
            lines.append(f"- **{str(f.get('severity','?')).upper()}** — {f.get('title','(untitled)')}"
                         f"{cve}  ·  `{f.get('target','')}`")
        if len(fsorted) > 60:
            lines.append(f"- … and {len(fsorted) - 60} more (see findings.json)")
    else:
        lines.append("- (none recorded)")
    lines.append("")

    lines.append("## Known assets (reuse — do not re-discover)")
    ka = known_assets
    def _list(kind, fmt=lambda x: str(x)):
        vals = ka.get(kind) or []
        if not vals:
            return
        lines.append(f"- **{kind}** ({len(vals)}): " +
                     ", ".join(fmt(v) for v in vals[:25]) + (" …" if len(vals) > 25 else ""))
    _list("ips")
    _list("domains")
    _list("ports", lambda p: f"{p.get('host','')}:{p.get('port','')}/{p.get('service','')}" if isinstance(p, dict) else str(p))
    _list("technologies")
    _list("endpoints", lambda e: (e.get("path") if isinstance(e, dict) else str(e)))
    _list("credentials", lambda c: (c.get("username", "?") if isinstance(c, dict) else str(c)))
    _list("auth_tokens", lambda t: "token" )
    _list("auth_endpoints", lambda e: (f"{e.get('method','')} {e.get('path','')}" if isinstance(e, dict) else str(e)))
    if not any(ka.get(k) for k in ("ips", "domains", "ports", "technologies", "endpoints",
                                   "credentials", "auth_tokens", "auth_endpoints")):
        lines.append("- (none recorded)")
    lines.append("")

    lines.append("## Assets summary (counts)")
    lines.append("```")
    lines.append(json.dumps(_asset_counts(known_assets), indent=2))
    lines.append("```")

    digest_md = "\n".join(lines) + "\n"
    with open(os.path.join(out, "digest.md"), "w") as fh:
        fh.write(digest_md)

    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Build a durable engagement store from a scan's on-disk state.")
    ap.add_argument("--session", default="session.json", help="path to session.json (default: ./session.json)")
    ap.add_argument("--coverage", default=None, help="coverage_matrix_*.json (default: newest matching the target)")
    ap.add_argument("--findings", default=None, help="findings.json (default: ./findings.json)")
    ap.add_argument("--name", default=None, help="engagement store name (default: slug of the target)")
    ap.add_argument("--out", default=None, help="output dir (default: engagements/<name>)")
    args = ap.parse_args(argv)

    if not os.path.exists(args.session):
        print(f"ERROR: session file not found: {args.session}", file=sys.stderr)
        return 2
    out = build(args.session, args.coverage, args.findings, args.name, args.out)
    stats = _load_json(os.path.join(out, "resume.json"))["stats"]
    print(f"✓ engagement store written: {out}")
    print(f"  {stats['findings']} findings | {stats['endpoints']} endpoints | "
          f"{stats['tested_clean']} tested_clean (skippable) | {stats['pending']} pending")
    print(f"  files: digest.md, resume.json, coverage.json, findings.json, known_assets.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
