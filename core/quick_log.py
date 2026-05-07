"""
Quick Log
=========
Append-only JSONL event feed for the QA daemon and dashboard.
Every MCP tool call, skill change, finding, and coverage update writes one line.

Entry types:
  SKILL    — set_skill called
  TOOL     — Docker tool completed (scan, http, etc.)
  SPIDER   — spider completed (TOOL subtype with endpoint count)
  FINDING  — report(action="finding") called
  COVERAGE — coverage matrix updated (endpoint registered or bulk_tested)
"""
from __future__ import annotations

import asyncio
import json
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

_REPO_ROOT = Path(__file__).parent.parent
_QUICK_LOG_FILE = _REPO_ROOT / "quick_log.json"

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_DOCKER_ALIASES = {"host.docker.internal", "172.17.0.1", "172.18.0.1"}


def _norm_target(t: str) -> str:
    for alias in _DOCKER_ALIASES:
        t = t.replace(alias, "localhost")
    return t


def _gate_lines(gates: list, now: datetime) -> list[str]:
    if not gates:
        return []
    pending: list[str] = []
    for g in gates:
        if g.get("status") == "satisfied":
            continue
        elapsed_min: int | str = "?"
        try:
            trig = datetime.fromisoformat(g["triggered_at"])
            elapsed_min = round((now - trig).total_seconds() / 60)
        except Exception:
            pass
        pending.append(
            f"{g['id']} (triggered {elapsed_min}min ago, requires: {', '.join(g.get('required_skills', []))})"
        )
    lines = []
    if pending:
        lines.append("Pending gates: " + "; ".join(pending))
    satisfied = [g["id"] for g in gates if g.get("status") == "satisfied"]
    if satisfied:
        lines.append("Satisfied gates: " + ", ".join(satisfied))
    return lines


def _session_lines(now: datetime) -> tuple[list[str], str]:
    """Return (summary lines, declared_target) from session.json."""
    session_file = _REPO_ROOT / "session.json"
    declared_target = ""
    lines: list[str] = []
    try:
        sd = json.loads(session_file.read_text())
        declared_target = sd.get("target", "")
        if declared_target:
            lines.append(f"Declared target: {declared_target}")
        depth = sd.get("depth", "")
        if depth:
            lines.append(f"Scan depth: {depth}")
        lines += _gate_lines(sd.get("gates", []), now)
    except Exception:
        pass
    return lines, declared_target


def _tool_lines(tools_all: list[dict], tools_15m: list[dict]) -> list[str]:
    if tools_15m:
        counts: dict[str, int] = {}
        for t in tools_15m:
            counts[t["name"]] = counts.get(t["name"], 0) + 1
        return ["Tools run (last 15min): " + ", ".join(f"{n}({c})" for n, c in counts.items())]
    if tools_all:
        return ["Tools run (last 15min): none"]
    return []


def _scope_drift_lines(declared_target: str, tools_all: list[dict]) -> list[str]:
    if not declared_target or not tools_all:
        return []
    decl_norm = _norm_target(declared_target)
    off_scope: set[str] = set()
    for t in tools_all:
        tgt = t.get("target", "")
        if not tgt:
            continue
        tgt_norm = _norm_target(tgt)
        if decl_norm not in tgt_norm and tgt_norm not in decl_norm:
            off_scope.add(tgt)
    if off_scope:
        return [f"Possible off-scope targets used: {', '.join(list(off_scope)[:5])}"]
    return []


def _coverage_lines(coverages: list[dict], now: datetime) -> list[str]:
    if not coverages:
        return []
    last_cov   = coverages[-1]
    pending    = last_cov.get("pending", 0)
    tested     = last_cov.get("tested", 0)
    registered = last_cov.get("registered", 0)
    total_cells = pending + tested
    pct = f"{round(pending / total_cells * 100)}%" if total_cells > 0 else "?"
    lines = [
        f"Coverage: {registered} endpoints, {total_cells} cells — "
        f"{tested} tested, {pending} pending ({pct} pending)"
    ]
    try:
        cov_dt = datetime.fromisoformat(last_cov["ts"])
        cov_elapsed = round((now - cov_dt).total_seconds() / 60)
        if cov_elapsed >= 30:
            lines.append(
                f"WARNING: coverage stale ({cov_elapsed} min — "
                f"{pending} cells still pending, run web-exploit)"
            )
        else:
            lines.append(f"Coverage last updated: {cov_elapsed} minutes ago")
    except Exception:
        pass
    return lines


def _finding_lines(findings: list[dict]) -> tuple[list[str], dict[str, int]]:
    if not findings:
        return [], {}
    sev_counts: dict[str, int] = {}
    for f in findings:
        s = f.get("severity", "unknown").lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1
    finding_str = ", ".join(f"{sev_counts[s]} {s}" for s in _SEV_ORDER if s in sev_counts)
    return [f"Findings: {finding_str}"], sev_counts


def _poc_lines(findings: list[dict], sev_counts: dict[str, int]) -> list[str]:
    try:
        high_crit = (sev_counts.get("critical", 0) + sev_counts.get("high", 0)) if findings else 0
        if high_crit > 0:
            pocs_dir = _REPO_ROOT / "pocs"
            poc_count = len(list(pocs_dir.glob("*.http"))) if pocs_dir.exists() else 0
            return [f"PoC files saved: {poc_count} / {high_crit} high/critical findings"]
    except Exception:
        pass
    return []


def _last_tool_line(tools_all: list[dict], now: datetime) -> list[str]:
    if not tools_all:
        return []
    last_tool = tools_all[-1]
    try:
        last_dt = datetime.fromisoformat(last_tool["ts"])
        elapsed = (now - last_dt).total_seconds() / 60
        return [f"Last tool call: {elapsed:.0f} minutes ago ({last_tool['name']})"]
    except Exception:
        return []


class QuickLog:
    def __init__(self, path: Path = _QUICK_LOG_FILE):
        self._path = path
        self._lock = threading.Lock()

    async def append(self, entry: dict) -> None:
        entry.setdefault("ts", datetime.now(timezone.utc).isoformat())
        line = json.dumps(entry) + "\n"
        await asyncio.to_thread(self._write_line, line)

    def _write_line(self, line: str) -> None:
        with self._lock:
            with self._path.open("a", encoding="utf-8") as f:
                f.write(line)

    def read_all(self) -> list[dict]:
        if not self._path.exists():
            return []
        lines = []
        for line in self._path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    lines.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return lines

    def read_since(self, ts: str) -> list[dict]:
        return [e for e in self.read_all() if e.get("ts", "") > ts]

    def summarize(self) -> str:
        entries = self.read_all()
        if not entries:
            return "No activity logged yet."

        now = datetime.now(timezone.utc)
        cutoff_15m = (now - timedelta(minutes=15)).isoformat()

        skills    = [e for e in entries if e.get("type") == "SKILL"]
        tools_all = [e for e in entries if e.get("type") == "TOOL"]
        tools_15m = [e for e in tools_all if e.get("ts", "") > cutoff_15m]
        findings  = [e for e in entries if e.get("type") == "FINDING"]
        spiders   = [e for e in entries if e.get("type") == "SPIDER"]
        coverages = [e for e in entries if e.get("type") == "COVERAGE"]

        session_ls, declared_target = _session_lines(now)
        lines: list[str] = session_ls

        if skills:
            lines.append("Skills invoked: " + ", ".join(e["name"] for e in skills))

        lines += _tool_lines(tools_all, tools_15m)
        lines += _scope_drift_lines(declared_target, tools_all)

        if spiders:
            last = spiders[-1]
            lines.append(f"Endpoints found: {last.get('endpoints_found', '?')} ({last.get('mode', 'spider')})")

        lines += _coverage_lines(coverages, now)
        finding_ls, sev_counts = _finding_lines(findings)
        lines += finding_ls
        lines += _poc_lines(findings, sev_counts)
        lines += _last_tool_line(tools_all, now)

        return "\n".join(lines) if lines else "Session started, no tool calls yet."


quick_log = QuickLog()
