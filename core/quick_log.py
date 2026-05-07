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
from datetime import datetime, timedelta, timezone
from pathlib import Path

_REPO_ROOT = Path(__file__).parent.parent
_QUICK_LOG_FILE = _REPO_ROOT / "quick_log.json"

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


class QuickLog:
    def __init__(self, path: Path = _QUICK_LOG_FILE):
        self._path = path
        self._lock = asyncio.Lock()

    async def append(self, entry: dict) -> None:
        entry.setdefault("ts", datetime.now(timezone.utc).isoformat())
        async with self._lock:
            with open(self._path, "a") as f:
                f.write(json.dumps(entry) + "\n")

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

        lines: list[str] = []

        # ── Session context from session.json ─────────────────────────────────
        session_file = _REPO_ROOT / "session.json"
        declared_target = ""
        try:
            import json as _json
            sd = _json.loads(session_file.read_text())
            declared_target = sd.get("target", "")
            if declared_target:
                lines.append(f"Declared target: {declared_target}")
            depth = sd.get("depth", "")
            if depth:
                lines.append(f"Scan depth: {depth}")
            gates = sd.get("gates", [])
            if gates:
                pending_gates = []
                for g in gates:
                    if g.get("status") == "satisfied":
                        continue
                    elapsed_min = "?"
                    try:
                        trig = datetime.fromisoformat(g["triggered_at"])
                        elapsed_min = round((now - trig).total_seconds() / 60)
                    except Exception:
                        pass
                    pending_gates.append(
                        f"{g['id']} (triggered {elapsed_min}min ago, requires: {', '.join(g.get('required_skills', []))})"
                    )
                if pending_gates:
                    lines.append("Pending gates: " + "; ".join(pending_gates))
                satisfied = [g["id"] for g in gates if g.get("status") == "satisfied"]
                if satisfied:
                    lines.append("Satisfied gates: " + ", ".join(satisfied))
        except Exception:
            pass

        if skills:
            lines.append("Skills invoked: " + ", ".join(e["name"] for e in skills))

        if tools_15m:
            tool_counts: dict[str, int] = {}
            for t in tools_15m:
                tool_counts[t["name"]] = tool_counts.get(t["name"], 0) + 1
            lines.append("Tools run (last 15min): " + ", ".join(f"{n}({c})" for n, c in tool_counts.items()))
        elif tools_all:
            lines.append("Tools run (last 15min): none")

        # Scope drift check — unique tool targets vs declared target
        # Normalize Docker-internal aliases so host.docker.internal == localhost
        _DOCKER_ALIASES = {"host.docker.internal", "172.17.0.1", "172.18.0.1"}
        def _norm(t: str) -> str:
            for alias in _DOCKER_ALIASES:
                t = t.replace(alias, "localhost")
            return t
        if declared_target and tools_all:
            off_scope = set()
            decl_norm = _norm(declared_target)
            for t in tools_all:
                tgt = t.get("target", "")
                if not tgt:
                    continue
                tgt_norm = _norm(tgt)
                if decl_norm not in tgt_norm and tgt_norm not in decl_norm:
                    off_scope.add(tgt)
            if off_scope:
                lines.append(f"Possible off-scope targets used: {', '.join(list(off_scope)[:5])}")

        if spiders:
            last = spiders[-1]
            lines.append(
                f"Endpoints found: {last.get('endpoints_found', '?')} ({last.get('mode', 'spider')})"
            )

        if coverages:
            last_cov   = coverages[-1]
            pending    = last_cov.get("pending", 0)
            tested     = last_cov.get("tested", 0)
            registered = last_cov.get("registered", 0)
            total_cells = pending + tested
            pct        = f"{round(pending / total_cells * 100)}%" if total_cells > 0 else "?"
            lines.append(
                f"Coverage: {registered} endpoints, {total_cells} cells — "
                f"{tested} tested, {pending} pending ({pct} pending)"
            )
            # Emit a timestamp so QA can reason about staleness accurately
            try:
                cov_dt = datetime.fromisoformat(last_cov["ts"])
                cov_elapsed = round((now - cov_dt).total_seconds() / 60)
                lines.append(f"Coverage last updated: {cov_elapsed} minutes ago")
            except Exception:
                pass

        if findings:
            sev_counts: dict[str, int] = {}
            for f in findings:
                s = f.get("severity", "unknown").lower()
                sev_counts[s] = sev_counts.get(s, 0) + 1
            finding_str = ", ".join(
                f"{sev_counts[s]} {s}"
                for s in _SEV_ORDER
                if s in sev_counts
            )
            lines.append(f"Findings: {finding_str}")

        # PoC file count — only report when there are confirmed high/critical findings
        try:
            high_crit = (sev_counts.get("critical", 0) + sev_counts.get("high", 0)) if findings else 0
            if high_crit > 0:
                pocs_dir = _REPO_ROOT / "pocs"
                poc_count = len(list(pocs_dir.glob("*.http"))) if pocs_dir.exists() else 0
                lines.append(f"PoC files saved: {poc_count} / {high_crit} high/critical findings")
        except Exception:
            pass

        if tools_all:
            last_tool = tools_all[-1]
            try:
                last_dt = datetime.fromisoformat(last_tool["ts"])
                elapsed = (now - last_dt).total_seconds() / 60
                lines.append(f"Last tool call: {elapsed:.0f} minutes ago ({last_tool['name']})")
            except Exception:
                pass

        return "\n".join(lines) if lines else "Session started, no tool calls yet."


quick_log = QuickLog()
