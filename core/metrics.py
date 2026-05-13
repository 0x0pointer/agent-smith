"""
Pentest run metrics
===================
Computes and appends one record to pentest_metrics.jsonl at scan completion.
Each record is a self-contained snapshot — never mutated after writing.

Called from mcp_server/session_tools.py :: _do_complete() after a clean or
force-completed scan.

Schema (all fields always present; None for unavailable):
  run_id            str       session UUID
  ts                str       ISO completion timestamp
  target            str       declared target
  depth             str       recon|standard|thorough
  status            str       complete|incomplete_with_unresolved_blockers|limit_reached
  force_completed   bool

  # Duration
  duration_minutes  float

  # Cost
  total_cost_usd        float
  tool_calls_total      int
  context_chars_total   int
  cost_per_finding      float | None
  tool_calls_per_finding float | None

  # Coverage
  endpoint_count        int
  total_cells           int
  coverage_rate_pct     float   (addressed/total * 100)
  injection_types_tested list[str]
  injection_breadth     int     (unique injection types tested)

  # Findings
  findings_total        int
  findings_critical     int
  findings_high         int
  findings_medium       int
  findings_low          int
  findings_info         int
  poc_coverage_rate_pct float | None   (findings_with_poc / (crit+high) * 100)
  false_positive_count  int
  escalation_completion_rate_pct float | None

  # Context health
  resume_events         int     (RESUME DETECTED in tool_invocations)
  duplicate_tool_calls  int     (DUPLICATE_TOOL_CALL warnings in tool_invocations)
  steering_interventions  int   (total directives in steering_queue history)
  steering_auto_satisfied int   (auto_satisfied directives)

  # Skill chain
  skills_invoked        list[str]
  skill_chain_depth     int
  unsatisfied_gate_count int
  completion_blockers   list[str]

  # Speed
  time_per_skill_minutes dict[str, float]
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

_REPO_ROOT = Path(__file__).parent.parent
_METRICS_FILE = _REPO_ROOT / "pentest_metrics.jsonl"


def record(
    session: dict,
    cost_summary: dict,
    findings_data: dict,
    coverage: dict,
    force_completed: bool,
    completion_blockers: list[str],
    quick_log_entries: list[dict],
    steering_history: list[dict],
) -> dict:
    """Compute metrics and append to pentest_metrics.jsonl. Returns the record."""
    m = _compute(
        session, cost_summary, findings_data, coverage,
        force_completed, completion_blockers, quick_log_entries, steering_history,
    )
    _append(m)
    return m


def load_all() -> list[dict]:
    """Return all historical metric records, oldest first."""
    if not _METRICS_FILE.exists():
        return []
    records = []
    for line in _METRICS_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                records.append(json.loads(line))
            except Exception:
                pass
    return records


# ── Computation ───────────────────────────────────────────────────────────────

def _compute(
    session: dict,
    cost_summary: dict,
    findings_data: dict,
    coverage: dict,
    force_completed: bool,
    completion_blockers: list[str],
    quick_log_entries: list[dict],
    steering_history: list[dict],
) -> dict:
    findings = findings_data.get("findings", [])
    meta = coverage.get("meta", {})
    matrix = coverage.get("matrix", [])
    endpoints = coverage.get("endpoints", [])

    # ── Duration ─────────────────────────────────────────────────────────────
    duration_min = _duration_minutes(session)

    # ── Cost ─────────────────────────────────────────────────────────────────
    total_cost = round(cost_summary.get("est_cost_usd", 0.0), 6)
    tool_calls = cost_summary.get("tool_calls_done", 0)
    context_chars = session.get("context_chars_sent", 0)

    findings_count = len(findings)
    cost_per_finding = round(total_cost / findings_count, 6) if findings_count else None
    calls_per_finding = round(tool_calls / findings_count, 2) if findings_count else None

    # ── Coverage ─────────────────────────────────────────────────────────────
    total_cells = meta.get("total_cells", 0)
    addressed = meta.get("addressed", meta.get("tested", 0) + meta.get("not_applicable", 0))
    coverage_rate = round(addressed / total_cells * 100, 1) if total_cells else 0.0

    tested_statuses = {"tested_clean", "vulnerable"}
    tested_injection_types = sorted({
        c["injection_type"]
        for c in matrix
        if c.get("status") in tested_statuses and c.get("injection_type")
    })

    # ── Findings ─────────────────────────────────────────────────────────────
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        s = f.get("severity", "").lower()
        if s in sev_counts:
            sev_counts[s] += 1

    high_crit_count = sev_counts["critical"] + sev_counts["high"]
    findings_with_poc = sum(1 for f in findings if f.get("poc_files"))
    poc_rate = round(findings_with_poc / high_crit_count * 100, 1) if high_crit_count else None

    false_positives = sum(1 for f in findings if f.get("status") == "false_positive")

    total_leads = sum(len(f.get("escalation_leads", [])) for f in findings)
    done_leads = sum(
        1 for f in findings
        for lead in f.get("escalation_leads", [])
        if lead.get("status") == "done"
    )
    esc_rate = round(done_leads / total_leads * 100, 1) if total_leads else None

    # ── Context health ────────────────────────────────────────────────────────
    invocations = session.get("tool_invocations", [])
    resume_events = sum(
        1 for i in invocations
        if "RESUME DETECTED" in i.get("summary", "")
    )
    duplicate_calls = sum(
        1 for i in invocations
        if "DUPLICATE_TOOL_CALL" in i.get("summary", "")
    )
    # Also check quick_log for QA_REPLY/duplicate markers
    for e in quick_log_entries:
        if e.get("type") == "TOOL" and "DUPLICATE" in e.get("name", ""):
            duplicate_calls += 1

    steering_total = len(steering_history)
    steering_auto = sum(1 for d in steering_history if d.get("status") == "auto_satisfied")

    # ── Skill chain ───────────────────────────────────────────────────────────
    skill_history = session.get("skill_history", [])
    skills_invoked = [
        (e["skill"] if isinstance(e, dict) else e)
        for e in skill_history
    ]

    gates = session.get("gates", [])
    unsatisfied_gates = sum(1 for g in gates if g.get("status") != "satisfied")

    # ── Time per skill (from quick_log SKILL events) ──────────────────────────
    time_per_skill = _compute_time_per_skill(quick_log_entries)

    return {
        # Identity
        "run_id":   session.get("id", ""),
        "ts":       session.get("finished") or datetime.now(timezone.utc).isoformat(),
        "target":   session.get("target", ""),
        "depth":    session.get("depth", ""),
        "status":   session.get("status", "complete"),
        "force_completed": force_completed,

        # Duration
        "duration_minutes": duration_min,

        # Cost
        "total_cost_usd":          total_cost,
        "tool_calls_total":        tool_calls,
        "context_chars_total":     context_chars,
        "cost_per_finding":        cost_per_finding,
        "tool_calls_per_finding":  calls_per_finding,

        # Coverage
        "endpoint_count":          len(endpoints),
        "total_cells":             total_cells,
        "coverage_rate_pct":       coverage_rate,
        "injection_types_tested":  tested_injection_types,
        "injection_breadth":       len(tested_injection_types),

        # Findings
        "findings_total":          findings_count,
        "findings_critical":       sev_counts["critical"],
        "findings_high":           sev_counts["high"],
        "findings_medium":         sev_counts["medium"],
        "findings_low":            sev_counts["low"],
        "findings_info":           sev_counts["info"],
        "poc_coverage_rate_pct":   poc_rate,
        "false_positive_count":    false_positives,
        "escalation_completion_rate_pct": esc_rate,

        # Context health
        "resume_events":            resume_events,
        "duplicate_tool_calls":     duplicate_calls,
        "steering_interventions":   steering_total,
        "steering_auto_satisfied":  steering_auto,

        # Skill chain
        "skills_invoked":          skills_invoked,
        "skill_chain_depth":       len(set(skills_invoked)),
        "unsatisfied_gate_count":  unsatisfied_gates,
        "completion_blockers":     completion_blockers,

        # Speed
        "time_per_skill_minutes":  time_per_skill,
    }


def _duration_minutes(session: dict) -> float:
    try:
        started  = datetime.fromisoformat(session["started"])
        finished = datetime.fromisoformat(session["finished"])
        return round((finished - started).total_seconds() / 60, 1)
    except Exception:
        return 0.0


def _compute_time_per_skill(entries: list[dict]) -> dict[str, float]:
    """Compute minutes spent in each skill by bucketing TOOL events between SKILL events."""
    skill_events = [(e["ts"], e.get("name", "")) for e in entries if e.get("type") == "SKILL"]
    tool_events  = [(e["ts"],) for e in entries if e.get("type") in ("TOOL", "SPIDER")]

    if not skill_events:
        return {}

    result: dict[str, float] = {}
    # Build time windows: skill_name → (start_ts, end_ts)
    windows: list[tuple[str, str, str]] = []
    for i, (ts, name) in enumerate(skill_events):
        end_ts = skill_events[i + 1][0] if i + 1 < len(skill_events) else ""
        windows.append((name, ts, end_ts))

    for name, start_ts, end_ts in windows:
        # Count tool events in this window
        in_window = [
            t[0] for t in tool_events
            if t[0] >= start_ts and (not end_ts or t[0] < end_ts)
        ]
        if not in_window:
            continue
        try:
            start_dt = datetime.fromisoformat(start_ts)
            end_dt   = datetime.fromisoformat(in_window[-1])
            mins = round((end_dt - start_dt).total_seconds() / 60, 1)
            result[name] = result.get(name, 0.0) + mins
        except Exception:
            pass

    return result


def _append(record: dict) -> None:
    try:
        line = json.dumps(record, separators=(",", ":")) + "\n"
        with _METRICS_FILE.open("a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass
