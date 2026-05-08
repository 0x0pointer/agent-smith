"""
QA Agent
========
Two-layer QA reviewer that runs every 2 minutes during an active scan.

Layer 1 — Deterministic Python rules
  Reads quick_log.summarize(), findings.json, and coverage_matrix.json.
  Produces coded, typed alerts without any LLM call.

Layer 2 — Semantic LLM review
  Only invoked when there are high/critical findings to review.
  Checks: overclaimed severity, vague descriptions, missing attack chains.
  Provider-agnostic via QA_MODEL env var:

    QA_MODEL=openai:gpt-4o-mini               (default)
    QA_MODEL=anthropic:claude-haiku-4-5-20251001
    QA_MODEL=ollama:qwen2.5:7b

Alert schema
  {
    "code":     str,   — machine-readable code (SCOPE_DRIFT, COVERAGE_STALL, …)
    "urgency":  str,   — "high" | "medium" | "low"
    "blocking": bool,  — true = this alert blocks scan completion
    "message":  str,   — human-readable description
  }
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict

_log = logging.getLogger(__name__)
_REPO_ROOT      = Path(__file__).parent.parent
_QA_STATE_FILE  = _REPO_ROOT / "qa_state.json"
_SESSION_FILE   = _REPO_ROOT / "session.json"
_FINDINGS_FILE  = _REPO_ROOT / "findings.json"
_COVERAGE_FILE  = _REPO_ROOT / "coverage_matrix.json"


# ── Deterministic checks ──────────────────────────────────────────────────────

def _deterministic_qa_checks(
    summary: str,
    findings_data: dict,
    coverage_data: dict,
) -> list[dict]:
    """Rule-based checks over the summary text and structured state.

    Returns a list of alert dicts: {code, urgency, blocking, message}.
    """
    alerts: list[dict] = []

    # SCOPE_DRIFT — tool ran against a target outside the declared scope
    if "Possible off-scope targets used:" in summary:
        m = re.search(r"Possible off-scope targets used: (.+)", summary)
        targets = m.group(1).strip() if m else "unknown"
        alerts.append({
            "code": "SCOPE_DRIFT", "urgency": "high", "blocking": False,
            "message": f"Scope drift: tools ran against {targets}",
        })

    # COVERAGE_STALL — no coverage update for >30 min and cells still pending
    stall_m   = re.search(r"WARNING: coverage stale \((\d+) min", summary)
    pending_m = re.search(r",\s*(\d+) pending", summary)
    if stall_m and pending_m:
        mins    = int(stall_m.group(1))
        pending = int(pending_m.group(1))
        if pending > 0:
            alerts.append({
                "code": "COVERAGE_STALL", "urgency": "high", "blocking": False,
                "message": f"Coverage stall — {pending} cells untested, last update {mins}min ago",
            })

    # SPIDER_WITHOUT_COVERAGE — spider ran but matrix is still empty
    if "Endpoints found:" in summary:
        cov_meta = coverage_data.get("meta", {})
        if cov_meta.get("total_cells", 0) == 0:
            m = re.search(r"Endpoints found: (\S+)", summary)
            count = m.group(1) if m else "?"
            alerts.append({
                "code": "SPIDER_WITHOUT_COVERAGE", "urgency": "high", "blocking": False,
                "message": f"Spider found {count} endpoint(s) but coverage matrix is empty — register endpoints",
            })

    # POC_GAP — high/critical finding has no linked PoC file (per-finding check)
    high_crit   = [f for f in findings_data.get("findings", [])
                   if f.get("severity") in ("high", "critical")]
    missing_poc = [f for f in high_crit if not f.get("poc_files")]
    if missing_poc:
        titles = ", ".join(f["title"] for f in missing_poc[:3])
        if len(missing_poc) > 3:
            titles += f" +{len(missing_poc) - 3} more"
        alerts.append({
            "code": "POC_GAP", "urgency": "medium", "blocking": False,
            "message": f"PoC gap: {len(missing_poc)}/{len(high_crit)} high/critical findings have no saved PoC: {titles}",
        })

    # SKILL_CHAIN_GAP — high/critical findings but web-exploit skill never invoked
    if "Findings:" in summary and "web-exploit" not in summary:
        sev_m = re.search(r"Findings: (.+)", summary)
        if sev_m and ("critical" in sev_m.group(1) or " high" in sev_m.group(1)):
            alerts.append({
                "code": "SKILL_CHAIN_GAP", "urgency": "medium", "blocking": False,
                "message": "High/critical findings but web-exploit not yet chained — run /web-exploit",
            })

    # TOOL_INACTIVITY — no tool call for >10 min
    inact_m = re.search(r"Last tool call: (\d+) minutes ago", summary)
    if inact_m:
        mins = int(inact_m.group(1))
        if mins > 10:
            alerts.append({
                "code": "TOOL_INACTIVITY", "urgency": "low", "blocking": False,
                "message": f"No tool activity in {mins}min — is Smith stuck?",
            })

    # BULK_MARKING — many N/A cells without tested_by tool
    if "Bulk-marking warning:" in summary:
        m = re.search(r"Bulk-marking warning: (.+?)(?:\n|$)", summary)
        detail = m.group(1).strip() if m else "N/A cells have no tested_by tool"
        alerts.append({
            "code": "BULK_MARKING", "urgency": "high", "blocking": True,
            "message": f"Bulk-marking detected: {detail}",
        })

    # COVERAGE_INTEGRITY — tested/vulnerable cells with no tested_by
    integ_m = re.search(r"(\d+) tested/vulnerable cells have no tested_by tool", summary)
    if integ_m:
        count = integ_m.group(1)
        alerts.append({
            "code": "COVERAGE_INTEGRITY", "urgency": "high", "blocking": True,
            "message": f"Coverage integrity: {count} tested/vulnerable cells lack tested_by tool",
        })

    # GATE_PENDING — mandatory skill gate not yet satisfied
    gate_m = re.search(r"Pending gates: (.+?)(?:\n|$)", summary)
    if gate_m:
        gate_info = gate_m.group(1)
        time_m    = re.search(r"triggered (\d+)min ago", gate_info)
        elapsed   = int(time_m.group(1)) if time_m else 0
        if elapsed >= 5:
            urgency   = "high" if elapsed >= 15 else "medium"
            gid_m     = re.search(r"^(\S+) \(", gate_info)
            gate_id   = gid_m.group(1) if gid_m else "unknown"
            req_m     = re.search(r"requires: (.+?)\)", gate_info)
            requires  = req_m.group(1) if req_m else "required skill"
            alerts.append({
                "code": "GATE_PENDING", "urgency": urgency, "blocking": False,
                "message": f"Gate {gate_id} pending {elapsed}min — chain {requires} or dismiss",
            })

    # RCE_GATE_FALSE_POSITIVE — rce gate open but only low/medium/info findings
    if gate_m and "rce" in gate_m.group(1).lower():
        sev_m = re.search(r"Findings: (.+)", summary)
        if sev_m:
            sev_str = sev_m.group(1)
            if "critical" not in sev_str and " high" not in sev_str:
                alerts.append({
                    "code": "RCE_GATE_FALSE_POSITIVE", "urgency": "medium", "blocking": False,
                    "message": "RCE gate may be a false positive — verify finding severity",
                })

    return alerts


# ── Semantic LLM review ───────────────────────────────────────────────────────

# Prompt focuses only on what a Python rule cannot assess: semantic quality.
QA_SYSTEM_PROMPT = """\
You are a QA reviewer for a penetration test. Review the finding quality below.

For each high or critical finding, check:
1. Is the severity plausibly overclaimed? (e.g. an info-disclosure marked critical)
2. Is the description so vague it is not actionable by a developer?
3. Is business impact absent or generic for a high/critical finding?
4. Is an obvious next attack path missing? (e.g. auth bypass + IDOR suggests priv-esc path)

Only flag issues you can justify from the finding text. Do NOT flag missing PoCs or coverage
gaps — those are handled by deterministic checks and will appear separately.

Output ONLY valid JSON — no markdown, no explanation:
{"alerts": [{"code": "FINDING_QUALITY", "urgency": "high|medium", "blocking": false, "message": "..."}]}
Max 2 alerts. If no semantic issues, return {"alerts": []}.
"""


# ── LangGraph wiring ──────────────────────────────────────────────────────────

class QAState(TypedDict):
    summary: str
    raw_response: str
    alerts: list[dict]


def _init_llm(model_name: str, max_tokens: int = 512):
    provider, _, model = model_name.partition(":")
    if not model:
        provider, model = "openai", model_name
    if provider == "openai":
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(model=model, max_tokens=max_tokens)
    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(model=model, max_tokens=max_tokens)
    if provider == "ollama":
        from langchain_ollama import ChatOllama
        return ChatOllama(model=model, num_predict=max_tokens)
    raise ValueError(f"Unknown QA_MODEL provider {provider!r}. Use openai:MODEL, anthropic:MODEL, or ollama:MODEL")


def _build_graph():
    """Build and return the LangGraph semantic QA graph, or None if deps are missing."""
    try:
        from langgraph.graph import StateGraph, END
    except ImportError as exc:
        _log.warning("QA Agent: langgraph / langchain-core not installed (%s). Semantic review disabled.", exc)
        return None

    model_name = os.getenv("QA_MODEL", "openai:gpt-4o-mini")
    try:
        llm = _init_llm(model_name)
    except Exception as exc:
        _log.warning("QA Agent: could not initialise model %s — %s", model_name, exc)
        return None

    def invoke_llm(state: QAState) -> QAState:
        from langchain_core.messages import SystemMessage, HumanMessage
        response = llm.invoke([
            SystemMessage(content=QA_SYSTEM_PROMPT),
            HumanMessage(content=state["summary"]),
        ])
        return {**state, "raw_response": response.content}

    def parse_response(state: QAState) -> QAState:
        try:
            alerts = json.loads(state["raw_response"]).get("alerts", [])
            if not isinstance(alerts, list):
                alerts = []
        except (json.JSONDecodeError, AttributeError):
            alerts = []
        # Ensure every alert has the required schema fields
        cleaned = []
        for a in alerts:
            if isinstance(a, dict) and a.get("message"):
                cleaned.append({
                    "code":     str(a.get("code", "FINDING_QUALITY")),
                    "urgency":  str(a.get("urgency", "medium")),
                    "blocking": bool(a.get("blocking", False)),
                    "message":  str(a["message"]),
                })
        return {**state, "alerts": cleaned}

    graph = StateGraph(QAState)
    graph.add_node("invoke_llm", invoke_llm)
    graph.add_node("parse_response", parse_response)
    graph.set_entry_point("invoke_llm")
    graph.add_edge("invoke_llm", "parse_response")
    graph.add_edge("parse_response", END)
    return graph.compile()


def _format_findings_for_semantic_review(findings_data: dict) -> str:
    """Format high/critical findings as compact text for the LLM."""
    high_crit = [
        f for f in findings_data.get("findings", [])
        if f.get("severity") in ("high", "critical")
    ]
    if not high_crit:
        return ""
    lines = []
    for f in high_crit[:10]:
        lines.append(
            f"[{f['severity'].upper()}] {f['title']}\n"
            f"  description: {(f.get('description') or '')[:300]}\n"
            f"  evidence: {(f.get('evidence') or '')[:200]}\n"
            f"  business_impact: {(f.get('business_impact') or 'not set')}"
        )
    return "\n\n".join(lines)


# ── State helpers ─────────────────────────────────────────────────────────────

def _session_is_running() -> bool:
    try:
        data = json.loads(_SESSION_FILE.read_text())
        return data.get("status") == "running"
    except Exception:
        return False


def _read_qa_state() -> dict:
    if not _QA_STATE_FILE.exists():
        return {}
    try:
        return json.loads(_QA_STATE_FILE.read_text())
    except Exception:
        return {}


def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text()) if path.exists() else {}
    except Exception:
        return {}


def _deduplicate(new_alerts: list[dict], previous_alerts: list[dict]) -> list[dict]:
    """Drop alerts whose code+message were already raised at same/higher urgency last cycle."""
    _URGENCY = {"high": 2, "medium": 1, "low": 0}
    prev_by_code: dict[str, dict] = {}
    for a in previous_alerts:
        code = a.get("code", "")
        if code and (_URGENCY.get(a.get("urgency", ""), 0) >= _URGENCY.get(prev_by_code.get(code, {}).get("urgency", "low"), 0)):
            prev_by_code[code] = a

    result = []
    for a in new_alerts:
        prev = prev_by_code.get(a.get("code", ""))
        if prev and prev.get("message") == a.get("message"):
            continue  # unchanged — skip to avoid noise
        result.append(a)
    return result


def _sanitize_history(raw: list) -> list[dict]:
    result = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        reply = entry.get("smith_reply")
        result.append({
            "ts":            str(entry.get("ts", ""))[:50],
            "summary_sent":  str(entry.get("summary_sent", "")),
            "alerts":        [a for a in entry.get("alerts", []) if isinstance(a, dict)][:10],
            "smith_reply":   str(reply)[:2000] if reply else None,
            "smith_actions": [a for a in entry.get("smith_actions", []) if isinstance(a, dict)][:50],
        })
    return result


# ── Daemon ────────────────────────────────────────────────────────────────────

class QADaemon:
    def __init__(self):
        self._graph = None
        self._graph_built = False

    def _get_graph(self):
        if not self._graph_built:
            self._graph = _build_graph()
            self._graph_built = True
        return self._graph

    async def run(self, interval_s: int = 120) -> None:
        _log.info("QA Daemon started (interval=%ds)", interval_s)
        while True:
            await asyncio.sleep(interval_s)
            try:
                await self._cycle()
            except Exception as exc:
                _log.warning("QA Daemon cycle error: %s", exc)

    async def _cycle(self) -> None:
        if not _session_is_running():
            return

        from core.quick_log import quick_log
        summary = quick_log.summarize()
        if not summary.strip() or summary == "No activity logged yet.":
            return

        findings_data = _load_json(_FINDINGS_FILE)
        coverage_data = _load_json(_COVERAGE_FILE)

        # Layer 1: deterministic checks — always run, no LLM cost
        determ_alerts = _deterministic_qa_checks(summary, findings_data, coverage_data)

        # Layer 2: semantic LLM review — only when there are high/critical findings
        semantic_alerts: list[dict] = []
        finding_text = _format_findings_for_semantic_review(findings_data)
        if finding_text:
            graph = self._get_graph()
            if graph is not None:
                try:
                    result = await asyncio.to_thread(
                        graph.invoke,
                        {"summary": finding_text, "raw_response": "", "alerts": []},
                    )
                    semantic_alerts = result.get("alerts", [])
                except Exception as exc:
                    _log.warning("QA Daemon: semantic review failed — %s", exc)

        all_alerts = determ_alerts + semantic_alerts

        existing       = _read_qa_state()
        previous_alerts: list[dict] = existing.get("alerts", [])

        # Deduplicate against last cycle to reduce noise
        unique_alerts = _deduplicate(all_alerts, previous_alerts)
        if not unique_alerts and not all_alerts:
            return

        # Cap at 4 alerts (deterministic takes priority over semantic)
        final_alerts = (all_alerts if not unique_alerts else unique_alerts)[:4]

        ts_before = datetime.now(timezone.utc).isoformat()

        # Re-read after async work so a Clear All during inference is respected
        post_existing = _read_qa_state()
        history       = _sanitize_history(post_existing.get("history", []))
        prev_cycle_ts = history[-1]["ts"] if history else ""
        events_since  = quick_log.read_since(prev_cycle_ts) if prev_cycle_ts else []

        smith_reply = " ".join(
            e["message"] for e in events_since
            if e.get("type") == "QA_REPLY" and e.get("message")
        ).strip() or None
        smith_actions = [e for e in events_since if e.get("type") != "QA_REPLY"]

        history.append({
            "ts":            ts_before,
            "summary_sent":  summary,
            "alerts":        final_alerts,
            "smith_reply":   smith_reply,
            "smith_actions": smith_actions,
        })

        _QA_STATE_FILE.write_text(json.dumps({
            "ts":      datetime.now(timezone.utc).isoformat(),
            "alerts":  final_alerts,
            "history": history[-20:],
        }))

        _log.info("QA Daemon: %d alert(s) written (%d determ, %d semantic)",
                  len(final_alerts), len(determ_alerts), len(semantic_alerts))


qa_daemon = QADaemon()
