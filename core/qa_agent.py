"""
QA Agent
========
LangGraph-based QA reviewer that reads quick_log.json and surfaces
workflow gaps as alerts every 2 minutes during an active scan.

Runs as a background asyncio task inside the FastAPI dashboard server.
Provider-agnostic via QA_MODEL env var:

  QA_MODEL=openai:gpt-4o-mini               (default)
  QA_MODEL=anthropic:claude-haiku-4-5-20251001
  QA_MODEL=ollama:qwen2.5:7b               (recommended local — reliable JSON output)

Install only the provider package you need:
  pip install langchain-openai     # OpenAI
  pip install langchain-anthropic  # Anthropic
  pip install langchain-ollama     # Ollama
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict

_log = logging.getLogger(__name__)
_REPO_ROOT      = Path(__file__).parent.parent
_QA_STATE_FILE  = _REPO_ROOT / "qa_state.json"
_SESSION_FILE   = _REPO_ROOT / "session.json"

QA_SYSTEM_PROMPT = """\
You are a QA reviewer for a live penetration test. Work through the checklist below
IN ORDER. For each check: read the exact line required, answer YES or NO, then act.
Never infer, guess, or apply a rule to data that is not literally present in the summary.

## CHECKLIST

CHECK 1 — Scope drift
  Required line: "Possible off-scope targets used: <targets>"
  If that EXACT line exists → flag high: "Scope drift: tools ran against <targets>"
  If absent → SKIP. Do NOT mention scope drift.

CHECK 2 — RCE false-positive gate
  Required: "Pending gates:" line contains the word "rce" or "post_exploit_rce"
  AND "Findings:" line shows only medium/low/info severity
  If BOTH true → flag medium: "RCE gate may be a false positive — verify finding severity"
  Otherwise → SKIP. Do NOT apply this check to any other gate name (e.g. credential_audit).

CHECK 3 — Pending gate (first time or escalation)
  Required: "Pending gates:" line exists
  Read the elapsed time shown in parentheses, e.g. "(triggered 8min ago)"
  - 5–14 min AND gate not in "Previously flagged" → flag medium: "Gate <id> pending <N>min — chain <skill> or dismiss"
  - 15–29 min AND high not already flagged for this gate → flag high
  - ≥30 min → flag high
  - <5 min OR already flagged at same/higher urgency → SKIP

CHECK 4 — Coverage stall
  Required: "Coverage last updated: N minutes ago" line exists AND N > 30
  AND "pending" cell count > 0
  If both true → flag high: "Coverage stall — <pending> cells untested, last update <N>min ago"
  Otherwise → SKIP. Do NOT flag this if the line is absent or N ≤ 30.

CHECK 5 — Spider without coverage
  Required: "Endpoints found:" line exists AND coverage shows 0 cells tested AND 0 cells pending
  If true → flag high: "Spider found endpoints but coverage matrix is empty — register endpoints"
  Otherwise → SKIP

CHECK 6 — Missing PoC files
  Required: "PoC files saved: X / Y" line exists AND X < Y
  If true → flag medium: "PoC gap: <X> of <Y> high/critical findings have no saved PoC"
  If line is absent → SKIP. Do NOT mention PoCs.

CHECK 7 — Skill chaining gap
  Required: "Findings:" line shows critical or high AND "Skills invoked:" does NOT contain "web-exploit"
  If true AND not in "Previously flagged" → flag medium: "High/critical findings but web-exploit not yet chained — run /web-exploit"
  Otherwise → SKIP

CHECK 8 — Tool inactivity
  Required: "Last tool call:" line shows > 10 minutes ago
  If true → flag low: "No tool activity in <N>min — is Smith stuck?"
  Otherwise → SKIP

## Deduplication
"Previously flagged (last cycle):" lists what was already raised. Do NOT repeat the same
alert unless the situation materially escalated (e.g. elapsed time crossed a new threshold).

## Minimum data threshold
If summary contains only a skill invocation (no findings, no tools, no coverage) → return {"alerts": []}

## Output format
Output ONLY valid JSON — no markdown, no explanation:
{"alerts": [{"urgency": "high|medium|low", "message": "..."}]}
Max 3 alerts. If nothing to flag, return {"alerts": []}.
"""


class QAState(TypedDict):
    summary: str
    raw_response: str
    alerts: list[dict]


def _init_llm(model_name: str, max_tokens: int = 512):
    """Direct provider dispatch — no dependency on langchain.chat_models.init_chat_model."""
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
    """Build and return the LangGraph QA graph, or None if deps are missing."""
    try:
        from langgraph.graph import StateGraph, END
        from langchain_core.messages import SystemMessage, HumanMessage
    except ImportError as exc:
        _log.warning(
            "QA Agent: langgraph / langchain-core not installed (%s). "
            "Install them to enable the QA daemon.",
            exc,
        )
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
        return {**state, "alerts": alerts}

    graph = StateGraph(QAState)
    graph.add_node("invoke_llm", invoke_llm)
    graph.add_node("parse_response", parse_response)
    graph.set_entry_point("invoke_llm")
    graph.add_edge("invoke_llm", "parse_response")
    graph.add_edge("parse_response", END)
    return graph.compile()


def _session_is_running() -> bool:
    try:
        data = json.loads(_SESSION_FILE.read_text())
        return data.get("status") == "running"
    except Exception:
        return False


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

        graph = self._get_graph()
        if graph is None:
            return

        from core.quick_log import quick_log
        summary = quick_log.summarize()
        if not summary.strip() or summary == "No activity logged yet.":
            return

        # Load existing state for deduplication and context injection
        existing: dict = {}
        if _QA_STATE_FILE.exists():
            try:
                existing = json.loads(_QA_STATE_FILE.read_text())
            except Exception:
                pass

        previous_alerts: list[dict] = existing.get("alerts", [])

        # Inject previous alerts so the model knows what it already flagged
        if previous_alerts:
            prev_lines = "\n".join(
                f"- [{a['urgency']}] {a['message']}" for a in previous_alerts
            )
            summary_with_ctx = summary + f"\n\nPreviously flagged (last cycle):\n{prev_lines}"
        else:
            summary_with_ctx = summary

        ts_before = datetime.now(timezone.utc).isoformat()

        result = await asyncio.to_thread(
            graph.invoke,
            {"summary": summary_with_ctx, "raw_response": "", "alerts": []},
        )
        alerts = result.get("alerts", [])

        # Hard deduplication: if all new alert messages match previous ones exactly, skip
        new_msgs  = sorted(a.get("message", "") for a in alerts)
        prev_msgs = sorted(a.get("message", "") for a in previous_alerts)
        if new_msgs and new_msgs == prev_msgs:
            _log.info("QA Daemon: alerts unchanged — skipping write")
            return

        # Re-read history after the LLM call so a Clear All that fired during inference
        # is respected — otherwise we'd write the old cycles back and undo the clear.
        post_existing: dict = {}
        if _QA_STATE_FILE.exists():
            try:
                post_existing = json.loads(_QA_STATE_FILE.read_text())
            except Exception:
                pass

        # smith_actions: what Smith did *since the previous cycle* — captures his response
        # to the last set of alerts, not what happened during this LLM inference window.
        history: list[dict] = post_existing.get("history", [])
        prev_cycle_ts = history[-1]["ts"] if history else ""
        smith_actions = quick_log.read_since(prev_cycle_ts) if prev_cycle_ts else []

        history.append({
            "ts":            ts_before,
            "summary_sent":  summary,
            "alerts":        alerts,
            "smith_actions": smith_actions,
        })

        _QA_STATE_FILE.write_text(json.dumps({
            "ts":      datetime.now(timezone.utc).isoformat(),
            "alerts":  alerts,
            "history": history[-20:],
        }))

        _log.info("QA Daemon: %d alert(s) written to qa_state.json", len(alerts))


qa_daemon = QADaemon()
