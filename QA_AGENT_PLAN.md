# QA Agent + Quick Log — Feature Plan

## What is this?

A lightweight QA layer that watches what the pentest agent (Smith) is doing during a live test, identifies workflow gaps, and surfaces actionable alerts — both in the dashboard and directly in Smith's own status responses so it can self-correct.

Works identically in **Claude Code** and **opencode**. No client-specific code anywhere.

---

## The core idea

During a pentest, Smith runs tools and logs results. A human operator would occasionally ask: _"why haven't you run credential-audit yet?"_ or _"the coverage matrix has 80 pending cells and you haven't touched them in 10 minutes."_

The QA Agent automates that oversight. It reads a compact event feed (`quick_log.json`), runs it through an LLM every 2 minutes, and writes alerts to `qa_state.json`. Smith reads those alerts at its next natural decision point — exactly like reading a message from a human operator. No running tool is ever interrupted.

---

## Architecture

```
[Smith (Claude Code or opencode)]
        │ calls MCP tools
        ▼
[MCP Server] ──writes──► quick_log.json   (compact append-only event feed)
                  └──writes──► session.json / findings.json / coverage_matrix.json

[QA Daemon]  ──reads──► quick_log.json  (single source of truth)
  (asyncio task         uses LangGraph + init_chat_model (provider-agnostic)
   inside API server)   writes──► qa_state.json  { ts, alerts, history[] }

[Dashboard API] ─ serves ─► /api/qa        (qa_state.json — alerts + history)
                             /api/quicklog   (quick_log.json — event feed)

[session(action="status")] ─ includes ─► qa_alerts from qa_state.json

[Dashboard tabs]
  QA Agent tab    ──► Current alerts + Quick Log timeline
  Conversation tab ──► Chat thread: QA bubbles (left) / Smith actions (right)
```

### Non-interrupting by design

The QA daemon is purely passive — it writes to `qa_state.json` and does nothing else. Smith only sees alerts the next time it calls `session(action="status")`, which happens naturally at decision points between tool calls. No in-flight tool call is ever interrupted.

This is identical to how a human steers Smith during a live test by typing a message: Smith finishes the current tool, then picks up the new direction on its next decision step.

---

## Quick Log (`quick_log.json`)

Append-only JSONL file. Every MCP tool call, skill change, finding, and coverage update writes one line. The QA daemon reads only this file — no other state needed.

```jsonc
// Smith invoked a skill
{"ts":"...", "type":"SKILL", "name":"web-exploit", "reason":"...", "chained_from":null}

// A tool call completed
{"ts":"...", "type":"TOOL", "name":"nuclei", "target":"https://...", "duration_s":4.2}

// A finding was logged
{"ts":"...", "type":"FINDING", "severity":"HIGH", "title":"SQLi in /search", "target":"..."}

// Coverage matrix updated
{"ts":"...", "type":"COVERAGE", "registered":23, "pending":86, "tested":4, "vulnerable":1}

// Spider completed
{"ts":"...", "type":"SPIDER", "target":"...", "endpoints_found":23, "mode":"playwright"}
```

The `summarize()` method aggregates this into a compact text block for the QA LLM:

```
Skills invoked: pentester, web-exploit
Tools run (last 15min): spider(1), nuclei(1), ffuf(0), http(3)
Endpoints found: 23 (playwright spider)
Coverage: 23 endpoints, 86 cells — 4 tested, 82 pending (95% pending)
Findings: 0 critical, 1 high, 2 medium
Last tool call: 11 minutes ago (http)
```

---

## QA Agent (`core/qa_agent.py`)

Uses **LangGraph** + **LangChain's `init_chat_model()`** — fully provider-agnostic. Set one env var, use any model:

```bash
QA_MODEL=anthropic:claude-haiku-4-5-20251001   # Anthropic
QA_MODEL=openai:gpt-4o-mini                    # OpenAI (default)
QA_MODEL=ollama:llama3                         # Local Ollama
```

Install only the provider you need:
```
langgraph
langchain-core
langchain-openai      # if using OpenAI
langchain-anthropic   # if using Anthropic
langchain-ollama      # if using Ollama
```

The LangGraph graph is two nodes: `invoke_llm` → `parse_response`. The LLM outputs JSON-only:

```json
{"alerts": [{"urgency": "high|medium|low", "message": "..."}]}
```

The system prompt encodes pentest workflow rules:
1. Spider must be followed by coverage matrix registration
2. `credential-audit` must run when auth services are found
3. `post-exploit` must run when an RCE gate is triggered
4. No tool silence > 10 minutes during a running session
5. Coverage cells > 50% pending with no recent testing → warning
6. Skills should chain: `pentester → web-exploit → post-exploit`
7. Findings logged but no escalation attempts → follow-through missing
8. Re-spider must run after new credentials or privilege escalation

---

## QA Daemon

Runs as a background `asyncio.create_task()` inside the existing FastAPI server — no extra process.

Every 2 minutes (when a session is running):
1. Calls `quick_log.summarize()` to build the compact event summary
2. Records the timestamp (`ts_before`) — used to capture Smith's response actions later
3. Invokes the LangGraph graph → gets alerts
4. Appends a history entry to `qa_state.json`:
   - `alerts` — what the QA agent flagged
   - `smith_actions` — quick_log entries that fired *after* the alerts (Smith's response)
5. Keeps the last 20 history cycles

---

## Dashboard — Two New Tabs

### Tab 1: QA Agent

**Alerts panel (top)** — current alerts from the latest QA cycle:
```
┌─ QA Agent ─────────────────────────────────────────┐
│ Last check: 2 min ago                               │
│                                                     │
│ 🔴 HIGH  Coverage matrix has 82 pending cells.      │
│          No tool calls in last 11 minutes.          │
│                                                     │
│ 🟡 MED   Spider ran but only 4/86 cells tested.     │
│          Consider invoking web-exploit.             │
│                                                     │
│ 🟢 LOW   credential-audit gate is pending.          │
│          Auth form found — invoke it.               │
└─────────────────────────────────────────────────────┘
```

**Quick Log timeline (bottom)** — live scrolling event feed:
```
┌─ Quick Log ──────────────────────────────────────────┐
│ 09:14  🔍 FINDING  HIGH  SQLi in /search             │
│ 09:12  🔧 TOOL     nuclei  → https://target           │
│ 09:03  📋 COVERAGE  23 endpoints, 86 cells pending   │
│ 09:02  🕷 SPIDER   23 endpoints found (playwright)   │
│ 09:01  🎯 SKILL    web-exploit  (reason: start)      │
└──────────────────────────────────────────────────────┘
```

Polls `/api/qa` and `/api/quicklog` every 5 seconds.

### Tab 2: Conversation

Human-readable chat thread showing the full QA↔Smith back-and-forth. QA bubbles on the left, Smith's response actions on the right.

```
┌─ QA Conversation ──────────────────────────────── 09:01 ┐
│                                                          │
│  ┌─────────────────────────────────────────── QA ──┐    │
│  │ 🔴 Coverage matrix has 82 pending cells with    │    │
│  │    no tool calls in the last 11 minutes.         │    │
│  │ 🟡 Spider ran but only 4/86 cells tested.        │    │
│  └─────────────────────────────────────────────────┘    │
│                                                          │
│          ┌────────────────────────────── Smith ──┐       │
│          │ 🔧 nuclei → https://target            │       │
│          │ 🔧 http → /api/users (GET)            │       │
│          │ 📋 COVERAGE +3 cells tested           │       │
│          └───────────────────────────────────────┘       │
│                                                          │
│  ┌─────────────────────────────────────────── QA ──┐    │
│  │ 🟡 credential-audit gate still pending.          │    │
│  │    Auth form found — invoke /credential-audit.   │    │
│  └─────────────────────────────────────────────────┘    │
│                                                          │
│          ┌────────────────────────────── Smith ──┐       │
│          │ 🎯 SKILL  credential-audit (chained)   │       │
│          │ 🔧 kali → hydra ...                   │       │
│          └───────────────────────────────────────┘       │
└──────────────────────────────────────────────────────────┘
```

Data source: `qa_state.json` → `history[]`. No additional API endpoint needed — history is included in `/api/qa`. Polls every 5 seconds.

---

## Files to Create

| File | Purpose |
|------|---------|
| `core/quick_log.py` | QuickLog class — append-only JSONL writer, `summarize()` method |
| `core/qa_agent.py` | LangGraph graph + QADaemon background loop |

## Files to Modify

| File | Change |
|------|--------|
| `core/api_server.py` | Add `GET /api/qa` and `GET /api/quicklog` endpoints; launch QADaemon on startup |
| `core/session.py` | Merge `qa_alerts` + `qa_last_check` into `status()` response |
| `mcp_server/_app.py` | Append TOOL/SPIDER entry to quick_log after every tool dispatch |
| `mcp_server/report_tools.py` | Append FINDING and COVERAGE entries to quick_log |
| `mcp_server/session_tools.py` | Append SKILL entry on `set_skill`; merge qa_alerts on `status` |
| `templates/dashboard.html` | Add QA Agent tab and Conversation tab |
| `requirements.txt` | Add `langgraph`, `langchain-core`, `langchain-openai` (+ optional provider packages) |

---

## Verification Steps

1. Start server: `python -m mcp_server` → `report(action="dashboard")`
2. Run `scan(tool="spider", target="https://...")` → verify `quick_log.json` has a `SPIDER` entry
3. Call `session(action="status")` → confirm `qa_alerts` field present (empty list until daemon fires)
4. Wait 2 min → `qa_state.json` appears → `/api/qa` returns alerts → dashboard QA tab shows them
5. Log a finding → verify quick_log has `FINDING` entry
6. Run more tool calls → wait for next QA cycle → Conversation tab shows QA bubbles + Smith's response actions
7. Repeat the same test in opencode — behaviour must be identical (MCP + files, no client code)
