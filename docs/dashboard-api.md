# Dashboard API Reference

The FastAPI server (`core/api_server.py`) starts when Claude calls `report(action="dashboard", ...)`. It serves both the dashboard UI and a REST API used by the frontend.

**Default URL:** `http://localhost:7777`

---

## Starting the dashboard

Claude calls `report(action="dashboard")` automatically at the start of a pentest. You can also call it manually:

```
report(action="dashboard", data={"port": 7777})  # default port
report(action="dashboard", data={"port": 8888})  # custom port
```

The call is idempotent — calling it again on the same port returns the existing URL without restarting.

---

## UI

### `GET /`

Returns `templates/dashboard.html` — a single-page app with these tabs:

| Tab | Contents |
|---|---|
| **Findings** | All confirmed vulnerabilities, color-coded by severity, with expandable evidence. Findings with an exported GitHub issue show a clipboard button to copy the formatted issue block. |
| **Topology** | Mermaid architecture diagrams produced by `report(action='diagram')` |
| **Components** | Findings grouped by logical application component (Admin Panel, Database, FTP Server, etc.) |
| **Coverage** | Live coverage matrix — endpoints × params × injection types. Cells colored by status: pending / in_progress / tested_clean / vulnerable / not_applicable / skipped. |
| **Skills** | Skill-history timeline and chaining graph. |
| **Activity** | Four-section live feed: **Stuck Events** (HIR + stalls), **QA Alerts** (high-urgency only), **Steering Directives** (pending / injected / acknowledged), and **Tool Activity** (newest 500 quick-log entries). Renders defensively — one failing renderer no longer blanks the whole tab. |
| **Threat Model** | Threat model reports from `threat-model/*.md` — dropdown to switch between reports, Mermaid diagrams pre-rendered server-side |
| **Metrics** | Per-scan metrics: tool counts, coverage rate, finding-rate-per-hour. |
| **Logs** | Structured session log — tool calls, results, notes, findings in real time |

### Command center (top of every tab)

A persistent panel above the tab nav exposes operator actions:

| Element | Behavior |
|---|---|
| Scan status badge | `running` · `intervention_required` · `complete` · `incomplete_with_unresolved_blockers` · `limit_reached`. Refreshes off `/api/session` every 5 s. |
| Smith status badge | `running` / `stopped` — independent of scan status. Driven by `/api/smith-status`. |
| **Instruct Smith** textarea | Free-form steer that POSTs to `/api/steer`. Becomes a HUMAN_STEER directive nagged on every tool call until Smith acknowledges. |
| **Complete Scan** button | POSTs to `/api/complete`. Marks the scan terminal AND triggers a SCAN_COMPLETED envelope on Smith's next tool call so the process exits cleanly. |
| **Restart Smith** button | Appears when scan is `running` / `intervention_required` but Smith's process is stopped. Auto-detects whether to spawn `opencode run` or `claude -p`. POSTs to `/api/restart-smith`. |
| HIR panel | Appears when `/api/intervention` returns `active: true`. Renders one button per option in the HIR — clicking calls `/api/intervention/respond` with that choice. |

---

## REST API

All endpoints return JSON.

---

### `GET /api/findings`

Current-session findings and diagrams (read from `findings.json`).

**Response:**
```json
{
  "findings": [
    {
      "id": "abc123",
      "title": "SQL Injection in /search",
      "severity": "high",
      "target": "example.com",
      "description": "...",
      "evidence": "...",
      "tool_used": "sqlmap",
      "cve": "",
      "timestamp": "2026-03-14T12:00:00Z",
      "gh_issue": "**Summary:** ...  (present after /gh-export runs)"
    }
  ],
  "diagrams": [
    {
      "id": "def456",
      "title": "Network topology",
      "mermaid": "graph TD\n  Internet --> WAF\n  ...",
      "timestamp": "2026-03-14T12:00:00Z"
    }
  ]
}
```

---

### `GET /api/session`

Current scan session state (read from `session.json`).

**Response:**
```json
{
  "id": "uuid",
  "target": "example.com",
  "depth": "standard",
  "depth_label": "Standard",
  "description": "recon + nuclei + dir fuzzing",
  "scope": ["example.com"],
  "out_of_scope": [],
  "limits": {
    "max_cost_usd": 0.5,
    "max_time_minutes": 45,
    "max_tool_calls": 25
  },
  "started": "2026-03-14T12:00:00Z",
  "status": "running"
}
```

---

### `GET /api/cost`

Per-tool cost breakdown for the current session (read from `session_cost.json`).

**Response:**
```json
{
  "tool_calls_total": 12,
  "est_cost_usd": 0.14,
  "tools": {
    "run_nuclei": {
      "calls": 1,
      "input_tokens": 450,
      "output_tokens": 1200,
      "est_cost_usd": 0.04
    }
  }
}
```

---

### `PATCH /api/findings/{id}`

Attach a GitHub issue markdown block to an existing finding. Called automatically by `/gh-export`.

**Request body:**
```json
{ "gh_issue": "**Summary:** ..." }
```

**Response:**
```json
{ "ok": true }
```

---

### `GET /api/threat-model`

Lists all `*.md` files in `threat-model/` and returns the content of the selected file. Mermaid code blocks are pre-rendered to SVG server-side via `npx @mermaid-js/mermaid-cli`.

**Query params:** `file=<filename>` (optional — defaults to the most recently modified file)

**Response:**
```json
{
  "files": ["threat-model-app.md", "threat-model-api.md"],
  "file": "threat-model-app.md",
  "content": "# Threat Model: ...",
  "svgs": {
    "0": "<svg>...</svg>",
    "1": "<svg>...</svg>"
  }
}
```

SVGs are cached by file mtime — only re-rendered when the file changes.

---

### `GET /api/logs`

Current session log lines (read from `logs/session_*.log`).

**Query params:** `file=<filename>` (optional — select a previous session log)

**Response:**
```json
{
  "lines": ["2026-03-14T12:00:01Z TOOL_CALL run_nmap ...", "..."],
  "file": "session_20260314.log",
  "files": ["session_20260314.log", "session_20260313.log"]
}
```

---

### `GET /api/coverage`

Current coverage matrix (read from `coverage_matrix.json`). Same shape as the file: `{meta, endpoints, matrix}`.

---

### `GET /api/quicklog`

Flat list of every quick-log entry — TOOL calls, SKILL transitions, SPIDER results, FINDING creations, COVERAGE updates, and QA_REPLY acknowledgments. Newest last.

The dashboard renders only the newest **500** entries to keep the Activity tab snappy on multi-day scans — a header line shows the omission count.

---

### `GET /api/qa`

QA-daemon state: most recent cycle's `alerts[]`, the daemon's `ts`, and a `history[]` of recent cycles for the QA ↔ Smith conversation view.

---

### `GET /api/steering`

Full steering-queue dump — every directive ever injected with its status (`pending` / `injected` / `acknowledged` / `auto_satisfied`).

---

### `GET /api/intervention`

Current HIR state. **Force-reloads `session.json` from disk on every call** so the dashboard process never serves stale in-memory data while the MCP process is writing.

**Response when active:**
```json
{
  "active": true,
  "code": "HIR_AUTH_FAILURE",
  "situation": "7/10 recent HTTP requests returned 401/403 ...",
  "options": ["RECREDENTIAL: ...", "REAUTH: ...", "SKIP_AUTH: ...", "ABORT: ..."],
  "triggered_at": "2026-06-07T08:00:00Z"
}
```

**Response when idle:** `{"active": false}`.

---

### `POST /api/intervention/respond`

Human resolves an HIR via the dashboard. Transitions the session back to `running` (unless it was already terminal — `complete` / `incomplete_with_unresolved_blockers` / `limit_reached` are preserved) and injects a high-priority `RESUME_REQUIRED` steering directive so Smith sees the choice on the next tool call.

**Request body:**
```json
{ "choice": "REAUTH", "message": "Use admin2/admin123" }
```

---

### `POST /api/steer`

Free-form HUMAN_STEER from the operator. Always queues (no dedup) so the operator can fire the same instruction twice if they want. The resulting directive is nagged on every tool call until Smith calls `session(action="qa_reply")`.

**Request body:** `{ "message": "stop /admin/approve_loan — dead endpoint" }`

---

### `POST /api/complete`

Terminate the scan. Sets `session.status = "complete"`, records the `finished` timestamp, and stores operator notes. Smith's next tool call returns a `SCAN_COMPLETED` envelope so the `opencode run` / `claude -p` process exits naturally instead of grinding on.

**Request body:** `{ "notes": "Completed by human operator via dashboard" }`

---

### `GET /api/smith-status`

`{"running": true/false}`. True when EITHER the dashboard-tracked Smith PID is alive OR the `quick_log.json` file has been touched within 180 s (catches Smith processes the dashboard didn't spawn).

---

### `GET /api/smith-clients`

Reports which LLM clients are installed and which one will be used on the next restart:

```json
{ "claude": true, "opencode": true, "active": "opencode" }
```

`active` resolution order: last-used client (persisted in `logs/smith.client`) → whichever client process is currently running → `opencode` if installed → `claude` as fallback.

---

### `POST /api/restart-smith`

Spawn a fresh Smith process. Auto-detects client unless overridden. **Force-reloads session state** before mutating to avoid acting on stale in-memory data.

**Request body (all optional):**
```json
{ "client": "opencode" | "claude", "force": true }
```

`force: true` bypasses the "Smith is already running" check — useful when the activity heartbeat is misleading (e.g. dashboard endpoints just touched session.json themselves).

**Response:** `{ "ok": true, "pid": 17080, "client": "opencode" }`

---

### `GET /api/watchdog`

Returns the auto-restart watchdog config + recent activity:

```json
{
  "enabled": true,
  "last_restart_ago_s": null,
  "restarts_in_last_hour": 0,
  "max_per_hour": 20,
  "poll_seconds": 60,
  "min_gap_seconds": 90
}
```

The watchdog polls every `poll_seconds`. It auto-restarts when: session is `running`, no HIR is active, Smith's process is dead, the per-hour cap isn't exceeded, AND the MCP SSE server (port 7778) is reachable. The MCP-health gate prevents tight respawn loops against a dead backend.

---

## Polling

The dashboard polls in the background:

- `/api/findings`, `/api/session`, `/api/coverage`, `/api/qa`, `/api/steering` — every 5 s
- `/api/intervention` — every 3 s (HIR needs fast surface)
- `/api/smith-status`, `/api/smith-clients` — every 10 s / 30 s
- `/api/quicklog`, `/api/cycle-history` — only while the Activity tab is the active tab
- `/api/threat-model` — polled when the tab is open
- Logs (`/api/logs`) — every 3 s when the Logs tab is active
