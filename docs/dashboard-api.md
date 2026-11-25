# Dashboard API Reference

The FastAPI server (the `core/api_server/` package — routes live in `core/api_server/routes/*.py`) starts when Claude calls `report(action="dashboard", ...)`. It serves both the dashboard UI and a REST API used by the frontend.

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

Returns `index.html` (a Jinja2 template that `{% include %}`s the per-tab partials; CSS/JS load from the `/static` mount) — a single-page app with these tabs:

| Tab | Contents |
|---|---|
| **Findings** | All confirmed vulnerabilities, color-coded by severity, with expandable evidence. Findings with an exported GitHub issue show a clipboard button to copy the formatted issue block. |
| **Topology** | Mermaid architecture diagrams produced by `report(action='diagram')` |
| **Components** | Findings grouped by logical application component (Admin Panel, Database, FTP Server, etc.) |
| **Coverage** | Live coverage matrix — endpoints × params × injection types. Cells colored by status: pending / in_progress / tested_clean / vulnerable / not_applicable / skipped. |
| **Skills** | Skill-history timeline and chaining graph. |
| **Activity** | Live feed: **Stuck Events** (HIR + stalls), **QA Alerts** (high-urgency only), **Steering Directives** (pending / injected / acknowledged), **Resource Wishlist** (agent→operator needs, with Fulfill/Dismiss buttons), **Tool Activity** (newest 500 quick-log entries), and the **Adjudication ↔ Smith** verdict log. Renders defensively — one failing renderer no longer blanks the whole tab. |
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

### Other UI / static routes

| Route | Returns |
|---|---|
| `GET /finding/{id}` | Standalone per-finding "dossier" page (`finding.html`); `finding.js` fetches `/api/findings/{id}`. Falls back to the archived list so a deleted finding's URL still resolves. |
| `GET /healthz` | `{"ok": true}` — unauthenticated liveness probe used by `serve()`; returns no scan data so it stays reachable when the `/api/*` control plane requires the per-session bearer token. |
| `GET /logo.png` | The dashboard logo PNG. |
| `GET /favicon.ico` | The `.ico` favicon (also `GET /favicon-32x32.png` for the sized PNG). |

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

### `GET /api/findings/{id}`

One finding plus any exploit chains that reference it — feeds the standalone `/finding/{id}` detail page. Chain Mermaid is pre-rendered to SVG server-side. Falls back to the `archived[]` list so a deleted finding still resolves.

**Response:** `{ "finding": {...}, "chains": [...], "archived": true|false, "meta": {...} }` — or `{"error": "not found"}` with a `404` if the id is unknown.

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

Update fields on an existing finding. Called by `/gh-export` (to attach the `gh_issue` block) and by the dashboard's inline finding editor. Every field is optional — only the keys present in the body are applied.

**Request body (any subset):**
```json
{
  "severity": "high",
  "title": "...",
  "description": "...",
  "evidence": "...",
  "status": "confirmed",
  "gh_issue": "**Summary:** ...",
  "remediation": "...",
  "reproduction": { "type": "http", "command": "...", "expected": "..." },
  "escalation_leads": [ ... ]
}
```

**Response:** `{ "ok": true }` (`ok` reflects whether the finding was updated). Returns `400` on error.

---

### `DELETE /api/findings/{id}`

Archive a finding — moves it to the `archived[]` array in `findings.json` (not a hard delete, so the `/finding/{id}` page still resolves).

**Response:** `{ "ok": true|false }` (`ok` reflects whether the finding was archived). Returns `400` on error.

---

### `GET /api/graph`

The knowledge-graph world-model for the dashboard's World Model tab: nodes/edges (each carrying its full property bag), graph-derived candidate chains, ranked findings, and value-ranked next targets. Worklist panels ("proposed kill-chains", "deepen next", "next targets") drain to empty as work is proven.

**Response:** `{ "stats": {nodes, edges, by_kind}, "nodes": [...], "edges": [...], "candidate_chains": [...], "ranked_findings": [...], "next_targets": [...] }`.

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

### `GET /api/adjudication-log`

The senior-review verdict log — the Adjudication ↔ Smith conversation feed. Returns an array of verdict entries (empty `[]` when nothing has been adjudicated yet).

---

### `GET /api/metrics`

Per-scan metrics for the Metrics tab (`pentest_metrics.jsonl`, loaded and aggregated): tool counts, coverage rate, finding-rate-per-hour.

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

Human resolves an HIR via the dashboard.

- **Non-terminal choices** (CONTINUE / GUIDE / EXTEND / REDUCE_SCOPE / SKIP_CELLS / REAUTH / …) transition the session back to `running` and inject a high-priority `RESUME_REQUIRED` steering directive so Smith acts on the choice on its next tool call. Returns `{ "ok": true, "resumed": true, "instruction": "..." }`.
- **Terminal choices** (`ACCEPT_PARTIAL` / `FORCE_COMPLETE` / `COMPLETE` / `ABORT`) actually **complete the scan** (so the agent isn't bounced back into the same blockers) — `ABORT` records `stop_reason=operator_abort`, the rest `operator_accept_partial`, both with `quality_gate=failed`. Returns `{ "ok": true, "completed": true, "instruction": "..." }`.

**Request body:**
```json
{ "choice": "REAUTH", "message": "Use admin2/admin123" }
```

---

### `POST /api/steer`

Free-form HUMAN_STEER from the operator. Always queues (no dedup) so the operator can fire the same instruction twice if they want. The resulting directive is nagged on every tool call until Smith calls `session(action="qa_reply")`.

**Request body:** `{ "message": "stop /admin/approve_loan — dead endpoint" }`

A typed steer that reads as a phase-advance instruction ("advance to phase B", "next phase") is parsed server-side and routed to `advance_phase` deterministically instead of the model.

---

### `GET /api/phase`

Current scan phase + advisory hint for the dashboard's phase control. Phases are `exploit` → `coverage` → `synthesis` and never auto-advance.

**Response:** `{ "phase": "exploit", "label": "...", "advice": null, "next": "coverage", "phases": ["exploit","coverage","synthesis"], "running": true }`

---

### `POST /api/phase/advance`

Operator advances the scan phase **forward** (the dashboard button). Body (optional): `{ "target": "coverage" | "synthesis" | "b" | "c" }`; omit `target` to advance to the next phase. Force-reloads session state before mutating (the MCP process owns `session.json`).

**Response:** the `advance_phase` result (`{ "ok": true, ... }`), or `400` when the transition is rejected.

---

### `GET /api/wishlist`

The agent→operator **resource backlog** (open + resolved), newest first. Smith appends needs it can't satisfy itself (creds, scope, rate-limit relief, tooling) via `session(action="wishlist_add")` instead of marking a coverage cell `not_applicable`.

**Response:** `{ "items": [{ "id", "ts", "need", "category", "rationale", "blocking_cell_ids": [...], "status": "open"|"fulfilled"|"dismissed", "resolution_note" }, ...] }`

---

### `POST /api/wishlist/{id}/fulfill`

Operator supplies a wished-for resource. Marks the item `fulfilled` **and injects a high-priority steering directive** telling Smith to reopen the blocked cells and use the new resource — closing the loop without an HIR pause.

**Request body:** `{ "note": "creds: analyst / Pw123 — sent to Smith" }`

---

### `POST /api/wishlist/{id}/dismiss`

Operator declines a wishlist item (won't/can't supply it). **Request body:** `{ "note": "out of scope for this engagement" }`

---

### `POST /api/complete`

Terminate the scan. Sets `session.status = "complete"`, records the `finished` timestamp, and stores operator notes. Smith's next tool call returns a `SCAN_COMPLETED` envelope so the `opencode run` / `claude -p` process exits naturally instead of grinding on.

**Request body:** `{ "notes": "Completed by human operator via dashboard" }`

Completion is unconditional — it does **not** run the adjudication pass (that's a separate operator choice via `POST /api/triage`). It preserves deliverables (findings, coverage, artifacts, PoCs) and only wipes scan-tied operational pointers (`smith.pid`, `smith.client`, `quick_log`) so the dashboard immediately reflects "smith stopped".

**Response:** `{ "ok": true, "status": "complete" }`

---

### `POST /api/triage`

Operator-triggered adjudication (triage) pass — does **not** complete the scan. Injects the senior-review directive for every un-adjudicated in-scope finding and wakes Smith if it has gone idle. On a terminal scan the directive tells Smith to stop after adjudicating; on a running scan it resumes testing afterwards.

**Response:** `{ "ok": true, "status": "triaging", "pending_adjudication": N, "smith_spawned": true|false }` (or `status: "nothing_to_triage"` when no findings await a verdict).

---

### `POST /api/triage-cancel`

Operator escape hatch for the triage banner. Drops the `triage_requested` flag and removes un-consumed `TRIAGE_ADJUDICATION` (and legacy force-complete) steering directives. Does **not** touch findings or verdicts already recorded.

**Response:** `{ "ok": true, "removed_directives": N }`

---

### `POST /api/force-stop`

Hard stop — the "just stop it now" control. Flips the session terminal from **any** non-terminal state (clearing an open HIR first), cancels any triage pass, AND kills the running Smith process so it can neither keep working nor be respawned by the watchdog. Deliverables are preserved. *No request body.*

**Response:** `{ "ok": true, "status": "complete", "killed": true|false, "pid": <pid|null>, "removed_directives": N }`

---

### `DELETE /api/clear`

Wipe all scan state — resets `findings.json` and the coverage matrix, and deletes `session.json`, `quick_log`, `qa_state`, cost, steering, metrics, log files, `pocs/*.http`, `artifacts/`, `threat-model/`, `gh-issues.md`, and the Smith PID/client pointers. Also tears down chisel tunnels.

**Response:** `{ "ok": true }`

---

### `DELETE /api/tunnels`

Kill chisel tunnels in the Kali container (remote clients disconnect automatically).

**Response:** `{ "ok": true, "message": "..." }`

---

### `POST /api/setup-gates/{id}/elect`

Operator elects a manual-setup gate: `now` | `defer` | `skip`. Non-blocking — election just records the operator's decision; it never completes or blocks the scan.

**Request body:** `{ "choice": "now" }` → **Response:** `{ "ok": true, "gate": {...} }` (or `404` if the gate isn't found).

---

### `POST /api/setup-gates/{id}/recheck`

Operator re-runs a gate's readiness probe (the "I've set it up — verify" button). On a pass that clears a deferred gate, wakes Smith so it resumes the gated work. Raw probe stdout/stderr is scrubbed from the response.

**Response:** `{ "ok": true, "status": "ok"|..., "gate": {...}, "probe": {...}, "smith_woken": true|false }`

---

### `GET /api/smith-status`

Smith liveness + activity heartbeat.

**Response:**
```json
{
  "running": true,
  "adjudicating": false,
  "heartbeat_age_s": 12,
  "idle": false
}
```

- `running` — true when any Smith process exists (including an idle interactive one sitting at a prompt).
- `heartbeat_age_s` — seconds since the last MCP tool call (`quick_log` mtime), the true *activity* signal (`null` if no heartbeat yet).
- `idle` — true when `heartbeat_age_s` exceeds the 120 s heartbeat window. A live-but-idle Smith (`running: true, idle: true`) has stopped working and is likely awaiting input.
- `adjudicating` — true when a post-complete triage relaunch is in progress (`triage_requested`), so the UI can label it "adjudicating" instead of mistaking it for a hung scan.

---

### `GET /api/smith-clients`

Reports which LLM clients are installed and which one will be used on the next restart:

```json
{ "claude": true, "opencode": true, "codex": false, "active": "opencode" }
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
- `/api/quicklog`, `/api/wishlist`, `/api/adjudication-log` — only while the Activity tab is the active tab
- `/api/threat-model` — polled when the tab is open
- Logs (`/api/logs`) — every 3 s when the Logs tab is active
