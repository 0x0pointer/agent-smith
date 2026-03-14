# Dashboard API Reference

The FastAPI server (`core/api_server.py`) starts when Claude calls `start_dashboard`. It serves both the dashboard UI and a REST API used by the frontend.

**Default URL:** `http://localhost:5000`

---

## Starting the dashboard

Claude calls `start_dashboard` automatically at the start of a pentest. You can also call it manually:

```
start_dashboard()           # default port 5000
start_dashboard(port=5001)  # custom port
```

The call is idempotent — calling it again on the same port returns the existing URL without restarting.

---

## UI

### `GET /`

Returns `templates/dashboard.html` — a single-page app with five tabs:

| Tab | Contents |
|---|---|
| **Findings** | All confirmed vulnerabilities, color-coded by severity, with expandable evidence. Findings with an exported GitHub issue show a clipboard button to copy the formatted issue block. |
| **Topology** | Mermaid architecture diagrams produced by `report_diagram` |
| **Components** | Findings grouped by logical application component (Admin Panel, Database, FTP Server, etc.) |
| **Threat Model** | Threat model reports from `threat-model/*.md` — dropdown to switch between reports, Mermaid diagrams pre-rendered server-side |
| **Logs** | Structured session log — tool calls, results, notes, findings in real time |

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

## Polling

The dashboard polls every 5 seconds:

- `/api/findings` — new vulnerabilities and diagrams
- `/api/session` — scan status and progress
- `/api/threat-model` — threat model reports (tab button gets a `●` dot when content arrives)

Logs are polled every 3 seconds when the Logs tab is active.
