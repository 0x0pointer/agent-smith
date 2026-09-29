# Implementation plan — Issue #186

**Reliable per-session reasoning log + dashboard tab (survives watchdog-spawned sessions)**

- Issue: https://github.com/0x0pointer/agent-smith/issues/186
- Branch: `feat/session-reasoning-log`
- Status: **Phase 1 implemented** (5a–5d + Option A) — 38 targeted tests pass; the
  eventstore freeze validator PASSes on a generated note+summary stream (schema +
  sequence + DAG + linkage + no-leak). Phase 2 (nudge) not started.

> This plan was written after reading the actual code. Every non-obvious claim is
> anchored to a `file:line`. Where the issue body itself is inaccurate versus the
> code, that is called out explicitly under **Corrections**.

---

## 1. Goal & hard constraint

Give an operator a reliable way to replay a *single* session's reasoning after a
pentest, captured **only at the MCP tool boundary** — no client-transcript scraping,
no per-runtime hooks. The MCP boundary is the one surface every client (Claude Code,
opencode, Codex, watchdog-spawned) shares, so anything captured there is
client-agnostic by construction.

Accepted cost (unchanged from the issue): we capture the reasoning the agent routes
*through MCP* (structured `decision`s, free-text `note`s, and per-call action+summary),
not hidden client-side chain-of-thought — that data does not exist at the MCP boundary.

## 2. What already exists (reuse, do not rebuild)

- `mcp_server/scan_engine/smith_events.py` writes a **per-session append-only** stream
  at `logs/smith-events/<engagement_id>.jsonl`, one file per scan, emitted from the
  tool choke point `emit_tool_call` (`smith_events.py:326`), called for every tool
  inside `wrap()` (`mcp_server/scan_engine/envelope/__init__.py:196`). It is
  fire-and-forget / fail-soft ("never break the scan").
- `engagement_id` **is** the server-owned session uuid, minted at
  `core/session/lifecycle.py:94` (`str(uuid.uuid4())`) and read via `_engagement_id()`
  (`smith_events.py:66`). The client never supplies it → the "floor" needs zero model
  cooperation. **This is the mechanism that already satisfies the watchdog/auto-spawn
  criterion** (see §7, criterion 3).
- One file per session → inherently immune to the `session.json` /
  `coverage_matrix.json` singleton clobber (with one caveat — see §8).
- A durable per-session bundle already exists: raw artifacts are copied to
  `logs/smith-events/<id>/<artifact_id>.txt` (`smith_events.py:262`), plus
  `meta.json` (`smith_events.py:283`) and final `findings.json`
  (`smith_events.py:300`, driven from `core/session/lifecycle.py:203`).
- The dashboard tab pattern is well-established: nav button + `{% include %}` +
  `TAB_NAMES` + a read route. The **AI Red Team** tab (added recently) and the
  **Logs** tab are the two templates to mirror.

## 3. Corrections to the issue's stated assumptions

The issue body is directionally right but contains three factual errors that change the work:

1. **"emit_tool_call already records each call's summary" — FALSE.** `emit_tool_call`
   persists only `result.observed.{execution_status,result_class}` and an optional
   `artifact_id` (`smith_events.py:354-358`). The human-readable `result.summary` is
   passed in but **never written**. So the "action-and-summary floor" criterion is only
   *partially* met today. → **Phase 1 must persist `result.summary`.**
2. **"note goes through `log.note` which redacts" — FALSE.** `core/logger.py:124` logs
   the raw message with no redaction (contrast `tool_result` → `_redact` at
   `core/logger.py:102`). `pentest.log` NOTE lines are already unredacted. → **The new
   note event must be redacted before it hits the jsonl** (mandatory, not optional —
   see §4).
3. **`_do_note` location.** It lives in `mcp_server/report_tools/diagrams.py:208`, not
   `report_tools/__init__.py` (the `__init__.py:195` dispatcher only routes
   `action=="note"` → `_do_note`).

Additional load-bearing fact the issue understates: the runtime stream is **not
write-only telemetry**. It is validated by `training-data/eventstore/validate_stream.py`
and consumed by `harvest_decisions.py` / the `eventstore`. So the `event_type` choice
has teeth (see §4) and a secret leaking into an event **hard-fails** the whole stream's
freeze acceptance (`validate_stream.py` `LEAK_PATTERNS`: JWT `eyJ…`, `Bearer …`, `AKIA…`,
`PRIVATE KEY`).

## 4. Note representation — DECIDED: Option A (first-class `note` type)

> **Confirmed:** implement Option A (first-class `note` event type). The alternatives
> below are retained for rationale; the 4 coordinated edits at the end of this section
> are the ones to make.


The issue says *"unify note and decision type in the stream."* That is ambiguous
between two implementations:

- **Option A (RECOMMENDED): a first-class `note` event type.** Keeps the reasoning
  channel unified *in the dashboard view* while keeping notes out of the `decision`
  training corpus. Requires 4 coordinated edits (below), or `validate_stream.py` rejects
  it as `unknown event_type` and the test harness `KeyError`s.
- **Option B: emit a note as a `decision` event** with sentinel fields. Schema-cheap
  (no new schema; `decision` is already in every validator map) **but** it pollutes
  `eventstore.decisions()` (`training-data/eventstore/core.py:110`) and the decision SFT
  corpus with empty-goal sentinels, and truncates note text into `explanation` (capped
  at 400 chars, `smith_events.py:190`).

**Recommendation: Option A.** It is faithful to "note … in the stream," keeps the
training corpus clean, and the dashboard unifies note+decision into one *reasoning view*
regardless. Option B is the fallback only if merging notes into the decision corpus is
explicitly acceptable. This is the single item worth an explicit human call before
coding, because it changes training-data semantics, not just code.

Option A's 4 coordinated edits:
1. Add `"note"` to the enum at `training-data/schemas/event-envelope.schema.json:12`.
2. Create `training-data/schemas/note-event.schema.json` — `allOf: [{$ref
   event-envelope}, {event_type const "note", "note": {message/text: string}, required:
   ["note"]}]`.
3. Add `"note": "note-event.schema.json"` to `EVENT_SCHEMA` in
   `training-data/eventstore/validate_stream.py:30` (else freeze-accept fails).
4. Add `"note": "note-event.schema.json"` to `_SCHEMA_FOR` in
   `tests/test_smith_events.py:18` (else `_validate` `KeyError`s).

## 5. Phase 1 — the deliverable (client-agnostic, mostly additive)

### 5a. Persist the action **summary** (the floor fix) — mandatory

- In `emit_tool_call` (`smith_events.py:~356`), after building `result_obj`, add
  `result_obj["summary"] = (getattr(result, "summary", "") or "")[:2000]` as a
  **sibling** of `observed`/`artifact_id`.
- **Must be result-level, not inside `observed`** — `tests/test_smith_events.py:76`
  asserts exact equality on `result["observed"]`; nesting summary there breaks it.
- Persist `result.summary` (the clean summarizer output), **not** the local `summary`
  variable in `wrap()` which has `EXECUTE NEXT: …` appended
  (`envelope/__init__.py:149-156`).
- `result-event.schema.json` has no `additionalProperties:false` on `result`, so the
  new field validates cleanly; optionally add `"summary": {"type":"string"}` to that
  schema for explicitness.
- **Redaction (as implemented):** the summary is redacted at capture via a new
  `_redact_text` helper (reusing `core.logger._redact`), because it is both scanned by the
  eventstore leak-scan and rendered verbatim on the dashboard — a leaked token there is
  worse than in a training file. Bounded to 2000 chars; the full un-redacted body still
  lives in the copied artifact `.txt` for training.

### 5b. `emit_note()` + wire into `_do_note` — the structured reasoning channel

- Add `emit_note(message: str)` to `smith_events.py`, structurally copied from
  `emit_decision`: `_enabled()` gate, `_engagement_id()` guard (no-op if falsy),
  `_EVENTS_DIR.mkdir(...)`, `path = _EVENTS_DIR/f"{engagement}.jsonl"`, `with _lock:`
  around `_next_seq` + append, `_envelope("note", …)`, whole body in `try/except`
  (fail-soft).
- **Two correctness requirements the critics flagged:**
  1. **Do NOT set `_current_decision`** (unlike `emit_decision:199`). If a note sets it,
     the *next real tool call's* action links `caused_by` the note instead of the actual
     decision, corrupting the decision→action→result graph.
  2. **Redact the message** with `core.logger._redact` (`core/logger.py:47`) before
     writing — `log.note` does not, and `validate_stream.py`'s leak-scan hard-fails the
     stream on a token substring.
- Call it from `_do_note` (`mcp_server/report_tools/diagrams.py:210`) right after
  `log.note(message)`, inside its own `try/except` so `_do_note`'s return contract is
  unchanged.
- (Optional hygiene, recommend scoping in) also add `_redact` to `core/logger.py:124`
  `note()` — `pentest.log` currently emits unredacted NOTE lines (AS-06/AS-15).

### 5c. Read API — `GET /api/session-log`

Serve the reasoning stream to the dashboard. Mirror `api_logs`
(`core/api_server/routes/misc_routes.py:58`) for the path-traversal-safe pattern.

- **New module** `core/api_server/routes/session_log_routes.py`:
  `from ._common import router`, `from core import paths as _paths`, handler
  `async def api_session_log(session: str = "", limit: int = 2000)` decorated
  `@router.get("/api/session-log")`.
- **Register it** in `core/api_server/routes/__init__.py`: add
  `from . import session_log_routes` to the import block (`:24-30`) — *mandatory*, a
  missing import = a silently-missing endpoint (404) — and optionally re-export
  `api_session_log` for by-name test imports.
- **Path source:** add `SMITH_EVENTS_DIR = LOGS_DIR / "smith-events"` to `core/paths.py`
  (leaf module, no cycle) and reference `_paths.SMITH_EVENTS_DIR`. **Do not import
  `mcp_server` from `core/`** — that violates the repo convention
  (`core/qa_agent/checks_depth.py:23`; every existing `core→mcp_server` import is
  deferred inside a function). Optionally repoint `smith_events._EVENTS_DIR` at the new
  constant to kill the duplicate derivation.
- **Behaviour:**
  - List sessions: `sorted(SMITH_EVENTS_DIR.glob("*.jsonl"), key=lambda p:
    p.stat().st_mtime, reverse=True)`. Glob `*.jsonl` **specifically** (the dir also
    contains per-session bundle *subdirs* `<id>/`). Sort by **mtime, not filename** —
    uuids are not time-ordered, so filename sort picks an arbitrary "newest".
  - Label each session from `SMITH_EVENTS_DIR/<id>/meta.json` (a **subdir**, not a
    sibling — `smith_events.py:283`), falling back to the bare id when meta is absent
    (a decision-only stream has no meta, since `_snapshot_meta` runs only from
    `emit_tool_call`).
  - `?session=<id>`: resolve against the trusted glob by `p.stem` (the dropdown value is
    the bare id, no extension), exactly like `api_logs` resolves `?file`. **Never** build
    a path from the raw query param. Unknown id → `{"events": [], "sessions": [...],
    "error": "invalid session"}`.
  - No `?session` → newest by mtime.
  - Parse each line `json.loads` in `try/except` (skip malformed — mirror
    `api_quicklog`); a truncated final line from a fire-and-forget crash must not 500.
    Surface `line[line["event_type"]]` as the payload (the reasoning is **nested**, not
    top-level).
  - Return **all** event types by default (or `decision/action/result/finding/note` with
    a `?types=` filter) — a hard allow-list that omits `finding`/`coverage_transition`
    would silently drop real rows.
  - Bound output: tail the last N via `collections.deque(maxlen=N)` (bounded memory, not
    `read_text()` of a multi-MB file) and return `{session, sessions, events, truncated,
    count}`. Optional `?since_seq=` for incremental polling (events carry a monotonic
    `sequence`).
- **Auth:** none per-route — the app-level middleware (`core/api_server/__init__.py:88`)
  already gates `/api/*` behind the bearer token. Match the other route modules (which
  add none). Do not name the handler `api_session` or reuse `/api/session` — both
  already exist (`findings_routes`).

### 5d. Dashboard tab — "Session Log" (read-only)

Mirror the Logs + AI Red Team tabs. **Two edit sites in `common.js`, both required.**

- **`dashboard/index.html`:**
  - Nav: append `<button class="tab-btn" id="tab-btn-session-log"
    onclick="switchTab('session-log')">Session Log</button>` as the **last** `.tab-btn`
    (in the System group, after Logs at `:53`).
  - Include: add `{% include 'tabs/session-log.html' %}` after `:189`.
  - Script: add `<script src="/static/js/session-log.js"></script>` after logs.js
    (`:203`) and **before** `main.js` (`:208`). **No `?v=` bump** — a `no-cache`
    middleware (`core/api_server/__init__.py:120`) forces revalidation; existing `?v=`
    values are divergent anyway, so "bump all to 23" would be wrong.
- **`dashboard/js/common.js`:**
  - Append `'session-log'` as the **last** element of `TAB_NAMES` (`:76`). The
    "Order MUST match the `.tab-btn` DOM order" comment is real — `switchTab` maps
    button *N* to `TAB_NAMES[N]` by index (`:80-81`). Appending both the button and the
    name keeps index alignment trivial.
  - Add `if (name === 'session-log') pollSessionLog();` to the switchTab dispatch block
    (after `:105`). This is a **separate** edit from `TAB_NAMES`; without it the tab
    highlights but never fetches on click.
- **`dashboard/tabs/session-log.html`:** root `<div id="tab-session-log"
  class="tab-content">` (id must be exactly `tab-${name}`; class drives the show/hide;
  **no `active`** — findings is the default). Inside: a `<select
  id="session-log-select" onchange="onSessionLogChange()">` dropdown (mirror
  `logs.html`'s `log-file-select`), an optional filter input, and a
  `<div id="session-log-output">`.
- **`dashboard/js/session-log.js`:** a **flat classic script, NOT an IIFE** (only the
  standalone `finding.js` is an IIFE; every tab module is flat and shares one global
  scope). Declare top-level `let _selectedSessionId = ''; let _sessionLogEvents = [];`
  with **unique** names — a duplicate top-level `let/const` across files is a
  page-breaking `SyntaxError`. Use plain `fetch('/api/session-log?…')` — `shared.js:31`
  monkeypatches `window.fetch` to attach the bearer token; there is no `authFetch`.
  `esc()` (from shared.js) every rendered field — model notes may paste untrusted target
  content. Renders a **raw console-style log** — one line per event
  (`HH:MM:SS  NNN  TYPE  <flattened text>`), color-coded by type, filterable — rather than
  structured cards, so it reads like tailing a reasoning log in the terminal. Note this
  shows only what crosses the MCP boundary (notes/decisions/actions/results/etc.), **not**
  the model's hidden client-side chain-of-thought, which is an explicit non-goal of #186.
- **`dashboard/js/main.js`:** add
  `setInterval(() => { if (!scanDone && _activeTab === 'session-log') pollSessionLog(); }, 3000);`
  near `:116`, and `pollSessionLog();` in the initial-load block (safe because
  session-log.js is parsed before main.js).
- **scanDone trap:** the recurring `setInterval` may gate on `scanDone`, but the
  **fetch-on-switch must run regardless of `scanDone`** — the whole point is reviewing a
  session *after* it finishes. Do not copy `logs.js`'s internal `if (scanDone) return;`
  into the switch path, or the tab is blank post-scan.

## 6. Phase 2 — server-side nudge (fast-follow, optional)

The issue marks item 3 ("portable enforcement instead of hooks") as a fast-follow.
Scope it as Phase 2.

- In `envelope/__init__.py`, after `merged_required` is assembled (`:140`) and before
  the EXECUTE-NEXT prepend (`:148`), prepend a nudge string to `merged_required` when
  `_safety_class(tool, ctx) != "read_only"` (`smith_events.py:114`) **and** no reasoning
  was recorded for the current engagement (`smith_events._current_decision.get(
  engagement)` is falsy — expose via a small accessor). It flows into `next.required`
  (`:163`), which every client sees, so enforcement is portable with zero hooks.
- Decide whether a recorded `note` (not only a `decision`) should suppress the nudge — if
  so, track a combined signal (today `_current_decision` tracks decisions only).

## 7. Acceptance-criteria mapping

| # | Criterion | Satisfied by | Residual risk |
|---|-----------|--------------|---------------|
| 1 | note + decision + action+summary in `<id>.jsonl`, tagged with the server-owned engagement id | 5a (summary) + 5b (note); decision/action already emit; all tagged via `_envelope` | none once 5a lands |
| 2 | Identical across ≥2 runtimes (Claude Code + opencode) | By construction — capture is at `wrap()`/`emit_tool_call`, below the client | none |
| 3 | Works for watchdog / auto-spawned sessions | Server-keyed uuid + fire-and-forget `emit_tool_call`; a **resumed** respawn reuses the same on-disk session.json → same id → same file | Holds for the **resume** path, not a fresh `session(action="start")` (see §8) |
| 4 | Per-session isolation, immune to the singleton clobber | One file per engagement id | **Partial** — see §8 (mid-stream `_current` swap) |
| 5 | A no-explicit-reasoning session still yields a reconstructable action+summary trail | 5a persists summary for every tool call | none once 5a lands |
| 6 | Dashboard replays any selected past session by id | 5c (list + by-id read) + 5d (dropdown) | none |

## 8. Known limitations / risks (state these in the PR)

1. **`engagement_id` is re-minted per `session(action="start")`**
   (`core/session/lifecycle.py:93-94` always sets a fresh uuid; `session_tools/start.py`
   restores counters/phase but **not** the id). So a *resume* (watchdog `--session`,
   where the agent calls `status`/`recovery` which `load_from_disk` the original id)
   preserves the stream, but any path that re-runs `start()` splits one logical run
   across two files / two dropdown rows. Criterion 3's "survives watchdog" holds for the
   resume path; document it, or (larger change) thread a stable engagement key across
   restarts.
2. **Clobber-immunity is only partial.** The per-file split protects the *contents*, but
   the engagement id is read through the in-memory `_current`, which
   `_reconcile_if_external_write` (`core/session/persistence.py:163`, run on every tool
   call via `add_tool_called`) can swap to a concurrent same-directory tab's session
   *before* emit — misrouting events into the other session's file. True immunity needs
   pinning the engagement id per MCP process. Recommend documenting the window for
   Phase 1 and treating the pin as a follow-up.
3. **Floor is silent before the first `session(...)` call** on a freshly-spawned MCP
   server process (`_current` is `None` until `load_from_disk`), so pre-session tool
   calls are uncaptured. The resume/cold prompts already tell the agent to call
   `status`/`recovery` first, which mitigates it.
4. **Per-poll read cost (follow-up).** The tab auto-refreshes every 3s, and each
   `/api/session-log` request re-globs `*.jsonl`, re-reads every session's `meta.json` for
   the dropdown labels, and re-reads the selected stream top-to-bottom (bounded in memory
   by the `deque` tail, but not in I/O). Fine for a single operator on a read-only tab;
   for very long scans / many past sessions the clean fix is incremental polling via
   `?since_seq=` plus caching the session list. Deferred, not blocking.
5. **Cross-process sequence collision:** `_next_seq` seeds from line count in per-process
   memory (`smith_events.py:75`). Because each start mints its own uuid, two writers
   normally target different files (the desired isolation); only a shared `<id>.jsonl`
   would collide.

## 9. Test plan

- `tests/test_smith_events.py`
  - `result` event carries a bounded `summary` from `result.summary`
    (extend `FakeResult`; place near `:76`); `test_emits_schema_valid_action_result_pair`
    still passes.
  - `emit_note`: schema-valid `note` event (add `"note"` to `_SCHEMA_FOR:18` first);
    does **not** mutate `_current_decision` (emit_note then `emit_tool_call`, assert the
    action has no `caused_by`); redacts a JWT (`eyJ…` not in the written jsonl);
    fail-soft under `SMITH_EVENTS_DISABLED` and no-session.
- `tests/test_report_tools.py` — `report(action="note")` / `_do_note` lands a note event
  in `logs/smith-events/<id>.jsonl` *in addition to* `pentest.log`.
- New `tests/test_session_log_api.py` (mirror `tests/test_api_server.py`, `TestClient`
  with `SMITH_DASHBOARD_AUTH=0`): lists sessions; returns nested payload rows; defaults
  to newest by mtime; missing-meta fallback; malformed-final-line → 200 (skip bad line);
  traversal `?session=../../etc/passwd` → invalid-session shape, never file contents;
  endpoint is mounted (catches a forgotten `routes/__init__.py` import).
- `tests/test_ai_redteam_dashboard.py`-style render test: `client.get("/").text` contains
  `tab-btn-session-log`, `switchTab('session-log')`, `/static/js/session-log.js`, and
  `id="tab-session-log"` (also catches a missing Jinja partial).
- Freeze/stream check: run an emitted stream through
  `training-data/eventstore/validate_stream.py` to prove Option A's schema plumbing +
  redaction are complete.
- Manual regression: click every nav button and confirm each highlights itself
  (TAB_NAMES index alignment); open Session Log post-scan and confirm it populates.
- Runner: `poetry run pytest tests/test_smith_events.py tests/test_session_log_api.py`.

## 10. Suggested sequencing

1. **5a** (summary floor fix) + its test — smallest, highest-value, satisfies criteria
   1 & 5, zero UI.
2. **5b** (`emit_note` + Option A schema plumbing + `_do_note` wiring) + tests.
3. **5c** (`/api/session-log`) + tests.
4. **5d** (dashboard tab) + render test.
5. **Phase 2** nudge (separate PR).

Each of 1–4 is independently shippable and behavior-additive; the stream and its
consumers keep validating throughout.
