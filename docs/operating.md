# Operating Smith

How Smith runs an engagement and the controls you have over it: scan modes, the Human
Intervention system, the Smith process lifecycle, the QA depth-enforcement daemon, and the
known-assets vault. For the dashboard REST API see [dashboard-api.md](dashboard-api.md).

---

## Scan modes

Pass `scan_mode` to `session(action="start")` to change how Smith handles critical findings.

| Mode | How to start | Exploit escalation on critical/high |
|---|---|---|
| `pentest` *(default)* | `session(action="start", options={target, scan_mode: "pentest"})` | Pauses and asks you before exploiting further (RCE, SQLi extraction, etc.) |
| `benchmark` | `session(action="start", options={target, scan_mode: "benchmark"})` | Automatically pushes Smith to exploit the full chain — RCE, DB dump, pivot — without waiting for permission |

> **Everything else is identical.** Both modes enforce all Human Intervention Required (HIR) pauses, cost limits, and depth-enforcement rules. Only the exploit-escalation decision on critical/high findings differs. The dashboard shows a **BENCHMARK** badge in the command center when this mode is active.

---

## Human Intervention Required (HIR)

Certain conditions pause the scan and block every tool call until you respond from the dashboard. While paused, the envelope returns a `HUMAN_INTERVENTION_REQUIRED` payload on every tool attempt so Smith cannot accidentally keep working in the dark.

| Trigger | Condition |
|---|---|
| Auth failure | >60 % of recent HTTP calls return 401/403 after prior successful 2xx responses. **Credential-validation attempts are excluded** — login requests carrying `password` / `api_key` / `secret` / `otp` fields or hitting a known auth endpoint don't count toward the threshold, so login-flow noise doesn't trip a false HIR. |
| Budget limit | >90 % of tool-call budget used with <80 % coverage |
| Zero endpoints | Spider finished, matrix is empty, 10+ min elapsed — target may be SPA/JS-heavy |
| Target unreachable | 3+ consecutive errors against the same target |
| Repeated tool failure | Same tool fails 3+ consecutive times within 20 min. **Tool-aware messaging**: Docker-backed tools (kali, nuclei, metasploit, …) get a container/infrastructure framing; in-process tools (`http_request`, `spider`) get a target-reachability framing (DNS / SSL / proxy block / target down). |
| Stuck on target | 5+ tool calls against the same target with no new finding — first cycle injects a steering directive; second cycle escalates to HIR |
| Force-complete blocked | Smith tried to mark the scan complete with unresolved quality blockers and exhausted its retry budget — the human chooses to skip cells, reduce scope, accept partial, or continue |

The dashboard surfaces the HIR reason in the notification with one-tap option buttons. Resolution flows back through `/api/intervention/respond`, which injects a high-priority steering directive into Smith's next tool call.

> **Polite note:** resolving an HIR after the scan was already marked **complete** / **incomplete\_with\_unresolved\_blockers** / **limit\_reached** no longer reopens the scan — the terminal status wins.

---

## Smith lifecycle and resilience

The dashboard exposes three operator actions tied to the scan lifecycle:

| Action | What it does |
|---|---|
| **Complete Scan** button | Marks `session.status = complete` and **soft-stops Smith**: the next tool envelope returns `SCAN_COMPLETED`, Smith writes a final summary, and `opencode run` / `claude -p` exits naturally. Resolving any stale HIR after this keeps the terminal status. |
| **Restart Smith** button | Spawns a fresh non-interactive Smith process. **Auto-detects the right client**: if you launched with OpenCode, the button reads "Restart Smith (opencode)" and spawns `opencode run`; for Claude Code it spawns `claude -p`. The choice persists across restarts. |
| **Watchdog (background)** | Polls every 60 s. If `session.status == running` but Smith's process is dead, the watchdog auto-restarts Smith — capped at 20 restarts/hour. **MCP-health gate**: the watchdog will not respawn Smith when the MCP SSE server (port 7778) is unreachable, preventing tight respawn loops against a dead backend. |

If the human leaves a free-form note via the **Instruct Smith** panel, it becomes a HUMAN_STEER directive that is **nagged on every tool call** until Smith acknowledges via `session(action="qa_reply", options={message: …})` — the dashboard shows that reply directly in the QA ↔ Smith conversation view.

---

## QA depth enforcement

A background QA daemon runs every 2 minutes alongside Smith. Its sole job is to ensure the scan goes deep and doesn't cut corners. It never fires mid-tool; it reads the quick-log between tool calls and injects steering directives or HIR events as needed.

### What it enforces

| Check | What it catches |
|---|---|
| **Vulnerable cells need a finding_id** | Marking a coverage cell `vulnerable` without a `finding_id` is rejected at the server. Smith must `report(action='finding', …)`, capture the returned `id`, and pass it back — guarantees every vulnerable cell has a formal finding entry and prevents the per-cell-granularity duplicates we used to see for app-wide misconfigs. |
| **Artifact required to close** | `tested_clean` and `vulnerable` closures require an `artifact_id` whose file exists on disk — no closing cells from memory. |
| **Auth-failure block** | Closing an injection cell as `tested_clean` while the artifact shows HTTP 401/403 is rejected — that's a missing-auth signal, not evidence the payload was filtered. The reject message tells Smith to retry with the JWT from `known_assets.auth_tokens`. |
| **Bulk N/A marking** | >10 coverage cells marked N/A with no tested_by tool — blocks completion |
| **Coverage integrity** | Cells marked tested but no artifact on disk — blocks completion |
| **Premature completion** | Thorough scan tries to complete before 3 semgrep passes — blocked |
| **Suspicious speed** | >20 cells closed in <10 min — likely rubber-stamping, not real testing |
| **N/A abuse** | N/A rate >35 % of all cells — injects a directive to re-examine skipped tests |
| **Depth after finding** | Critical/high finding logged >20 min ago with no follow-up tool — pushes Smith to go deeper |
| **Whitebox passes** | Thorough codebase scans must complete 3 real semgrep passes, not one |
| **Tool inactivity** | No tool call for >15 min — injects a recovery directive |
| **Core skill chain** | Enforces the universal spider → /web-exploit → /param-fuzz → /business-logic progression |
| **Missing skills** | Endpoint types (SQLi-eligible, financial logic, auth flows) with no matching skill invoked |

### Directive priority + alert dedup

When the QA agent injects a steering directive it takes over Smith's next action completely — the planner suppresses all `required`/`recommended` suggestions while a directive is active. QA alerts at medium/low urgency go to the dashboard only; only `high` urgency alerts surface in Smith's tool envelope to keep the model context lean.

**Content-based dedup** — an identical `(code, message)` alert is suppressed for 30 minutes after the first injection. Without this, persistent state (e.g. "553 cells lack tested_by") would re-surface every 2-minute cycle and Smith would burn turns acknowledging the same message it just answered. The cooldown resets the moment the message text changes (counts grow, condition flips), so escalations still land immediately.

**HUMAN_STEER nag** — free-form instructions from the operator are nagged on every tool call until Smith calls `session(action="qa_reply")` to acknowledge. This prevents Smith reading the steer once, deciding to act on the substance, and never closing the loop with a reply the human can see on the dashboard.

---

## Known assets vault

The MCP server auto-extracts authentication context into `session.json → known_assets`:

| Key | Populated from |
|---|---|
| `credentials` | A 2xx POST to an auth-looking URL with a `username + password` body is recorded as a working credential pair. |
| `auth_tokens` | Any JWT-shaped string (`eyJ…`) found in response bodies or request `Authorization` headers is captured with timestamp + source URL. |
| `auth_endpoints` | Login endpoints discovered above are stored with their method + body template. |

`session(action='recovery')` surfaces an `auth_context` block at the top of the recovery brief listing the most recent credentials, tokens, and endpoints — Smith uses these instead of marking auth-protected injection cells as `tested_clean` on 401 (which is now rejected at the server).

**Missing-auth warning** — every `http_request` returning 401/403 with **no auth** in the request (no `Authorization`, no `Cookie`, no `X-Api-Key` / `X-Auth-*` / `X-Session-*` header, no `?token=`-style query parameter) gets an `AUTH_MISSING` envelope warning telling Smith exactly which JWT to attach on retry.

> ⚠️ **Note:** `known_assets` stores harvested credentials and JWTs in cleartext in `session.json`, which the dashboard serves. Treat `session.json` — and the dashboard — as sensitive, and see [production-isolation.md](production-isolation.md) for how to contain that exposure.
