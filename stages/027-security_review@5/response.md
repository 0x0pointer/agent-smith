Verdict: fail

Blocking findings: dashboard/js/sessions.js:117 — persisted dashboard runs cannot be selected/scoped after restart without a locally cached run token.

# Security review

## Summary

Verdict: **fail**. Previous blocking findings 1-3 are addressed in the changed regions: session/session-log now scope by DB workdir for run tokens, run-id allocation uses an insert/retry path before worker side effects, and run creation now spawns an agent driver with run context. The dashboard run UI was added, but AC5 is still blocked because persisted runs cannot be selected/scoped unless their plaintext run token happens to be cached in the same browser.

Findings: 1 blocking, 0 non-blocking. I count 5/7 acceptance criteria met at the unit/API level, with AC4 only partially verifiable from snapshot persistence and AC5 not met.

## Changed-file triage and blast radius

| File | Risk | Blast radius |
|---|---:|---|
| control_plane/__init__.py | MED | New export; 3 public functions |
| control_plane/orchestrator.py | HIGH | Run creation/stop/status; ~25 create_run refs, 4 stop refs |
| core/api_server/__init__.py | HIGH | Auth middleware for all `/api/*` routes |
| core/api_server/routes/__init__.py | LOW | Route registration only |
| core/api_server/routes/findings_routes.py | HIGH | Findings/session/cost/coverage read/mutate routes; 8 scoped-data refs |
| core/api_server/routes/misc_routes.py | MED | QA/steering reads |
| core/api_server/routes/runs_routes.py | HIGH | New run control API; operator/run token boundary |
| core/api_server/routes/scan_state_routes.py | MED | Steering write path |
| core/api_server/routes/session_log_routes.py | HIGH | Reasoning/event log disclosure boundary; 2 callers via FastAPI/router |
| core/api_server/routes/sessions_routes.py | HIGH | Session enumeration boundary; 2 callers via FastAPI/router |
| core/api_server/routes/triage_routes.py | MED | Triage state/directive mutation |
| core/api_server/routes/wishlist_routes.py | MED | Wishlist read/mutate paths |
| core/cost.py | MED | Cost snapshot persistence |
| core/coverage/__init__.py | MED | Coverage persistence/load semantics |
| core/dashboard_auth.py | HIGH | Bearer token minting/verification |
| core/db/__init__.py | HIGH | DB enablement and run-scoped snapshots |
| core/db/repository.py | HIGH | SQL persistence, token lookup, run insert/upsert |
| core/db/schema.py | MED | New DB schema |
| core/findings.py | HIGH | Finding load/save/mutate scoping |
| core/paths.py | HIGH | Runtime state root isolation |
| core/qa_agent/daemon.py | MED | QA snapshot persistence |
| core/run_context.py | HIGH | Run id/name/network sanitization |
| core/session/lifecycle.py | HIGH | Session start/load, container cleanup |
| core/session/persistence.py | HIGH | Session write-through persistence |
| core/steering.py | MED | Run-scoped steering queue |
| core/wishlist.py | MED | Run-scoped wishlist queue |
| dashboard/js/sessions.js | HIGH | Run selection/token handling for dashboard tabs |
| dashboard/tabs/sessions.html | MED | Run start/list UI |
| docker-compose.yml | MED | Local Postgres service config |
| mcp_server/http_tools.py | MED | PoC/artifact path relocation |
| mcp_server/scan_engine/artifacts.py | MED | Artifact path relocation |
| mcp_server/session_tools/containers.py | LOW | Status message API URL helpers |
| poetry.lock | LOW | Dependency lockfile |
| pyproject.toml | LOW | Dependencies + console script |
| smith_cli.py | MED | Control-plane CLI entrypoint |
| tests/test_container_isolation.py | LOW | Tests |
| tests/test_control_plane.py | LOW | Tests |
| tests/test_dashboard_auth.py | LOW | Tests |
| tests/test_dashboard_runs_ui.py | LOW | Tests |
| tests/test_db_repository.py | LOW | Tests |
| tests/test_paths.py | LOW | Tests |
| tests/test_runs_routes.py | LOW | Tests |
| tests/test_smith_cli.py | LOW | Tests |
| tools/kali_runner.py | HIGH | Docker command API/container isolation |
| tools/metasploit_runner.py | HIGH | Docker command API/container isolation |
| tools/mobsf_runner.py | HIGH | Docker command API/container isolation |

## Findings

### Blocking: persisted dashboard runs cannot be selected after restart without a locally cached run token

**File/line:** `dashboard/js/sessions.js:117`

The sessions tab lists runs from `/api/runs` using the operator token, but it disables `Select` unless `localStorage.smith_run_tokens[run_id]` already contains that run's plaintext token. `/api/runs` deliberately returns only `{run_id,target,status,depth,workdir}`, and the DB stores only token hashes, so after a process restart in a fresh browser/session, or for runs created by another client/API, the dashboard can list persisted runs but cannot select them. Operator-token requests to existing data tabs are not run-scoped either (`request.state.run_id` is empty, so routes such as `/api/findings` fall back to the global JSON cache), so there is no alternate path for the listed run to scope the tabs. This violates AC5's requirement that after restart the dashboard lists all runs and selecting a run scopes existing tabs to that run.

**Required fix:** add a real operator-mediated selection path for persisted runs. For example, add an operator-only endpoint that mints a new per-run token for an existing `run_id` (or an operator-token mode that validates a selected `run_id` server-side without accepting arbitrary run ids from run tokens), update the sessions UI to use it instead of disabling rows without cached tokens, and add a browser/API regression test that starts/list-persisted runs with no `smith_run_tokens` localStorage and proves selecting run A makes `/api/findings`, `/api/session`, `/api/coverage`, etc. read run A rather than the global cache or run B.

## Test coverage gaps

- `tests/test_dashboard_runs_ui.py` only checks for substrings and even accepts an unused `selectedRunToken` sentinel; it would not fail if selection never scopes the dashboard.
- No test covers the AC5 restart/new-browser path where `/api/runs` lists a persisted run but the browser has no cached per-run token.
- No live Docker/Postgres/browser test was run here; container and control-plane behavior is unit/mocked in the diff.

## Security/adversarial notes

For the high-risk auth/session changes I checked the reachable run-token path: a holder of run A's bearer token reaches the middleware, `request.state.run_id` is set from the hashed DB token row, and session/session-log now resolve only run A's workdir from the DB. The concrete cross-run event-log leak from the previous review appears fixed in the changed region. I did not find a new reachable injection path in the since-review diff: Docker/agent subprocess launches use argv lists, SQL uses SQLAlchemy Core parameters, and dashboard-rendered run fields are HTML-escaped; target text is still placed into an LLM prompt via JSON, but only the operator/control-token run-creation path can supply it.

## Not covered

I did not re-audit unchanged parts of the 46-file change outside `/tmp/fabro/since-review.diff`, per the re-review instruction. I did not run the full suite or live services; automated checks were already reported as passing, and I used targeted code/history/caller inspection only.