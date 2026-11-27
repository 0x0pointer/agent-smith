Verdict: fail

Blocking findings: unauthenticated API access in DB/per-run mode; findings detail/mutation routes are not run-scoped; Metasploit/MobSF dynamic API ports are not discovered; fixed listener/handler ports collide across runs; stop_run only edits DB; smith start is a stub; POST /api/runs validation is incomplete; required tests do not exercise the broken behaviours.

Contents of `/tmp/fabro/security-review.md`:

```markdown
# Security review

## Summary
Blocking findings: 8. Non-blocking findings: 0. I reviewed the full diff once, then focused on the HIGH/MEDIUM changed regions, caller searches, origin/main snippets, targeted blame/history for auth and container command API changes, and a small targeted API reproduction. Only 1 of 7 acceptance criteria appears fully met (single-run compatibility/tests); AC1-AC6 are incomplete or violated.

## Changed-file risk and blast radius

| File | Risk | Blast radius |
|---|---:|---|
| control_plane/__init__.py | LOW | New re-export only; called by CLI/routes. |
| control_plane/orchestrator.py | HIGH | New run lifecycle control; called by `/api/runs*` and `smith_cli`; affects every platform run. |
| core/api_server/__init__.py | HIGH | Middleware on every `/api/*` request; critical auth boundary. |
| core/api_server/routes/__init__.py | LOW | Route registration only. |
| core/api_server/routes/findings_routes.py | HIGH | Existing dashboard findings/session/cost/coverage/detail/mutation endpoints. |
| core/api_server/routes/runs_routes.py | HIGH | New create/list/stop run API. |
| core/cost.py | MEDIUM | Cost state funnel; persisted per run when DB enabled. |
| core/coverage/__init__.py | MEDIUM | Coverage state funnel; used by coverage MCP/dashboard flows. |
| core/dashboard_auth.py | HIGH | Token mint/verify for legacy, operator, and run tokens. |
| core/db/__init__.py | HIGH | New DB repository gateway used by all write-through state. |
| core/db/repository.py | HIGH | New SQL persistence layer and token lookup. |
| core/db/schema.py | HIGH | New run/snapshot/token tables. |
| core/findings.py | MEDIUM | Findings state funnel and signed output side effects. |
| core/paths.py | MEDIUM | Runtime path root for state, artifacts, PoCs, logs. |
| core/run_context.py | MEDIUM | Run id/container/network naming helpers used by DB and Docker runners. |
| core/session/lifecycle.py | HIGH | Session start/load/stop paths; tool-container cleanup. |
| core/session/persistence.py | HIGH | Session flush write-through to DB. |
| core/steering.py | MEDIUM | Steering queue persistence. |
| core/wishlist.py | MEDIUM | Wishlist queue persistence. |
| mcp_server/http_tools.py | MEDIUM | PoC/artifact path changes for HTTP tool. |
| mcp_server/scan_engine/artifacts.py | MEDIUM | Artifact root moved under run workdir. |
| mcp_server/session_tools/containers.py | MEDIUM | User-visible tool container API URLs. |
| poetry.lock | MEDIUM | New DB dependencies. |
| pyproject.toml | MEDIUM | New CLI entrypoint and DB dependencies. |
| smith_cli.py | MEDIUM | New operator entrypoint, but only calls stubs. |
| tools/kali_runner.py | HIGH | Docker command API container creation and all Kali exec calls; `api_url()` has multiple callers. |
| tools/metasploit_runner.py | HIGH | Docker command API container creation and all Metasploit exec calls. |
| tools/mobsf_runner.py | HIGH | Docker command API container creation and all MobSF scans. |
| tests/test_container_isolation.py | LOW | New tests, but do not exercise real Docker port discovery/collisions. |
| tests/test_control_plane.py | LOW | New unit tests for orchestrator only. |
| tests/test_dashboard_auth.py | LOW | New token hashing test. |
| tests/test_db_repository.py | LOW | New DB snapshot tests. |
| tests/test_paths.py | LOW | New path-root tests. |
| tests/test_runs_routes.py | LOW | New run route tests. |
| tests/test_smith_cli.py | LOW | New CLI stub tests. |

## Findings

### Blocking — unauthenticated API access remains possible in DB/per-run mode
- **File/line:** `core/api_server/__init__.py:113`
- **Problem:** If a request has no valid DB bearer token and there is no legacy `logs/dashboard.token`, the middleware falls through and serves the route. In the new platform mode run/operator tokens live only in DB, so an unauthenticated local process can call `GET /api/findings` and receive 200 instead of the AC6-required 401. I confirmed this with a targeted TestClient check (`/api/findings` without a token returned 200; `/api/runs` returned 403 from the route, not 401 from auth). Attacker model: a local untrusted process/user on the operator host reaches `127.0.0.1:7777/api/*`; impact is unauthenticated read of any fallback JSON state and inconsistent protection of control APIs.
- **Fix:** In auth-on mode, require either a valid DB token or a valid legacy token before any `/api/*` route runs. Return 401 for missing/invalid credentials; only set `operator` from a verified legacy/operator token.

### Blocking — per-run tokens do not scope all findings read/mutation routes
- **File/line:** `core/api_server/routes/findings_routes.py:53`
- **Problem:** `/api/findings/{finding_id}` ignores `request.state.run_id` and reads the process-global `_FINDINGS_FILE`; `PATCH` and `DELETE` at lines 302-330 call `core.findings` without a request run context. A run-A token can therefore be served data from the dashboard process's global file instead of run A's DB snapshot, or cannot read its own DB-backed detail at all; mutation endpoints are likewise not tied to the token's run id. This violates AC5/AC6's requirement that all existing tabs are run-scoped and token A cannot read or mutate another run.
- **Fix:** Make detail, patch, and delete routes accept `Request`, load/update the DB snapshot for `request.state.run_id`, and reject run tokens without a matching run context. Keep legacy file behavior only for verified legacy single-run/operator mode.

### Blocking — Metasploit and MobSF publish ephemeral ports but keep using fixed ports
- **File/line:** `tools/metasploit_runner.py:124`
- **Problem:** In multi-run mode Docker is asked to publish `127.0.0.1::5000`, but after the container starts line 144 records `MSF_PORT` instead of discovering Docker's assigned host port. `api_url()` then polls and executes against `127.0.0.1:5002`, where no multi-run container is listening. MobSF has the same bug at `tools/mobsf_runner.py:147`/`:156` with `MOBSF_PORT`. This makes the new dynamic API port isolation fail and prevents those tools from starting in a run.
- **Fix:** Add and use a Docker `port` discovery helper for Metasploit and MobSF, equivalent to Kali's `_discover_host_port`, and only update `_RUN_API_PORTS` after successfully reading the assigned host port.

### Blocking — fixed listener/handler host ports still make concurrent tool containers collide
- **File/line:** `tools/kali_runner.py:212`
- **Problem:** Kali still publishes fixed host ports `1080`, `8888`, `8889`, and `11601`; Metasploit similarly publishes fixed `4444`, `4445`, and `1081` at `tools/metasploit_runner.py:126`. Two concurrent runs cannot both start these containers on one host because the second Docker run will hit host-port allocation conflicts. This violates AC3's non-colliding simultaneous worker/tool-container requirement.
- **Fix:** In multi-run mode publish these listener/handler ports with per-run host ports (or do not publish them by default and expose the assigned mapping per run), and add tests that start two mocked `ensure_running()` flows and assert no fixed host ports are reused.

### Blocking — stopping a run only edits the database
- **File/line:** `control_plane/orchestrator.py:95`
- **Problem:** `stop_run()` loads a session snapshot, sets `status = "stopped"`, and writes it back. It does not stop the worker process/container, Kali/Metasploit/MobSF containers, or the per-run Docker network. A user pressing Stop sees success while the run and privileged Docker-backed command APIs keep running, violating AC5 and the stop-run edge case.
- **Fix:** Track the worker resource for each run and, before/while marking the DB row stopped, stop only that run's worker and tool containers and remove only that run's network. Make the operation idempotent and record cleanup failures without stopping other runs.

### Blocking — `smith start` is a stub and does not start the approved platform
- **File/line:** `control_plane/orchestrator.py:106`
- **Problem:** `start_control_plane()` returns a static JSON object; `smith_cli.py` just prints it. There is no `docker-compose.yml`, no Postgres startup, no dashboard/API/orchestrator service launch, no operator token creation/return, and no health check proving `GET /api/runs` can return an empty list. AC1 is not implemented.
- **Fix:** Implement `smith start` to bring up the approved local control plane (Postgres plus dashboard/API/orchestrator on loopback), mint/provide the operator/control token safely, and have `smith status` report actual service health.

### Blocking — run creation validation is not the accepted API contract
- **File/line:** `control_plane/orchestrator.py:24`
- **Problem:** `_validate()` assumes `payload` is a dict and only checks non-empty `target` and an allowed `depth`. A malformed JSON shape such as `[]` raises `AttributeError` through `/api/runs` (targeted check: TestClient raised instead of returning 400), and oversized `scope`/`out_of_scope` are ignored rather than rejected before DB rows/workdirs/workers. This violates AC2 and the malformed/oversized edge cases.
- **Fix:** Validate the request body schema before calling `.get()`, reject non-dict/malformed input with 400, enforce documented length/count limits on target/scope/out_of_scope, and ensure validation happens before creating the workdir, minting tokens, inserting rows, or spawning workers.

### Blocking — required tests do not exercise the broken behaviours
- **File/line:** `tests/test_container_isolation.py:23`
- **Problem:** The required isolation and auth tests do not fail when the implemented feature is broken. `test_two_run_apis_do_not_collide` manually seeds `_RUN_API_PORTS` instead of exercising `ensure_running()`/Docker port discovery, so it missed the Metasploit/MobSF fixed-port bug; route tests also omit no-token 401, malformed non-dict `POST /api/runs`, stop cleanup, and run-scoped findings detail/mutation checks.
- **Fix:** Replace the manual port-map assertions with mocked Docker run/port flows through `ensure_running()`, and add negative route tests for no-token 401, malformed/oversized create bodies with no side effects, real stop cleanup calls, and findings detail/patch/delete isolation under run tokens.

## Test coverage gaps
- The new route tests do not assert AC6's no-token 401 behavior; a targeted check showed `/api/findings` still returns 200 without a token in DB mode.
- `test_two_run_apis_do_not_collide` manually seeds `_RUN_API_PORTS` and never exercises `ensure_running()`/Docker port discovery, so it missed the Metasploit and MobSF fixed-port fallback bug.
- No test covers two real mocked Docker runs with Kali/Metasploit fixed listener/handler port collisions.
- Stop tests assert the DB response only; they do not assert worker/tool-container/network cleanup.
- `test_create_run_validation_400` tests a direct `ValueError`, not malformed API bodies, oversized scope/out_of_scope, or no side effects after validation failure.
- No dashboard route test covers findings detail, patch, delete, steering, logs, or other existing tabs under per-run tokens.

## What I did not cover
- I did not rerun the full test suite because the verify log already shows it passed.
- I did not run Docker or Postgres; container findings are based on the Docker argv/API URL code paths and targeted caller/history review.
- I did not audit unrelated dashboard UI files because they are not in the diff.
- I did not inspect `poetry.lock` beyond dependency/security relevance.
```