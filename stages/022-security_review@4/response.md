verdict: fail

blocking findings: run tokens can read unscoped session logs/session indexes; duplicate run IDs overwrite existing runs instead of retrying/409; run creation launches only an idle MCP server; dashboard run list/start/select UI is missing.

# Security review

## Summary
Blocking findings: 4. Non-blocking findings: 0. I treated this as a large/high-risk differential review; `/tmp/fabro/since-review.diff` was not present even though this is a re-review, so I checked the prior blocker status and focused on the changed regions and their directly affected routes/callers. Three of seven acceptance criteria appear met at the API/unit level; AC3/AC5/AC6 still have blocking isolation or dashboard gaps, and AC4 was only partially verifiable from the snapshot-based DB implementation.

The prior phase-control finding is not repeated as blocking because the approved spec now explicitly excludes legacy phase-control endpoints and typed phase steering from cross-run token isolation for this build.

## Changed files triage

| File | Risk | Blast radius |
|---|---:|---|
| control_plane/__init__.py | LOW | Re-export only |
| control_plane/orchestrator.py | HIGH | Public run lifecycle; `create_run` 20 refs, starts/stops processes/containers |
| core/api_server/__init__.py | HIGH | Auth middleware for every `/api/*` route |
| core/api_server/routes/__init__.py | MEDIUM | Route registration/re-export |
| core/api_server/routes/findings_routes.py | HIGH | Run-scoped persisted findings/session/cost/coverage reads and mutations |
| core/api_server/routes/misc_routes.py | HIGH | Run-scoped QA/steering reads |
| core/api_server/routes/runs_routes.py | HIGH | Public run create/list/stop API |
| core/api_server/routes/scan_state_routes.py | HIGH | Steering/phase mutation; phase controls accepted out-of-scope |
| core/api_server/routes/triage_routes.py | HIGH | Run session and steering mutation |
| core/api_server/routes/wishlist_routes.py | HIGH | Run-scoped wishlist mutation and steering injection |
| core/cost.py | MEDIUM | Cost snapshot write-through |
| core/coverage/__init__.py | MEDIUM | Coverage snapshot write-through |
| core/dashboard_auth.py | HIGH | Token minting, hashing, lookup |
| core/db/__init__.py | HIGH | DB enablement and repository singleton |
| core/db/repository.py | HIGH | SQL persistence and token lookup; `save_snapshot`/`load_snapshot` 39/40 refs |
| core/db/schema.py | MEDIUM | New persistence schema |
| core/findings.py | HIGH | Findings update/delete and DB write-through |
| core/paths.py | HIGH | Runtime path isolation for state/artifacts/PoCs/logs |
| core/qa_agent/daemon.py | MEDIUM | QA snapshot persistence |
| core/run_context.py | HIGH | Run id/container/network naming primitive |
| core/session/lifecycle.py | HIGH | Session start/load/stop containers |
| core/session/persistence.py | HIGH | Session JSON/DB write-through and race protections |
| core/steering.py | HIGH | Directive queue run scoping; `add_directive` 65 refs |
| core/wishlist.py | HIGH | Wishlist queue run scoping |
| docker-compose.yml | MEDIUM | Local Postgres service and loopback port |
| mcp_server/http_tools.py | MEDIUM | PoC/artifact filesystem paths |
| mcp_server/scan_engine/artifacts.py | MEDIUM | Artifact filesystem root |
| mcp_server/session_tools/containers.py | HIGH | Tool container API URLs |
| poetry.lock | LOW | Dependency lock update |
| pyproject.toml | LOW | Dependencies/CLI entrypoint |
| smith_cli.py | MEDIUM | Operator entrypoint for lifecycle commands |
| tests/test_container_isolation.py | LOW | New container isolation tests |
| tests/test_control_plane.py | LOW | New control-plane tests |
| tests/test_dashboard_auth.py | LOW | Token auth tests |
| tests/test_db_repository.py | LOW | DB persistence tests |
| tests/test_paths.py | LOW | Path isolation tests |
| tests/test_runs_routes.py | LOW | Run route tests |
| tests/test_smith_cli.py | LOW | CLI tests |
| tools/kali_runner.py | HIGH | Docker container/network/port isolation; command API is root RCE if mispublished |
| tools/metasploit_runner.py | HIGH | Docker container/network/port isolation; command API/handler ports |
| tools/mobsf_runner.py | HIGH | Docker container/network/port isolation |

## Findings

### Blocking: run tokens can read unscoped session logs and session indexes
A holder of run A's bearer token is accepted by the changed auth middleware for any `/api/*` route, but `core/api_server/routes/session_log_routes.py:46` and `core/api_server/routes/sessions_routes.py:89` do not accept `Request`, do not check `request.state.run_id`, and enumerate `_paths.SMITH_EVENTS_DIR` globally. Attack path: use run A's dashboard token, call `GET /api/session-log?session=<known-or-listed-id>` or `GET /api/sessions`; the route returns targets, session metadata, and reasoning/event payloads for sessions outside run A. This is outside the accepted phase-control exception and violates AC5/AC6 run-token isolation for existing dashboard data tabs.

Required fix: make these routes run-aware. For run tokens, resolve the authenticated run's workdir/event path from Postgres and only return that run's log/index, or return 403 if the data is not modeled yet. Keep all-run listing behind the operator role only. Add regression tests with run A and run B/legacy event streams proving run A's token cannot list or replay other runs.

### Blocking: duplicate run ids overwrite an existing run instead of retrying or returning 409 before side effects
`control_plane/orchestrator.py:244` calls `_new_run_id()` once, then `repo.upsert_run()` at line 256. Because `upsert_run()` updates an existing row, a collision reuses the same workdir/token namespace and then starts another worker for the same run id. This violates the edge-case acceptance criterion that concurrent create for the same generated id/name retries generation or returns 409 before starting containers/workers.

Required fix: allocate run ids with an atomic insert/create operation that fails on existing `runs.run_id`, retry a bounded number of times before creating the workdir/token/worker, and return 409 if exhausted. Add a test that forces `_new_run_id()` to collide with an existing row and asserts no worker starts and the original run snapshot is unchanged.

### Blocking: `POST /api/runs` records a running scan but only launches an idle MCP server
`control_plane/orchestrator.py:85` starts `[sys.executable, "-m", "mcp_server"]` with `SMITH_RUN_ID` and `SMITH_WORKDIR`, but it never launches the per-run agent CLI/reused spawn path, never passes the requested target/depth/scope to the worker, and never starts a scan. The API returns `status: running`, so users see a run that cannot progress unless something external manually drives that MCP server, which does not satisfy the approved intent/code map for always-on run creation.

Required fix: have run creation start the actual per-run worker/agent flow described by the spec (for example via the existing `core.api_server.smith.spawn` path or the worker container entrypoint) and pass the validated target/depth/scope. Mark the run failed and clean up if that launch fails. Add a test that verifies the spawn command/environment includes the run id, workdir, and scan target/depth, not just an idle MCP process.

### Blocking: dashboard run list/start/select UI is not implemented
No dashboard assets changed. `dashboard/js/sessions.js:41` still polls `/api/sessions`, and `dashboard/tabs/sessions.html` only contains the legacy session replay table; there is no Start Run form, no `/api/runs` run list, and no selected-run token/state used to scope the existing tabs. As a user-visible result, AC5 is not met: after restart the dashboard cannot list Postgres runs or select a run to scope data tabs.

Required fix: implement the specified dashboard run-list/start UI, fetch `/api/runs` with the operator token, create runs via `/api/runs`, store/select the returned per-run token without putting it in query strings, and make existing data-tab fetches use the selected run token. Add browser/API-level tests that would fail if the dashboard keeps using `/api/sessions` instead of `/api/runs` for platform runs.

## Test coverage gaps
- Missing negative tests for unscoped existing dashboard routes such as `/api/session-log` and `/api/sessions` under a run token.
- Missing duplicate-run-id collision test that proves no overwrite and no worker start before retry/409.
- Missing test that run creation launches the agent/scan driver with target/depth/scope, not just an idle MCP server.
- Missing dashboard asset tests for the required Start Run/run selection UI; no dashboard files were changed.

## What I did not cover
I did not run the full test suite or live Docker/Postgres services. I did not audit unchanged routes beyond direct callers/route surfaces reached from the new auth and run-scoping changes. Because `/tmp/fabro/since-review.diff` was absent, I could not restrict the re-review precisely to the since-review delta.