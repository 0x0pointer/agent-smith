Verdict: fail

Blocking findings: run-scoped API fallback/unscoped routes; dynamic Docker API ports not rediscovered after worker restart; `smith start` can return an unpersisted operator token; orchestrator health is a fake sleep process.

# Security review

## Summary
Blocking findings: 4. Non-blocking findings: 0. This is a re-review: fixes addressed the unauthenticated DB-mode API hole, malformed create bodies, scoped finding mutation basics, default listener-port collisions, and initial MSF/MobSF port discovery, but several acceptance-critical multi-run/auth/control-plane defects remain.

Acceptance criteria status: AC7 appears met; AC1, AC3, AC5, and AC6 are not met; AC2 is only partially met; AC4 was not fully verified and appears incomplete from the diff because persistence is mostly snapshots and several named state types/routes are not run-scoped.

## Changed files triage
| File | Risk | Blast radius / notes |
|---|---:|---|
| control_plane/orchestrator.py | HIGH | New control plane; called by `/api/runs` and `smith`; launches subprocesses, mints tokens, starts/stops Docker resources. |
| control_plane/__init__.py | LOW | Re-export only; 1-hop import surface. |
| core/api_server/__init__.py | HIGH | Global API auth middleware; affects every `/api/*` route. |
| core/api_server/routes/runs_routes.py | HIGH | New run create/list/stop API; operator and run token boundary. |
| core/api_server/routes/findings_routes.py | HIGH | Run-scoped reads/mutations; affects findings/session/cost/coverage tabs. |
| core/api_server/routes/__init__.py | LOW | Route registration/noqa only. |
| core/dashboard_auth.py | HIGH | Token mint/verification and token-at-rest hashing. |
| core/db/{__init__,repository,schema}.py | HIGH | New persistence/auth-token store; all DB-backed run state. |
| core/findings.py | HIGH | Finding load/save/update/delete, HMAC signing behavior, DB write-through. |
| core/session/lifecycle.py | HIGH | Session identity and container stop behavior. |
| tools/kali_runner.py | HIGH | Docker command API container naming, ports, network; `ensure_running`/`api_url` have broad tool impact. |
| tools/metasploit_runner.py | HIGH | Same as Kali for Metasploit. |
| tools/mobsf_runner.py | HIGH | Same as Kali for MobSF. |
| core/paths.py | MEDIUM | Runtime-state path isolation under `SMITH_WORKDIR`. |
| core/run_context.py | MEDIUM | Run-id sanitization and Docker name derivation. |
| core/session/persistence.py | MEDIUM | Session JSON/DB write-through. |
| core/coverage/__init__.py | MEDIUM | Coverage load/save run cache behavior. |
| core/cost.py | MEDIUM | Cost snapshot write-through/load fallback. |
| core/steering.py | MEDIUM | Steering DB snapshot fallback. |
| core/wishlist.py | MEDIUM | Wishlist DB snapshot fallback. |
| docker-compose.yml | MEDIUM | Starts only Postgres and uses static local credentials. |
| mcp_server/http_tools.py | MEDIUM | PoC/artifact path relocation. |
| mcp_server/scan_engine/artifacts.py | MEDIUM | Artifact path relocation. |
| mcp_server/session_tools/containers.py | LOW | Message/API URL display only. |
| smith_cli.py | MEDIUM | Operator entrypoint for start/stop/status. |
| pyproject.toml, poetry.lock | LOW | Dependencies/console script. |
| tests/* | LOW | Test coverage only. |

## Findings

### Blocking — per-run tokens can still see or mutate global/other-run state through unscoped routes
`core/api_server/routes/findings_routes.py:18-25` falls back to the dashboard process-global JSON file whenever a run token has no DB snapshot for that kind. Several existing tabs/actions also still ignore `request.state.run_id` entirely (`wishlist_routes.py:16-76`, `triage_routes.py:60-141`, `misc_routes.py:18-25`, and internal reads in `findings_routes.py:93-125,264`). A holder of run A's token can call these `/api/*` endpoints and receive stale repo-root state or operate on global queues instead of run A's DB-backed state, violating AC5/AC6.

Fix: for a DB-backed run token, never fall back to process-global files; return an empty per-run document or 404/409 when the run snapshot is absent. Thread `run_id` through wishlist, steering/triage, QA/steering reads, and any helper reads used by those routes, and add negative cross-run tests for each dashboard tab/action.

### Blocking — existing tool containers lose their dynamic API port after worker restart
`tools/kali_runner.py:179-180`, `tools/metasploit_runner.py:151-152`, and `tools/mobsf_runner.py:167-168` return `already running` before calling `docker port` when the per-run container already exists. After a worker process restart `_RUN_API_PORTS` is empty, so `api_url()` falls back to fixed 5001/5002/5003 even though Docker published an ephemeral host port; subsequent health checks/commands target the wrong local port. This fails AC3 and the review-focus requirement that dynamic API URLs update after restart.

Fix: in multi-run mode, when `container_running()` is true and the current run has no remembered port, call `_discover_host_port(...)` and store it before returning. Do the same for all three runners and add an already-running/restarted-process test.

### Blocking — `smith start` can return an operator token that was never persisted
`control_plane/orchestrator.py:355-356` mints the operator token immediately after `docker compose up -d postgres` without waiting for the database to accept connections. `core/dashboard_auth.py:80-83` returns a token even when `_db.get_repository()` is `None`, so if Postgres is still starting the CLI prints an unusable operator token; later `/api/runs` calls with that token fail auth. This violates AC1/AC6.

Fix: wait for the database healthcheck/connection and schema migration to succeed before minting tokens, and make DB-token minting fail closed when it cannot persist the hash. `smith start` should report unhealthy instead of returning an unauthenticatable token.

### Blocking — orchestrator health is a fake sleep process
`control_plane/orchestrator.py:174-181` starts `python -c 'time.sleep(...)'` and `control_plane_status()` reports the orchestrator healthy solely because that marker process is alive. This does not prove any orchestrator service is serving run create/list/stop, and status can show `orchestrator: running` while the actual API route surface is unavailable. AC1 requires an always-on orchestrator with real health.

Fix: start the actual orchestrator/control-plane service (or explicitly model it as part of the dashboard API) and health-check the real run-management endpoint/process. Do not use an inert marker process as service health.

## Test coverage gaps
- No test covers a run token whose per-run DB snapshot is absent while repo-root JSON contains another run's data.
- No tests cover wishlist, steering/triage, QA/steering, or skill/session routes under run tokens.
- No test simulates a worker restart with already-running tool containers and empty `_RUN_API_PORTS`.
- No test makes Postgres initially unavailable/starting during `smith start` and verifies the returned operator token authenticates.
- No test proves the orchestrator status is tied to a real service rather than a marker process.

## Not covered
I did not rerun the full test suite. I did not perform a full audit of unchanged dashboard routes beyond tracing the run-token trust boundary from the changed middleware and the routes named in the spec. I did not manually exercise Docker or Postgres; findings are from code paths and targeted history/caller review.