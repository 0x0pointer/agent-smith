1. Intent
Build the issue as one platform change, in vertical slices: run identity/workdir isolation -> Postgres read/write model -> per-run tool-container isolation -> always-on orchestrator/worker launch -> multi-run dashboard/tokens. Keep the existing single-scan worker model inside each worker so the 87 `scan_session.get()` call sites are not rewritten. `smith start` becomes the operator entrypoint for an always-on local control plane that can run multiple isolated scans concurrently, while a documented `SMITH_SINGLE_RUN=1`/no-DB mode preserves today’s MCP single-run workflow.

2. Acceptance criteria
1. `smith start` brings up Postgres, dashboard/API on `127.0.0.1:7777`, and orchestrator; `smith status` shows healthy services and `GET /api/runs` returns an empty list before scans.
2. `POST /api/runs` from the dashboard/API validates input, inserts a run, returns `{run_id, status, dashboard_url, token}`, and starts one worker using `SMITH_RUN_ID` and `SMITH_WORKDIR`.
3. Two simultaneous `POST /api/runs` calls create two workers whose Kali/Metasploit/MobSF containers and Docker networks are named with different run ids, use non-colliding dynamic API ports, and keep artifacts/PoCs/events under separate workdirs.
4. Findings, diagrams, chains, coverage endpoints/cells, known assets, steering, wishlist, cost summary, and session/run metadata are persisted in Postgres keyed by `run_id`; large artifacts, PoCs, and smith-events remain on disk and are referenced by id/path.
5. The dashboard lists all runs after process restart, selecting a run scopes all existing tabs to that run, and stopping run A does not stop or mutate run B.
6. Bearer token auth maps tokens to run ids: no token is 401, token A cannot read/mutate run B, and the operator/control token may create/stop runs.
7. Existing MCP tools and single-run tests keep working without `SMITH_DATABASE_URL` and with `SMITH_SINGLE_RUN=1`.

3. Boundaries
Always: derive state paths through `core.paths`; use `core.store`/existing `_load`/`_save` funnels; use `tools.docker_cli.docker_executable`; keep command APIs loopback-only; use parameterized SQL via SQLAlchemy Core; keep blobs out of Postgres.
Never: do not rewrite all session call sites; do not remove any MCP tool action; do not expose Docker/container command APIs on `0.0.0.0`; do not add accounts/RBAC/billing; do not store secrets in logs or URL query strings; do not modify `skills/` submodule content.

4. Code map
Slice 1, run roots (tests: `test_paths.py`, existing `test_session.py`): `core/run_context.py` add `run_id()`, `workdir()`, `docker_network_name()`, `container_name(tool)`, `sanitize_run_id()`; `core/paths.py` root runtime state under `SMITH_WORKDIR` when set while leaving code/static dirs at `REPO_ROOT`; `mcp_server/scan_engine/artifacts.py` and `mcp_server/http_tools.py` use `core.paths.ARTIFACTS_DIR`/`POCS_DIR`.
Slice 2, DB persistence (tests: `test_db_repository.py`, existing `test_findings.py`, `test_coverage.py`, `test_wishlist.py`): add `core/db/{__init__.py,schema.py,repository.py}` with migrations-on-connect and run-scoped CRUD; update `pyproject.toml`/lock for SQLAlchemy Core + psycopg; update `core/session/lifecycle.py`, `core/session/persistence.py`, `core/findings.py`, `core/coverage/__init__.py`, `core/steering.py`, `core/wishlist.py`, `core/cost.py` to write-through to DB when configured and still maintain the JSON cache.
Slice 3, isolated containers (tests: `test_container_isolation.py`, existing `test_kali_proxychains.py`, `test_session_tools_helpers.py`): update `tools/kali_runner.py`, `tools/metasploit_runner.py`, `tools/mobsf_runner.py` to compute names/API URLs/ports after start from run id, attach `smith-run-<run_id>` network, publish command API as `127.0.0.1::container_port`, and stop only that run’s containers; update `mcp_server/session_tools/containers.py` and `core/session/lifecycle.stop_pentest_containers` to use the run context.
Slice 4, control plane (tests: `test_control_plane.py`, `test_smith_cli.py`): add `control_plane/orchestrator.py` routes `POST /runs`, `GET /runs`, `POST /runs/{run_id}/stop`; add `smith` CLI module/console script for `start|stop|status`; add `docker-compose.yml` and `installers/worker/Dockerfile`; reuse `core/api_server/smith/spawn.py` for per-run agent spawn with run env.
Slice 5, dashboard/auth (tests: `test_runs_routes.py`, `test_dashboard_auth.py`, existing `test_api_server.py`, `test_sessions_api.py`): update `core/dashboard_auth.py` to store token metadata `{token_hash, run_id, role}` in DB; middleware sets `request.state.run_id`; update dashboard routes for findings/session/cost/coverage/wishlist/triage to query by run id; add run-list/start UI in `dashboard/tabs/sessions.html` and `dashboard/js/sessions.js`.

5. Edge cases
| State/input | Expected behaviour |
|---|---|
| Empty run list | Dashboard shows no runs and Start Run remains available. |
| Malformed target/depth/body | `POST /api/runs` returns 400 without creating DB rows or containers. |
| Oversized scope/out_of_scope | Request is rejected at documented limits; no worker starts. |
| Duplicate target submitted twice | Two distinct run ids are allowed; state and containers remain isolated. |
| Concurrent create for same generated id/name | Orchestrator retries id generation or returns 409 before starting containers. |
| Postgres unavailable | `smith status` unhealthy; run creation returns 503; worker file cache is not corrupted. |
| Docker run/network failure | Run becomes `failed`, partial worker/tool containers/network are cleaned best-effort. |
| Stop run twice | First stops resources and marks stopped; second is idempotent 200/404-safe with no other run affected. |

6. Security considerations
Untrusted input enters through dashboard/API run creation, steering/wishlist forms, MCP tool options, and target-derived coverage data. Validate and length-limit run parameters, use parameterized SQL only, hash tokens at rest, keep tokens in URL fragments not query strings, and prevent token A from selecting arbitrary `run_id`. Docker access is privileged via the host socket; only the orchestrator should receive it, and worker/tool container names, networks, and mounts must be run-scoped. Continue existing shell-injection protections: subprocess argv lists for Docker/agent launch; no shell concatenation of request fields. Logs must redact secrets and must not include bearer tokens.

7. Test plan
Add `tests/test_paths.py::test_smith_workdir_rehomes_runtime_state_only` and `::test_default_paths_unchanged_without_env`.
Add `tests/test_db_repository.py::{test_session_findings_coverage_round_trip_by_run_id,test_json_cache_survives_db_disabled,test_db_error_does_not_truncate_cache}`.
Add `tests/test_container_isolation.py::{test_kali_run_uses_run_scoped_name_network_and_ephemeral_port,test_two_run_apis_do_not_collide,test_stop_only_current_run_containers}` with Docker subprocess/aiohttp mocked.
Add `tests/test_control_plane.py::{test_create_run_inserts_row_and_starts_worker,test_concurrent_create_two_runs,test_create_run_validation_400,test_docker_failure_marks_failed_and_cleans}`.
Add `tests/test_runs_routes.py::{test_api_runs_list_persists_after_restart,test_run_token_scopes_existing_tabs,test_cross_run_token_rejected,test_operator_token_can_create_and_stop}`.
Update `tests/test_dashboard_auth.py` for token metadata and hashed storage; update existing route tests to set request run context. Existing `test_session.py`, `test_findings.py`, `test_coverage.py`, `test_wishlist.py`, `test_api_server.py`, `test_sessions_api.py`, `test_kali_proxychains.py`, and `test_session_tools_helpers.py` must keep passing.
Tests required: yes

8. Review focus
1. Whether DB write-through preserves current JSON-cache semantics and terminal-status race protections.
2. Whether any dashboard route can be forced to read another run by query/body manipulation.
3. Whether dynamic Docker port discovery is race-free and updates API URLs after restart.
4. Whether cleanup can accidentally stop fixed legacy containers or another run’s containers.
5. Whether `smith start`/install changes preserve existing single-run developer workflow.

9. Assumptions
The full issue, not only Phase 0, is in scope for this build. A local operator/control token is permitted for creating/stopping runs because per-run tokens alone cannot safely protect the Start Run surface. SQLAlchemy Core with psycopg is acceptable as a normal PyPI dependency. Tests may use SQLite or mocked DB adapters for unit coverage, but platform mode must support PostgreSQL. `SMITH_SINGLE_RUN=1` is the compatibility switch for the old daemon-style workflow.

10. Suspicious content
none

Size: standard
Risk level: high
Reason: XL by the planning skill sizing (new persistence, orchestration, auth, Docker isolation, and dashboard surfaces); mistakes can cross-contaminate pentest data, expose command APIs, or stop the wrong containers.