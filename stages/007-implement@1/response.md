Changed:
- Added run/workdir context and runtime path rehoming via `core.run_context` + `core.paths`, and switched artifact/PoC writes to those canonical paths.
- Added DB-backed run snapshots in `core/db/*` and write-through persistence for session/findings/coverage/wishlist/steering/cost, with fail-soft fallback to JSON cache.
- Added run-scoped container naming/API helpers for Kali/Metasploit/MobSF and updated terminal container-stop behavior to target only the current run.
- Added DB-backed dashboard bearer tokens, `/api/runs` create/list/stop routes, scoped API reads for run-token requests, a minimal control-plane orchestrator, and a `smith` CLI entrypoint.
- Restored `_load_artifact_payload()` compatibility with tests that monkeypatch the artifacts dir.

Test coverage:
- Acceptance 1 / slice 1 path isolation:
  - `tests/test_paths.py::test_smith_workdir_rehomes_runtime_state_only`
  - `tests/test_paths.py::test_default_paths_unchanged_without_env`
  - plus existing `tests/test_session.py`
- Acceptance 4 / slice 2 DB persistence + compatibility:
  - `tests/test_db_repository.py::test_session_findings_coverage_round_trip_by_run_id`
  - `tests/test_db_repository.py::test_json_cache_survives_db_disabled`
  - `tests/test_db_repository.py::test_db_error_does_not_truncate_cache`
  - plus existing `tests/test_findings.py`, `tests/test_coverage.py`, `tests/test_wishlist.py`
- Acceptance 3 / slice 3 container isolation:
  - `tests/test_container_isolation.py::test_kali_run_uses_run_scoped_name_network_and_ephemeral_port`
  - `tests/test_container_isolation.py::test_two_run_apis_do_not_collide`
  - `tests/test_container_isolation.py::test_stop_only_current_run_containers`
  - plus existing runner tests
- Acceptance 2, 5, 6 / slices 4-5 control plane + auth:
  - `tests/test_control_plane.py::*`
  - `tests/test_runs_routes.py::*`
  - `tests/test_dashboard_auth.py::test_db_tokens_store_hashes_and_scope_run_ids`
  - `tests/test_smith_cli.py::*`
  - plus existing `tests/test_api_server.py`, `tests/test_sessions_api.py`, `tests/test_dashboard_auth.py`

Verification run:
- Targeted suites for each slice were run during implementation.
- Final full suite: `poetry run pytest -q` → `2783 passed, 22 skipped`.

Concerns:
- The control plane / `smith start|status|stop` implementation is minimal scaffolding, not a full real service launcher for Postgres/docker-compose.
- Run scoping is implemented for the main read surfaces exercised by tests, but not every dashboard tab/mutation path from the spec was fully reworked.
- Dynamic per-run container API port discovery is only partially implemented; helper/state support exists, but the full end-to-end Docker discovery path is not comprehensively exercised.

Noticed, not touched:
- Existing test-suite warnings remain (FastAPI `on_event` deprecation and a few pre-existing async mock/runtime warnings).

STATUS: DONE_WITH_CONCERNS