Summary:
- Root cause: the multi-run control plane still had single-run assumptions in four places: session event APIs read the global `smith-events` directory for run tokens, run creation used upsert instead of atomic create on generated IDs, workers launched idle `python -m mcp_server` without scan context, and the Sessions tab still used legacy `/api/sessions` instead of platform `/api/runs`.
- Fix:
  - Added atomic `create_run()`/`get_run()` DB repository methods and bounded run-id collision retries before workdir/token/worker side effects.
  - Changed run creation to spawn an agent driver command with `SMITH_RUN_ID`, `SMITH_WORKDIR`, target/depth/scope env, and an initial `session(action='start', ...)` prompt instead of idle MCP.
  - Scoped `/api/sessions` and `/api/session-log` to the authenticated run’s stored workdir; cross-run replay by run token now returns 403.
  - Reworked the Sessions tab into a Runs UI using `/api/runs`, with Start Run form and selected-run token storage for scoping data tabs.
  - Added regression tests for the reviewed defects.

Verification run in this session:
- Red step before implementation: focused regression command failed with `4 failed` covering the four reviewed defects.
- Green focused step after fix:  
  `poetry run pytest -q tests/test_control_plane.py::test_create_run_retries_generated_id_collision_before_side_effects tests/test_control_plane.py::test_create_run_spawns_agent_driver_with_run_start_context tests/test_runs_routes.py::test_run_token_scopes_sessions_and_session_log_to_run_workdir tests/test_dashboard_runs_ui.py::test_sessions_tab_uses_runs_api_for_platform_run_management` → `4 passed`.
- Adjacent tests:  
  `poetry run pytest -q tests/test_control_plane.py tests/test_runs_routes.py tests/test_dashboard_runs_ui.py tests/test_db_repository.py tests/test_dashboard_auth.py` → `41 passed`.
- Required full suite:  
  `poetry run pytest -q` → `2808 passed, 22 skipped, 11 warnings`.