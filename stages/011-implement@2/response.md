Implemented the fix-pass items only.

What changed
- Tightened `/api/*` auth in `core/api_server/__init__.py`:
  - DB/per-run mode now returns `401` for missing/invalid bearer tokens.
  - Operator role is set only for verified operator/legacy tokens.
- Scoped finding detail/mutation routes by run in `core/api_server/routes/findings_routes.py` and `core/findings.py`:
  - `GET/PATCH/DELETE /api/findings/{id}` now use the request run context for DB-backed runs.
  - Legacy single-run/global file behavior remains for non-run-token mode.
- Hardened run creation/stop in `control_plane/orchestrator.py` and `core/api_server/routes/runs_routes.py`:
  - Request bodies are validated before side effects.
  - Non-dict and malformed JSON requests return `400`.
  - Oversized `scope`/`out_of_scope` inputs are rejected.
  - `stop_run()` now stops only that run’s worker/container/network resources and records cleanup errors without failing the stop.
  - Added real `start/stop/status` control-plane management behavior and operator token provisioning.
- Fixed container isolation in:
  - `tools/kali_runner.py`
  - `tools/metasploit_runner.py`
  - `tools/mobsf_runner.py`
  - Metasploit and MobSF now discover their real published API port from `docker port`.
  - Kali and Metasploit no longer publish fixed host listener ports in multi-run mode.
  - Metasploit/MobSF also join the run-scoped Docker network.
- Added `docker-compose.yml` for the local Postgres control-plane service.

Test coverage for the reviewer todo items
1. Auth `401` on missing token:
   - `tests/test_dashboard_auth.py::test_db_mode_api_401_without_any_bearer`
2. Run-scoped findings detail/patch/delete:
   - `tests/test_runs_routes.py::test_run_token_scopes_finding_detail_patch_and_delete`
3. Metasploit/MobSF dynamic API port discovery:
   - `tests/test_container_isolation.py::test_two_run_apis_do_not_collide`
4. Non-colliding multi-run listener/handler ports:
   - `tests/test_container_isolation.py::test_kali_run_uses_run_scoped_name_network_and_ephemeral_port`
   - `tests/test_container_isolation.py::test_two_run_apis_do_not_collide`
   - existing `tests/test_container_isolation.py::test_stop_only_current_run_containers`
5. Stop-run cleanup:
   - `tests/test_control_plane.py::test_stop_run_cleans_only_targeted_resources`
6. Control-plane start/stop/status behavior:
   - `tests/test_control_plane.py::test_start_control_plane_starts_services_and_returns_operator_token`
   - `tests/test_control_plane.py::test_control_plane_status_reflects_real_health`
   - `tests/test_control_plane.py::test_stop_control_plane_terminates_services`
   - existing `tests/test_smith_cli.py`
7. Request validation / malformed input / no side effects:
   - `tests/test_control_plane.py::test_create_run_rejects_non_dict_without_side_effects`
   - `tests/test_control_plane.py::test_create_run_rejects_oversized_scope_without_side_effects`
   - `tests/test_control_plane.py::test_api_create_run_malformed_body_400_without_side_effects`

Verification run
- Targeted changed tests: passed
- Full suite: `poetry run pytest -q` → passed (`2792 passed, 22 skipped`)

Noticed, not touched
- Existing pytest warnings remain, including FastAPI `on_event` deprecation and a few pre-existing runtime warnings in unrelated tests.

STATUS: DONE