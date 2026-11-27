Summary:
- Root cause: persisted runs listed by `/api/runs` had no recoverable plaintext run token, and `dashboard/js/sessions.js` refused to select a run unless `smith_run_tokens` already contained one. Fresh browsers/restarted dashboards therefore kept using the operator token with no `run_id`, causing existing data tabs to fall back to global JSON instead of run-scoped DB snapshots.
- Fix: added an operator-only `POST /api/runs/{run_id}/token` endpoint that mints a fresh per-run token for an existing run, and updated the sessions UI to call that endpoint when no cached run token exists instead of disabling the Select button.
- Guard coverage: added regression tests proving an operator can mint a token for persisted run A and that `/api/findings`, `/api/session`, `/api/coverage`, and `/api/cost` scope to run A, while a run token cannot mint tokens for another run and missing runs return 404. Added UI coverage proving persisted runs remain selectable without cached localStorage tokens.

Verification run in this session:
- Red check with implementation temporarily removed: focused regression command failed with 2 failures as expected.
- Green focused check after restoring fix: `poetry run pytest -q tests/test_runs_routes.py::test_operator_can_mint_persisted_run_token_that_scopes_existing_tabs tests/test_dashboard_runs_ui.py::test_sessions_tab_can_select_persisted_runs_without_cached_localstorage_tokens` → `2 passed`.
- Affected suite: `poetry run pytest -q tests/test_runs_routes.py tests/test_dashboard_runs_ui.py tests/test_dashboard_auth.py` → `25 passed`.
- Required full suite after final edit: `poetry run pytest -q` → `2810 passed, 22 skipped`.