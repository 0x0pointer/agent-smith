Summary:
- Root cause: `/api/session` loaded a run-scoped DB session, but its triage self-heal path then switched back to global `findings.json`, global `session.json`, and global steering helpers. Under a run token, that could leak/mutate unrelated state and even drop the run session response.
- Fix:
  - Kept `/api/session` triage self-heal fully run-scoped when `request.state.run_id` is set: findings, session updates, progress counters, and steering cancellation all use the authenticated run’s DB snapshots.
  - Preserved legacy single-run behavior for requests without `run_id`.
  - Fixed wishlist route direct-call compatibility by safely treating missing `Request.state` as global/single-run mode, while still using run-scoped wishlist/steering for authenticated dashboard requests.
- Regression coverage:
  - Added `test_run_token_session_triage_self_heal_uses_run_snapshots_only`, which fails without the `/api/session` fix and passes with it.
  - Verified red/green:
    - Before fix: new regression failed with `KeyError: 'target'`.
    - With fix: new regression passed.
    - Temporarily removed fix: regression failed again with `KeyError: 'target'`.
    - Restored fix: regression passed.

Verification run after final edit:
- `poetry run pytest -q tests/test_wishlist_routes.py` → `4 passed`
- `poetry run pytest -q tests/test_runs_routes.py tests/test_wishlist_routes.py tests/test_dashboard_auth.py tests/test_container_isolation.py tests/test_control_plane.py tests/test_smith_cli.py` → `47 passed`
- Required full suite: `poetry run pytest -q` → `2804 passed, 22 skipped, 11 warnings`