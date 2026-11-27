Verdict: fail

Blocking findings: core/api_server/routes/scan_state_routes.py:216 — run-token phase steering still mutates process-global state.

# Security review

## Summary
- Findings: 1 blocking, 0 non-blocking.
- Re-review status: the four prior blockers were mostly addressed: scoped reads no longer fall back to global findings for run tokens, QA/steering/wishlist/triage got run-aware paths, the three tool runners rediscover dynamic ports after restart, operator-token minting now waits for DB availability/fails closed, and the inert orchestrator marker was removed in favor of health-checking the real `/api/runs` surface.
- Remaining issue: phase-control steering is still process-global in a run-token request, so an existing dashboard action is not scoped to the selected run.

## Changed files reviewed

| File | Risk | Blast radius |
|---|---:|---|
| `control_plane/orchestrator.py` | HIGH | CLI and `/api/runs` create/list/stop/status paths; 5 public control-plane functions. |
| `core/api_server/routes/findings_routes.py` | HIGH | Findings/session/cost/coverage APIs; dashboard tabs for every authenticated run. |
| `core/api_server/routes/misc_routes.py` | HIGH | QA and steering read APIs; dashboard state disclosure boundary. |
| `core/api_server/routes/scan_state_routes.py` | HIGH | `/api/steer`, phase controls, intervention/stop state actions; public dashboard control surface. |
| `core/api_server/routes/triage_routes.py` | HIGH | Complete/triage/cancel/force-stop dashboard actions. |
| `core/api_server/routes/wishlist_routes.py` | HIGH | Wishlist read/fulfill/dismiss actions and steering wakeups. |
| `core/dashboard_auth.py` | HIGH | Bearer token mint/verification for run and operator tokens. |
| `core/qa_agent/daemon.py` | MEDIUM | One QA writer loop; now persists QA snapshots to DB. |
| `core/steering.py` | HIGH | Central directive queue; >20 direct callers across QA, MCP tools, routes, and envelope injection. |
| `core/wishlist.py` | MEDIUM | Wishlist queue; direct callers in dashboard routes, MCP session tools, pivot/spider helpers. |
| `tools/kali_runner.py` | HIGH | Kali command API container lifecycle and dynamic port URL. |
| `tools/metasploit_runner.py` | HIGH | Metasploit command API container lifecycle and dynamic port URL. |
| `tools/mobsf_runner.py` | HIGH | MobSF API container lifecycle and dynamic port URL. |
| `tests/test_container_isolation.py` | LOW | Regression coverage for container naming/ports. |
| `tests/test_control_plane.py` | LOW | Regression coverage for control-plane health/token behavior. |
| `tests/test_dashboard_auth.py` | LOW | Regression coverage for token persistence/fail-closed behavior. |
| `tests/test_runs_routes.py` | LOW | Regression coverage for run token scoping on selected tabs/actions. |

## Findings

### Blocking — run-token phase steering still mutates process-global state

- **File/line:** `core/api_server/routes/scan_state_routes.py:216`
- **Category:** authorization / correctness
- **Attacker model:** Holder of a valid run A dashboard token. This is an authenticated but run-scoped user interacting through the documented dashboard/API route.
- **Reachable path checked:** The auth middleware sets `request.state.run_id` for the bearer token. `POST /api/steer` with `{"message":"advance to phase B"}` enters the phase special case at lines 219-226 before the new `run_id` is used for normal steering directives. That branch calls `scan_session.load_from_disk(force=True)` and `scan_session.advance_phase(target)`, which operate on the process-global session, not the authenticated run's DB snapshot. The sibling `/api/phase/advance` endpoint has the same global pattern.
- **Impact:** Selecting run A does not scope phase-control actions to run A. The request either fails against an unrelated empty/global session or advances whatever process-global/single-run session is loaded, while run A's persisted DB session remains unchanged. This violates the AC5 requirement that selecting a run scopes existing dashboard tabs/actions to that run, and keeps a run token able to affect state outside its run boundary.
- **Required fix:** For DB-backed run-token requests, load the authenticated run's session snapshot, apply the forward-only phase transition to that document, and save it back with `repo.upsert_run()`/`repo.save_snapshot(run_id, "session", ...)`; do not touch `core.session` globals. Apply the same run-scoped behavior or an explicit 403/409 to `/api/phase`, `/api/phase/advance`, and typed phase steering in `/api/steer`. Add a regression test with run A and run B snapshots proving a run A token advances only run A and does not create or mutate repo-root/global session state.

## Test coverage gaps
- Added tests cover run-scoped normal `/api/steer` directives, wishlist, QA, steering, triage, and findings operations, but not typed phase steering or `/api/phase/advance` under run tokens.
- I did not run the whole test suite per instruction. I used targeted source/history/caller/test inspection only.

## Not covered / limits
- Re-review was limited to regions in `/tmp/fabro/since-review.diff`; I did not re-audit unchanged portions of the large original change except where needed to trace callers/guards.
- I did not manually exercise Docker, Postgres, or the dashboard browser UI.
- I did not review dependency lockfile content beyond noting it was outside the re-review delta.