Implemented per-engagement Source binding, consult/recall integration, profile-gated methodology pull, and best-effort finding/digest write-back.

What changed
- Added Source registry/client:
  - `core/sources.py`
  - `core/source_client.py`
  - `sources.yaml`
- Threaded `source_instance` through session start/status/recovery/use_source:
  - `core/session/lifecycle.py`
  - `mcp_server/session_tools/start.py`
  - `mcp_server/session_tools/__init__.py`
  - `mcp_server/session_tools/status.py`
  - `mcp_server/session_tools/recovery_build.py`
  - `mcp_server/session_tools/skills.py`
  - `mcp_server/session_tools/complete.py`
- Added explicit `report(action='consult')` and Source-aware `recall`:
  - `mcp_server/report_tools/__init__.py`
  - `mcp_server/report_tools/recall.py`
- Added best-effort Source write-back:
  - per finding in `mcp_server/report_tools/findings.py`
  - on completion hold / terminal complete in `mcp_server/session_tools/complete.py` and `core/session/lifecycle.py`
- Factored reusable note projection:
  - `scripts/build_engagement_digest.py`
- Documented Source usage:
  - `CLAUDE.md`
  - `.env.example`

Test coverage by acceptance criterion
1. Start binds Source and exposes it:
   - `tests/test_session_source.py::test_start_binds_source_and_status_recovery_show_it`
   - `tests/test_session.py::test_start_stores_source_instance`
2. Unknown/blank/malformed/non-loopback never block start:
   - `tests/test_sources.py::*`
   - `tests/test_session_source.py::test_start_unknown_source_non_blocking`
3. `use_source` rebinds/clears:
   - `tests/test_session_source.py::test_use_source_rebinds_and_clears`
4. `report(action='consult')` works and fail-softs:
   - `tests/test_source_client.py::*`
   - `tests/test_report_tools.py::test_report_consult_dispatch`
5. `recall` merges engagements + Source / supports `scope:'source'`:
   - `tests/test_recall.py::test_recall_merges_bound_source_with_engagements`
   - `tests/test_recall.py::test_recall_source_scope_only`
   - existing legacy-scope recall tests still pass
6. `set_skill` Source methodology only on medium/full:
   - `tests/test_session_source.py::test_set_skill_source_methodology_full_medium_not_small`
   - existing `tests/test_session_no_kb.py::test_set_skill_has_no_recall_hint` still passes for direct `_do_set_skill`
7. Finding write-back posts stable note without changing finding response flow:
   - `tests/test_report_tools.py::test_finding_schedules_source_writeback_after_persist_and_not_on_duplicate`
   - existing finding response tests still pass
8. Completion write-back on held-success path and terminal transition:
   - `tests/test_session_tools_helpers.py::TestDoComplete::test_no_blockers_schedule_source_digest_writeback`
   - `tests/test_session.py::test_terminal_complete_schedules_digest_writeback`
9. No regressions for existing behavior / CLI output unchanged:
   - `tests/test_build_engagement_digest.py::test_build_cli_unchanged`
   - full suite pass: `poetry run pytest -q`

Validation run
- Focused source/session/report/digest tests: passed
- Full suite: `poetry run pytest -q` → passed

Noticed, not touched
- Existing test warnings remain (FastAPI/Starlette deprecations and some pre-existing async mock warnings).

STATUS: DONE