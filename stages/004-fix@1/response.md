Fixed the CI issues on the PR branch and verified with `poetry run pytest -q`.

Summary by failed check:

- SonarCloud `core/source_client.py`
  - Cause: `_normalize_items()` was too complex, and `search()` / `ingest()` used nested `async with`.
  - Change: split payload/item normalization into helpers and combined the nested context managers into single `async with` statements.

- SonarCloud `core/sources.py`
  - Cause: `_load_registry()` was too complex, had an unused local, and rebuilt a localhost URL with a hardcoded `http://` literal.
  - Change: broke registry parsing into small helpers, removed the unused variable, and normalized validated URLs from parsed components instead of hardcoding the protocol literal.

- SonarCloud `mcp_server/report_tools/recall.py`
  - Cause: `_do_recall()` was too complex.
  - Change: extracted request parsing plus engagement/source section builders so the main recall flow stays simple while preserving behavior.

- SonarCloud `mcp_server/session_tools/start.py`
  - Cause: `_start_response()` was too complex.
  - Change: moved optional start-message sections into focused helpers for ignored limits, benchmark/deep-pivot guidance, and anti-FP text.

- SonarCloud `tests/test_report_tools.py`
  - Cause: one composite assertion.
  - Change: split it into separate assertions.

- SonarCloud coverage gate
  - Cause: new Source/recall/start branches were under-tested.
  - Change: added focused tests for empty/invalid source bindings, no-hit/error paths, registry edge cases, recall guidance/fail-soft cases, and start-message/resume/refusal helpers.

Validation:
- `poetry run pytest -q` ✅ (`2763 passed, 22 skipped`)

I did not `git push` because this environment’s instructions forbid push/commit; the branch is updated locally and ready for the next automation step to push.