Implemented the reviewer-requested fix pass only.

What I changed
- Hardened `core/source_client.py`:
  - added `_coerce_k()` so malformed `k` values fail soft and clamp to `1.._MAX_RESULTS` instead of raising
  - changed `render_search()` to render each Source snippet inside a fenced ` ```text ` data block
  - neutralized snippet backticks/fence delimiters before rendering so stored prompt-injection text stays inert data
- Added/updated regression tests for the exact rejected cases:
  - `tests/test_source_client.py`
  - `tests/test_recall.py`
  - `tests/test_session_source.py`

Coverage by todo item
1. Prompt-injection hardening for Source snippets
- `tests/test_source_client.py::test_consult_render_fences_untrusted_snippet_and_neutralizes_backticks`
- `tests/test_recall.py::test_recall_source_snippets_stay_fenced_as_data`
- `tests/test_session_source.py::test_set_skill_source_methodology_full_medium_not_small`

2. Malformed `consult`/search `k` must not raise
- `tests/test_source_client.py::test_search_coerces_bad_k_without_raising`

What I ran
- `poetry run pytest -q tests/test_source_client.py tests/test_recall.py tests/test_session_source.py`
- `poetry run pytest -q`

Results seen
- Targeted tests: passed
- Full suite: `2749 passed, 22 skipped`

Noticed, not touched
- Existing test-suite warnings about FastAPI deprecations and a few coroutine/runtime warnings remain unchanged.

STATUS: DONE