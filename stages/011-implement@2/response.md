Changed:
- Fixed `/api/kb/docs` deprecation wrapping to rebuild JSON responses without reusing the stale `Content-Length`, while still adding the deprecation header/field.
- Added a “Vector vaults” summary/list in the Operator Actions UI that renders returned vaults/datasets with doc counts and lets operators select a vault/dataset to refresh the document list.
- Added regression coverage for both reviewer findings.

Test coverage:
- Todo 1 (`/api/kb/docs` malformed alias response): covered by `tests/test_api_vector_docs.py::test_kb_docs_aliases_return_deprecation_header_or_field`
- Todo 2 (dashboard must list existing vaults/datasets): covered by `tests/test_dashboard_vector_ui.py::test_setup_gates_uses_vector_vaults_not_kb_docs`

Tests run:
- `poetry run pytest -q tests/test_api_vector_docs.py tests/test_dashboard_vector_ui.py`
- `poetry run pytest -q`

Noticed, not touched:
- Existing full-suite warnings remain (FastAPI/TestClient deprecations and a few pre-existing runtime warnings in unrelated tests).

STATUS: DONE