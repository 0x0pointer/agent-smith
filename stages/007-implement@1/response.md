Implemented the vector-vault migration end to end.

What changed
- Added `core/vector_store.py` for vault/dataset storage, sanitised IDs, duplicate handling, search, delete, and engagement-vault purge.
- Replaced the old KB core with a thin compatibility shim in `core/kb.py`.
- Added `session(action="vector_add")` in `mcp_server/session_tools/vector_add.py`; kept `kb_add` as a deprecated alias.
- Reworked `report(action="recall")` in `mcp_server/report_tools/recall.py` to search:
  - static security vault for `scope:"kb"`
  - active engagement vault for `scope:"docs"`
  - existing prior-engagement stores for `scope:"engagements"`
  - direct `vault`/`dataset` targeting
- Added `/api/vector/docs` in `core/api_server/routes/vector_routes.py`; kept `/api/kb/docs` as deprecated aliases.
- Updated lifecycle purge logic, planner/QA vector lookups, dashboard Operator Actions UI, and KB builder/install bootstrap checks for the new vector store.

Acceptance criteria coverage
1. `vector_add` ingest + recall by vault/dataset:
   - `tests/test_vector_add.py::test_vector_add_file_dir_url_artifact_defaults`
   - `tests/test_vector_recall.py::test_static_security_vault_recall_scope_kb`
2. Legacy recall scopes and filters preserved:
   - `tests/test_vector_recall.py::test_static_security_vault_recall_scope_kb`
   - `tests/test_vector_recall.py::test_prior_engagements_output_preserved`
   - `tests/test_vector_recall.py::test_scope_kind_filters_use_datasets`
3. UNTRUSTED labelling/warning preserved:
   - `tests/test_vector_recall.py::test_active_docs_scope_and_untrusted_warning`
   - `tests/test_vector_add.py::test_vector_add_file_dir_url_artifact_defaults`
4. Dashboard shows vector vault UI, not old KB UI:
   - `tests/test_dashboard_vector_ui.py::test_setup_gates_uses_vector_vaults_not_kb_docs`
5. `/api/vector/docs` added and `/api/kb/docs` aliased with deprecation:
   - `tests/test_api_vector_docs.py::test_empty_upload_list_delete_recallable`
   - `tests/test_api_vector_docs.py::test_kb_docs_aliases_return_deprecation_header_or_field`
   - `tests/test_vector_add.py::test_kb_add_alias_deprecated_and_recallable`
6. `scripts/build_kb.py` populates/checks static vector vault:
   - `tests/test_build_kb.py::test_offline_build_index_query_status_selftest`
   - `tests/test_build_kb.py::test_build_offline_missing_cache_skips`
   - `tests/test_build_kb.py::test_main_status`
   - `tests/test_build_kb.py::test_main_selftest_no_index`
7. Purge only engagement vaults, preserve static/prior data:
   - `tests/test_vector_store.py::test_purge_only_engagement_vault`
8. Empty/unconfigured stores fail soft:
   - `tests/test_vector_recall.py::test_empty_store_message`

Additional updated coverage
- Core vector-store behavior:
  - `tests/test_vector_store.py::test_ingest_search_by_vault_dataset_and_scope`
  - `tests/test_vector_store.py::test_duplicate_idempotent_or_suffixed`
  - `tests/test_vector_store.py::test_sanitizes_ids_and_delete_blocks_traversal`
- Planner integration:
  - updated `tests/test_planner.py`
- Existing recall usage aggregation kept passing:
  - `tests/test_session.py::test_record_recall_aggregates_usage`

Validation run
- Targeted updated/new tests passed.
- Full suite passed: `poetry run pytest -q`

Noticed, not touched
- Existing suite emits a few unrelated deprecation/runtime warnings (FastAPI `on_event`, some async mock warnings).

STATUS: DONE