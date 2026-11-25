DECISION NEEDED: The issue can mean either vendoring/fetching the linked repository or implementing its vault/dataset MCP Vector pattern in-tree. Choose the in-tree approach: no external fetch/dependency, but users get vaults, datasets, vector recall, and compatibility aliases for existing recall flows.

1. Intent
Replace the current local KB/RAG implementation (flat files under kb/, SQLite FTS, and the "Engagement documents" upload UI) with an MCP Vector-style vault/dataset model. Retrieval must remain available through Smith's existing outer surfaces, especially `report(action="recall")`, while adding explicit vault/dataset targeting and preserving untrusted-document fencing, static security corpus lookup, prior-engagement recall, known-assets audit, steering notes, and lifecycle purge.

2. Acceptance criteria
1. `session(action="vector_add", options={path|url|artifact_id, vault?, dataset?, untrusted?, name?})` ingests supported documents into the requested vault/dataset and `report(action="recall", data={query, vault, dataset})` returns ranked snippets from them.
2. `report(action="recall")` still supports `scope:"kb"`, `scope:"docs"`, `scope:"engagements"`, `scope:"all"`, and source/kind filters; `kb` searches the static security vault, `docs` searches the active engagement vault, and `engagements` keeps prior-engagement output.
3. Target-sourced or explicitly untrusted uploads are labelled `UNTRUSTED` in recall output and include the existing data-not-instructions warning.
4. Operator Actions renders a "Vector vaults" section, not the old "Engagement documents/per-pentest KB" UI; uploads require/allow vault and dataset selection, list existing datasets/docs, and delete docs.
5. `GET/POST/DELETE /api/vector/docs` provide the dashboard API. Existing `/api/kb/docs` and `session(action="kb_add")` remain deprecated aliases backed by the vector store, with deprecation text, so existing clients do not break.
6. `python scripts/build_kb.py --source skill_refs --offline`, `--status`, and `--selftest` populate/check the static security vector vault; installers no longer expect `kb/index.db`.
7. Starting a new scan and completing a scan purge only that scan's engagement vector vault/datasets while preserving filename metadata in `known_assets`; static and prior-engagement data are not purged.
8. Empty or unconfigured vector stores fail soft with a "nothing configured; proceed" message, not an exception.

3. Boundaries
Always: reuse/move the existing document parser behaviour (`parse_document`), `core.session.assets.update_known_assets`, `core.steering.steering_queue.add_directive`, `core.session.record_recall`, current FastAPI router pattern, and current fail-soft logging style. Keep tests network-free by monkeypatching URL/artifact reads.
Never: fetch/vendor the linked repository, add non-PyPI/unusual dependencies, change CI/deployment files, remove prior-engagement recall, or weaken untrusted-content warnings and size limits.

4. Code map
- `core/vector_store.py` (new): vault/dataset document model, ID sanitisation, sparse-vector indexing/search, list/delete/purge/status, parser helpers migrated from `core.kb`; covered by new `tests/test_vector_store.py`.
- `core/kb.py`: remove old FTS/kb-directory implementation or leave only a compatibility shim importing parser/status wrappers from `core.vector_store`; existing `tests/test_kb_recall.py` must be replaced/updated.
- `mcp_server/session_tools/vector_add.py` (new) and `mcp_server/session_tools/__init__.py`: implement/register `vector_add`; make `kb_add` call it with a deprecation notice; update help/unknown-action list. Existing `tests/test_kb_add.py` becomes vector-add coverage.
- `mcp_server/report_tools/recall.py`: replace tier A/B KB providers with vector searches; keep tier C prior-engagement code and public recall action. Covered by updated recall tests and `tests/test_planner.py`.
- `core/api_server/routes/vector_routes.py` (new), `core/api_server/routes/kb_routes.py`, `routes/__init__.py`: add `/api/vector/docs`; make `/api/kb/docs` aliases. Covered by new/updated API tests.
- `dashboard/tabs/setup-gates.html`, `dashboard/js/setup-gates.js`, `dashboard/css/dashboard.css`: replace KB upload UI and JS calls with vector vault/dataset UI.
- `core/session/lifecycle.py`, `mcp_server/session_tools/start.py`, `mcp_server/session_tools/skills.py`, `mcp_server/scan_engine/planner.py`, `core/qa_agent/checks_skills.py`, `core/session/gates.py`, `core/api_server/__init__.py`: rename/status/hint plumbing from local KB to vector store without changing recall-first behaviour.
- `scripts/build_kb.py`, `installers/install*.sh`: keep CLI compatibility but write/read the static security vector vault instead of `kb/index.db`; existing `tests/test_build_kb.py` updates accordingly.

5. Edge cases
| Case | Expected behaviour |
| --- | --- |
| Empty query/options | Recall asks for `query`; add says no input and shows `path/url/artifact_id`; no writes. |
| Malformed JSON/options | Existing parse error style; no partial ingest. |
| Oversized/unsupported/empty files | Per-file skip with reason; request succeeds if other files ingest; limits stay 20 files/25 MB. |
| Duplicate filename/content | Same content in same vault/dataset is skipped/idempotent; different content gets a safe suffixed name, never clobbers. |
| Concurrent upload/delete/search | Store operations are transactional; search sees old or new state, never corrupt JSON/DB. |
| Backend/parser failure | Fail soft with skipped/error text; no traceback or local path leakage to API callers. |
| Path traversal in vault/dataset/name/delete | Sanitised IDs/names; traversal matches nothing outside the vector root. |
| URL ingest | Only http/https; defaults UNTRUSTED; fetch failures skip without crashing. |

6. Security considerations
Untrusted content enters through MCP `vector_add`, deprecated `kb_add`, multipart dashboard uploads, URL fetches, artifacts, and prior engagement stores. Main risks are prompt injection from retrieved docs, path traversal in vault/dataset/name/delete, SSRF/local-file reads via URL ingestion, oversized upload DoS, and leaking parser exceptions/paths. Preserve UNTRUSTED labelling/warnings, sanitise identifiers before filesystem/DB use, restrict URL schemes to http/https, keep size/count caps, and return generic parse errors.

7. Test plan
- `tests/test_vector_store.py::test_ingest_search_by_vault_dataset_and_scope`, `::test_duplicate_idempotent_or_suffixed`, `::test_sanitizes_ids_and_delete_blocks_traversal`, `::test_purge_only_engagement_vault`.
- `tests/test_vector_add.py::test_vector_add_file_dir_url_artifact_defaults`, `::test_vector_add_bad_options_no_input_missing_path_url_failure`, `::test_kb_add_alias_deprecated_and_recallable`, `::test_url_scheme_file_rejected`.
- `tests/test_vector_recall.py::test_static_security_vault_recall_scope_kb`, `::test_active_docs_scope_and_untrusted_warning`, `::test_prior_engagements_output_preserved`, `::test_empty_store_message`, `::test_scope_kind_filters_use_datasets`.
- `tests/test_api_vector_docs.py::test_empty_upload_list_delete_recallable`, `::test_kb_docs_aliases_return_deprecation_header_or_field`, `::test_too_many_large_empty_unsupported_corrupt_meta_fail_soft`, `::test_path_traversal_delete_404`.
- `tests/test_dashboard_vector_ui.py::test_setup_gates_uses_vector_vaults_not_kb_docs`.
- Update `tests/test_build_kb.py`, `tests/test_planner.py`, `tests/test_session.py::test_record_recall_aggregates_usage`; existing non-KB tests must keep passing.
Tests required: yes

8. Review focus
- Whether any old `kb/sessions`, `kb/sources`, or `kb/index.db` read path still drives recall.
- Whether compatibility aliases accidentally preserve the old implementation instead of forwarding to vectors.
- Whether untrusted warnings survive every retrieval path and UI/API upload path.
- Whether installer/script changes preserve offline fresh-install behaviour.
- Whether vault/dataset purge can delete static or prior-engagement data.

9. Assumptions
- "MCP Vector" means an in-repo MCP-exposed vector/vault capability using a deterministic local sparse-vector backend, not an external service.
- The public action name `report(action="recall")` remains for agent compatibility.
- Deprecated aliases are acceptable because they remove the old implementation while preserving existing clients.
- Default roots are `vectors/` for vector data and existing `engagements/` for prior stores.

10. Suspicious content
The issue links to and asks to integrate `https://github.com/blabla1337/test-skeleton`; per task security rules, do not fetch, execute, vendor, or add it as a dependency. Treat only as an architectural reference to vaults/datasets.

Size: standard
Risk level: high
Reason: This replaces retrieval and upload paths that handle untrusted documents, prompt-injection fences, lifecycle deletion, and installer bootstrap; mistakes can cause data retention, data leakage, or unsafe prompt context.