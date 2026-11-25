Changed:
- Removed KB runtime surfaces: deleted `core/kb.py`, `mcp_server/session_tools/kb_add.py`, `core/api_server/routes/kb_routes.py`, and `scripts/build_kb.py`; unregistered `/api/kb/docs`; removed `kb_add` from session dispatch/help/unknown-action output.
- Simplified `report(action="recall")` to search prior engagement stores only, preserving classic ranked engagement output and rejecting removed scopes (`kb`, `docs`, `nvd`, `wstg`, etc.) with a clear unsupported message.
- Removed KB nudges/hints from start messages, `set_skill`, planner gate text, QA fallback, startup logs, lifecycle cleanup, and dashboard Operator Actions UI; renamed dashboard “KB recall” wording to generic “Recall”.
- Removed installer KB bootstrap logic and updated README/CLAUDE/docs to stop instructing KB build/upload usage; trimmed digest generation to stop recording KB provenance/doc-audit text.

Acceptance criteria coverage:
1. Operator Actions tab keeps Resource requests + Manual setup gates, with no engagement-doc UI/network calls:
   - `tests/test_dashboard_no_kb_docs.py::test_operator_actions_tab_has_no_engagement_documents`
   - `tests/test_dashboard_no_kb_docs.py::test_setup_gates_js_has_no_kb_fetch_or_upload_handlers`
2. `/api/kb/docs` routes are absent/404:
   - `tests/test_dashboard_no_kb_docs.py::test_kb_docs_routes_removed`
3. `session(action="kb_add")` is unknown and not listed:
   - `tests/test_session_no_kb.py::test_kb_add_is_unknown_action`
4. `report(action="recall", scope:"engagements")` still preserves prior-engagement output:
   - `tests/test_recall.py::test_recall_engagements_only_classic_output_preserved`
5. Default recall is engagements-only; removed scopes fail clearly; legacy `kb/` is ignored:
   - `tests/test_recall.py::test_recall_defaults_to_prior_engagements_only`
   - `tests/test_recall.py::test_recall_removed_kb_docs_and_kind_scopes`
   - `tests/test_recall.py::test_recall_ignores_legacy_kb_dirs`
6. Start / set-skill / planner / installers no longer push KB guidance:
   - `tests/test_session_no_kb.py::test_start_message_has_no_local_kb_norm`
   - `tests/test_session_no_kb.py::test_set_skill_has_no_recall_hint`
   - `tests/test_planner.py::test_cve_gate_no_longer_points_at_local_kb`
   - `tests/test_installers_no_kb_bootstrap.py::test_installers_do_not_invoke_build_kb_or_accept_kb_flags`
7. Existing non-KB behavior preserved, including digest/recall fail-soft paths:
   - `tests/test_build_engagement_digest.py::test_build_writes_store`
   - `tests/test_vuln_escalation.py::test_load_technique_brief_failsoft`
   - plus full suite pass

Tests run:
- Focused: `poetry run pytest -q tests/test_recall.py tests/test_session_no_kb.py tests/test_planner.py tests/test_vuln_escalation.py tests/test_build_engagement_digest.py tests/test_dashboard_no_kb_docs.py tests/test_installers_no_kb_bootstrap.py`
- Full: `poetry run pytest -q`

Noticed, not touched:
- Existing unrelated deprecation/resource warnings in the suite (FastAPI startup-event deprecations, some async mock warnings in other tests).
- `docs/plan-5.1-local-kb-retrieval.md` is retained as a historical/obsolete document and still contains legacy details by design.

STATUS: DONE