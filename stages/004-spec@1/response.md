BEHAVIOUR REMOVED: the local/static KB, engagement-document upload/ingestion, KB/docs recall scopes, automatic recall-first nudges, and installer KB bootstrap are removed because issue #297 asks to roll back the current KB RAG approach; prior-engagement recall is retained because it predates and is distinct from KB RAG.

1. Intent
Remove the KB RAG feature from runtime code and the dashboard: no static KB builder/index, no `session(action="kb_add")`, no `/api/kb/docs`, no Operator Actions upload UI, no KB/docs recall tiers, and no automatic prompts telling Smith to recall local KB content. Keep `report(action="recall")` as a prior-engagement-store search over `engagements/*` only, preserving resume/recall behaviour that is not file-upload RAG.

2. Acceptance criteria
1. The Operator Actions tab still renders Resource requests and Manual setup gates, but contains no “Engagement documents”, file picker, upload/remove controls, or network calls to `/api/kb/docs`.
2. `GET`, `POST`, and `DELETE /api/kb/docs...` are not registered and return 404 from the dashboard API.
3. `session(action="kb_add", ...)` is no longer a supported action: it returns the normal unknown-action message, and session help/unknown-action text does not list `kb_add`.
4. `report(action="recall", data={"query":"sudo", "scope":"engagements"})` still searches prior engagement stores and returns the existing ranked prior-observations output.
5. `report(action="recall", data={"query":"sudo"})` defaults to prior engagement stores only. `scope:"kb"`, `scope:"docs"`, and former kind scopes such as `wstg`/`nvd` return a clear “removed/unsupported” message and never read `kb/`.
6. `session(action="start")`, `session(action="set_skill")`, planner recommendations, QA stuck-escalation briefs, startup logs, installers, README/CLAUDE/docs do not tell users to build a KB, upload docs, or “recall before web” from KB/docs.
7. Existing non-KB behaviours keep working: dashboard wishlist/setup-gates polling, prior-engagement digest generation, scan start/complete/clear-all, skill logging, and recall usage metrics (if retained) as generic recall metrics.

3. Boundaries
Always: use existing FastAPI router registration in `core/api_server/routes/__init__.py`, existing `report(action="recall")` dispatch in `mcp_server/report_tools/__init__.py`, existing prior-store helpers in `mcp_server/report_tools/recall.py`, and existing dashboard tab structure in `dashboard/tabs/setup-gates.html`/`dashboard/js/setup-gates.js`.
Never: do not remove prior-engagement digest/recall, wishlist, setup gates, skill gates, dashboard auth, or CI/deployment workflows. Do not add replacement RAG/vector/embedding dependencies.

4. Code map
- Delete: `core/kb.py`, `mcp_server/session_tools/kb_add.py`, `core/api_server/routes/kb_routes.py`, `scripts/build_kb.py`; remove their tests (`tests/test_kb_core.py`, `tests/test_kb_add.py`, `tests/test_api_kb_docs.py`, `tests/test_build_kb.py`) or replace with removal assertions.
- `core/api_server/routes/__init__.py`: stop importing `kb_routes`, so `/api/kb/docs` is absent.
- `mcp_server/session_tools/__init__.py`: remove `kb_add` help, async dispatch, and unknown-action listing.
- `mcp_server/report_tools/recall.py`: remove `core.kb` import and Tier A/B providers; `_do_recall(data)` searches only prior engagement stores for default/all/engagements/path scopes and rejects removed scopes.
- `mcp_server/session_tools/start.py`, `mcp_server/session_tools/skills.py`, `mcp_server/scan_engine/planner.py`, `core/qa_agent/checks_skills.py`, `core/api_server/__init__.py`: remove KB presence checks, recall-first hints, CVE/tech KB suggestions, QA KB fallback, and startup KB nudge.
- `core/session/lifecycle.py`, `core/api_server/routes/scan_state_routes.py`, `scripts/build_engagement_digest.py`: remove KB-doc purge/provenance/name-audit logic while preserving normal session cleanup and digest fields.
- `dashboard/tabs/setup-gates.html`, `dashboard/js/setup-gates.js`, `dashboard/css/dashboard.css`: remove engagement-doc markup, functions, polling call, and file-picker CSS only.
- `dashboard/js/skills.js`, `core/session/gates.py`: rename “KB recall” wording to generic “recall” if the metric remains.
- `installers/install.sh`, `installers/install_codex.sh`, `installers/install_opencode.sh`, `README.md`, `CLAUDE.md`, `docs/dashboard-api.md`, `docs/plan-5.1-local-kb-retrieval.md`, `.gitignore`: remove or mark obsolete KB feature docs/bootstrap references; keep `kb/` ignored only as legacy local data if desired.

5. Edge cases
| Input/state | Expected behaviour |
| --- | --- |
| no `engagements/*/resume.json` | recall says no prior engagement stores found; no KB suggestion |
| missing/blank recall query | help mentions prior engagement recall only |
| `scope:"kb"`, `scope:"docs"`, `scope:"nvd"` | deterministic unsupported/removed message; no filesystem read under `kb/` |
| legacy `kb/` directory/index exists | ignored by all runtime paths; no startup/log/dashboard prompt |
| oversized/malformed upload attempt | `/api/kb/docs` is 404; no parsing or file write |
| duplicate/concurrent dashboard polling | setup-gates/wishlist continue; no extra KB fetch races |
| corrupt prior engagement JSON | existing fail-soft recall behaviour remains |

6. Security considerations
This removes trust boundaries: multipart upload parsing, URL fetching in `kb_add` (SSRF risk), target-sourced prompt-injection fencing, file deletion by doc name, and static KB network fetchers. Negative tests must prove no hidden upload/API/action remains. Remaining recall reads local prior-engagement files only; preserve existing path scoping and fail-soft JSON handling, and do not introduce shell, SQL, template, prompt, or path sinks.

7. Test plan
- Add/update `tests/test_recall.py::test_recall_engagements_only_classic_output_preserved`, `test_recall_defaults_to_prior_engagements_only`, `test_recall_removed_kb_docs_and_kind_scopes`, `test_recall_missing_query_help_mentions_only_engagements`, `test_recall_ignores_legacy_kb_dirs`.
- Add `tests/test_dashboard_no_kb_docs.py::test_kb_docs_routes_removed`, `test_operator_actions_tab_has_no_engagement_documents`, `test_setup_gates_js_has_no_kb_fetch_or_upload_handlers`.
- Add/update `tests/test_session_no_kb.py::test_kb_add_is_unknown_action`, `test_start_message_has_no_local_kb_norm`, `test_set_skill_has_no_recall_hint`.
- Update `tests/test_planner.py::test_cve_gate_no_longer_points_at_local_kb` and remove KB hint tests.
- Update `tests/test_vuln_escalation.py` to remove `_kb_recall_brief` fallback expectations and assert missing refs fail soft.
- Add `tests/test_installers_no_kb_bootstrap.py::test_installers_do_not_invoke_build_kb_or_accept_kb_flags`.
- Existing tests for session lifecycle, dashboard auth, wishlist routes, setup gates, planner, and prior-engagement digest must keep passing.
Tests required: yes

8. Review focus
1. A hidden KB entry point remains (`/api/kb/docs`, `kb_add`, installer flag, dashboard JS fetch, or prompt docs).
2. Prior-engagement recall was accidentally removed or its output changed incompatibly.
3. Legacy `kb/` data is still read, logged, or copied into digests.
4. Dashboard Operator Actions polling/rendering regressed while removing upload code.
5. Documentation still instructs agents/operators to use removed KB/docs scopes.

9. Assumptions
- “KB RAG” means static KB plus engagement-document upload/recall tiers, not prior-engagement recall over generated engagement stores.
- Removed scopes should fail with a clear message rather than silently broadening to engagements.
- `kb/` may remain gitignored as legacy local data protection, but no runtime code should depend on it.

10. Suspicious content
none

Size: standard
Risk level: medium
Reason: the change removes user-visible API/UI/actions and security-sensitive upload/URL-fetch code; mistakes could leave a hidden ingestion surface or break prior-engagement recall.