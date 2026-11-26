1. Intent
Add optional per-engagement Source memory binding to agent-smith. A scan can select a registered local Source instance; smith can consult it, `recall` can include it, medium/full skill selection gets one bounded methodology push, and findings/completion are mechanically written back as stable notes. All behavior is additive, bounded, local-only, and best-effort so an unconfigured or down Source never blocks a scan.

2. Acceptance criteria
1. With `SOURCE_REGISTRY` pointing at a registry containing `prod-web: http://127.0.0.1:<port>`, `session(action='start', options={target:'http://t', source:'prod-web'})` returns a start message naming `Source: prod-web`; `session.json`, `session(action='status')`, and `session(action='recovery')` expose `source_instance:{name:'prod-web', url:'http://127.0.0.1:<port>'}`.
2. Unknown, blank, malformed, or non-loopback Source entries never block start; the response says no Source was bound and lists available valid names.
3. `session(action='use_source', options={source:'name'})` rebinds the running engagement; `source:''` clears it. Both persist and are reflected by status/recovery.
4. `report(action='consult', data={query:'x', k:2})` returns char-capped snippets from only the bound Source. With no binding or an unreachable Source it returns a clear no-source/unreachable message, not an exception.
5. `report(action='recall', data={query:'x'})` still searches prior `engagements/*`; when Source is bound it also includes a labelled Source section. `scope:'engagements'` excludes Source; `scope:'source'` searches only Source. Legacy scopes (`kb`, `docs`, `nvd`, `wstg`, etc.) remain rejected.
6. `session(action='set_skill', options={skill:'web-exploit', reason:'...'})` appends one bounded `Methodology from <source>` block only for `model_profile` `full` or `medium`; `small` produces no Source request/block.
7. A successful `report(action='finding', ...)` posts one `POST /ingest` note with id `smith-<session_id>-finding-<finding_id>` and does not change the normal finding response text except for existing matrix/gate notes.
8. When `session(action='complete')` reaches its existing human-signoff-held success path, and when `core.session.complete()` makes a terminal transition, Source receives/upserts `smith-<session_id>-digest` summarising target, scope, findings, endpoints, technologies, and auth assets. Blocked completion attempts do not ingest.
9. Existing start/resume guards, dashboard token text, no-Source recall, finding dedup/trace validation, and `scripts/build_engagement_digest.py` CLI output keep working.

3. Boundaries
Always use `core.paths.REPO_ROOT`, `core.logger.note`, `core.session._flush/load_from_disk`, existing `_background_tasks` for MCP fire-and-forget, `aiohttp` with short timeouts, and the current `scripts/build_engagement_digest.py` shaping style. Use stdlib parsing for a small YAML subset; add no dependency.
Never implement the Source server, contact non-loopback URLs, change dashboard auth/completion gates, weaken legacy recall-scope rejection, or log/return raw ingest note bodies/secrets.

4. Code map
- `core/sources.py` (new): `SOURCE_REGISTRY_FILE`, `list_sources(registry_path=None)`, `resolve_source(name, registry_path=None)`; parse `sources.yaml`/`SOURCE_REGISTRY`, accept localhost HTTP only, return available names/errors. New tests.
- `sources.yaml` (new): commented empty sample (`sources: {}`), no real targets.
- `core/source_client.py` (new): `async search(query,k=3,mode=None,path=None,tags=None)`, `async ingest(notes)`, `ingest_best_effort(notes)`; read `scan_session.get()['source_instance']`, normalize Source JSON, cap output, fail-soft. New tests.
- `core/session/lifecycle.py:start, complete`: accept/persist `source_instance`; terminal complete schedules digest ingest. Covered by `tests/test_session.py`.
- `mcp_server/session_tools/start.py:_do_start,_start_response`: resolve `opts['source']`, pass to `scan_session.start`, show Source bound/warning.
- `mcp_server/session_tools/__init__.py`: document `source`, `use_source`; dispatch async set-skill wrapper and sync `use_source`; update unknown-action text.
- `mcp_server/session_tools/skills.py`: add async wrapper that calls existing `_do_set_skill` then appends profile-gated Source methodology; keep direct `_do_set_skill` behavior for existing tests.
- `mcp_server/session_tools/status.py`, `recovery_build.py`: include `source_instance` when bound.
- `mcp_server/report_tools/recall.py`: add Source tier/default merge and `scope:'source'`, preserving legacy rejection.
- `mcp_server/report_tools/__init__.py`: document/dispatch `consult`.
- `mcp_server/report_tools/findings.py`: after persisted finding, schedule per-finding Source ingest best-effort.
- `scripts/build_engagement_digest.py`: add pure `project_notes(session, findings, known_assets=None, coverage=None, kind='digest'|'finding', finding=None) -> list[dict]`; keep `build()` output unchanged.
- `CLAUDE.md`, `.env.example` (create if absent): document registry, `source`, `consult`, recall scopes, local/best-effort write-back.

5. Edge cases
| Case | Expected behaviour |
|---|---|
| no registry/blank source | scan starts unbound; consult says no Source bound |
| malformed registry/missing url | invalid entries ignored; available list shows valid entries only |
| URL not loopback HTTP | rejected; no outbound request |
| Source down/timeout/bad JSON | original action succeeds or returns concise unavailable; log note only |
| empty/non-token query | asks for a query or says no searchable terms |
| oversized snippets/notes | snippets/methodology are char-capped; notes are compact |
| duplicate finding/complete write-back | same stable id upserts; no duplicate expected |
| background ingest failure | exception consumed/logged; MCP action does not fail |

6. Security considerations
New trust boundary: operator-configured local HTTP Source. Validate registry URLs to loopback `http://localhost`, `127.0.0.1`, or `[::1]` to avoid SSRF/exfiltration. Source snippets are untrusted and may contain prompt injection; consult/recall/methodology output must label them as data, not instructions, and cap/fence snippets. Ingest may include credentials/tokens already in session state; never print them in MCP responses or logs. No shell, SQL, template rendering, or auth changes are required.

7. Test plan
- `tests/test_sources.py`: `test_resolve_source_known_loopback`, `test_resolve_source_unknown_lists_available`, `test_resolve_source_rejects_non_loopback_and_malformed`, `test_source_registry_env_override`.
- `tests/test_source_client.py`: `test_consult_search_success_caps_and_labels`, `test_consult_no_bound_source`, `test_source_timeout_bad_json_fail_soft`, `test_ingest_best_effort_posts_notes_without_logging_secret`.
- `tests/test_session_source.py`: `test_start_binds_source_and_status_recovery_show_it`, `test_start_unknown_source_non_blocking`, `test_use_source_rebinds_and_clears`, `test_set_skill_source_methodology_full_medium_not_small`.
- `tests/test_recall.py`: add `test_recall_merges_bound_source_with_engagements`, `test_recall_source_scope_only`; keep legacy-scope tests passing.
- `tests/test_report_tools.py`: add `test_report_consult_dispatch`, `test_finding_schedules_source_writeback_after_persist_and_not_on_duplicate`.
- `tests/test_build_engagement_digest.py`: add `test_project_notes_finding_stable_id_and_shape`, `test_project_notes_digest_contains_scope_assets_findings`, `test_build_cli_unchanged`.
- `tests/test_session.py`: add `test_start_stores_source_instance`, `test_terminal_complete_schedules_digest_writeback`.
Existing `test_session_no_kb.py`, `test_small_model_profile.py`, `test_recall.py`, `test_report_tools.py`, and `test_build_engagement_digest.py` must still pass.
Tests required: yes

8. Review focus
1. Sync/async boundaries around set_skill, finding write-back, and terminal completion may block or drop tasks.
2. Registry parser may be too narrow for real operator YAML.
3. Digest notes may persist more secret material than intended.
4. Source snippets may still steer the model despite data-only labels/fencing.
5. Ingest from both MCP-complete and terminal-complete may cause unexpected upsert churn.

9. Assumptions
- Implement only agent-smith; Source HTTP server work belongs to the companion repo and is simulated by tests here.
- Supported registry YAML subset: optional top-level `sources:`, entries as `name: {url: ...}` or indented `url:`.
- Loopback HTTP only is mandatory even if an operator wants remote Source.
- Raw credential/token values already in `known_assets` may be written to the bound Source vault but never surfaced in tool output/logs.

10. Suspicious content
none

Size: standard
Risk level: medium
Reason: touches session state, outbound local HTTP, prompt-visible memory snippets, and persistence of sensitive engagement data; failures could leak secrets to the wrong local Source or steer scans with injected memory.