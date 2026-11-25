Verdict: fail

Blocking findings: stale `Content-Length` on deprecated `/api/kb/docs` alias responses; dashboard Vector vaults UI does not list existing vaults/datasets.

# Security / Correctness Review

## Summary
- Findings: 2 blocking, 0 non-blocking.
- Acceptance criteria: 6/8 met from the diff. Criteria 4 (dashboard must list existing vector vaults/datasets/docs) and 5 (deprecated `/api/kb/docs` aliases must remain working) are not fully met.
- Security-sensitive paths reviewed: untrusted document ingestion, vector storage path sanitisation, recall warnings, lifecycle purge, dashboard/API aliases, and static KB bootstrap.

## Changed-file risk / blast radius

| File | Risk | Blast radius |
| --- | --- | --- |
| `core/vector_store.py` | HIGH | New storage/search/delete core; called by API, MCP actions, recall, build script, planner, QA, lifecycle. |
| `mcp_server/session_tools/vector_add.py` | HIGH | New MCP ingestion action; reachable through `session(vector_add)` and `kb_add` alias. |
| `core/api_server/routes/vector_routes.py` | HIGH | New dashboard upload/list/delete API for untrusted files. |
| `mcp_server/report_tools/recall.py` | HIGH | Main retrieval output and prompt-injection fence; called by public `report(recall)`. |
| `core/api_server/routes/kb_routes.py` | HIGH | Deprecated API compatibility aliases used by existing clients. |
| `core/session/lifecycle.py` | HIGH | Start/complete purge path for engagement docs. |
| `core/api_server/routes/scan_state_routes.py` | HIGH | Dashboard Clear All purge path. |
| `scripts/build_kb.py` | MEDIUM | Installer/static corpus bootstrap; network/subprocess use, but operator-run. |
| `core/kb.py` | MEDIUM | Compatibility shim; imports parser/status/vector helpers. |
| `mcp_server/session_tools/__init__.py` | MEDIUM | Public action registration/help. |
| `mcp_server/scan_engine/planner.py` | MEDIUM | Recall hint generation; static vector status only. |
| `mcp_server/session_tools/start.py` | MEDIUM | Start-message recall hints/status. |
| `mcp_server/session_tools/skills.py` | MEDIUM | Skill recall hints/status. |
| `core/qa_agent/checks_skills.py` | MEDIUM | Static vault snippets enter QA technique briefs. |
| `core/api_server/__init__.py` | LOW | Startup bootstrap log check. |
| `core/api_server/routes/__init__.py` | LOW | Route registration/re-export. |
| `dashboard/tabs/setup-gates.html` | MEDIUM | Operator-facing upload UI. |
| `dashboard/js/setup-gates.js` | MEDIUM | Operator-facing upload/list/delete UI. |
| `installers/install.sh`, `installers/install_codex.sh`, `installers/install_opencode.sh` | LOW | Installer bootstrap message/command changes. |
| Tests (`tests/test_*`) | LOW | Coverage only; checked for required cases and loosened checks. |

## Findings

### Blocking — deprecated KB aliases send malformed JSON responses
- **File/line:** `core/api_server/routes/kb_routes.py:102-105`
- **Problem:** `_with_deprecation()` parses the JSON body, adds a `deprecated` field, then creates a new `JSONResponse` while reusing `resp.headers`. Those headers still include the original `Content-Length`. A direct check shows an original 11-byte response becomes a 75-byte body with `content-length: 11`. Real HTTP clients can truncate or reject the body, so existing `/api/kb/docs` clients are not reliably preserved.
- **Fix:** Do not pass the original `content-length` into the replacement response. Build fresh headers containing only the deprecation header (and any safe non-length headers), or set the deprecated field before the initial response is rendered. Add a regression test asserting the alias response content length matches the returned body and `r.json()` contains `deprecated`.

### Blocking — Operator Actions does not list existing vaults/datasets
- **File/line:** `dashboard/js/setup-gates.js:342-345`
- **Problem:** `/api/vector/docs` returns `vaults` with each vault's datasets, but `_loadVectorDocs()` discards everything except `data.docs`. The UI has only free-text vault/dataset inputs and the current document list, so operators cannot see existing vaults/datasets from the Vector vaults section. This misses acceptance criterion 4; the current dashboard test only checks for static strings and would pass even if dataset discovery is absent.
- **Fix:** Render `data.vaults` in the Vector vaults section (for example as selectable vault/dataset chips or a table showing datasets and doc counts) and update the docs list when a vault/dataset is selected. Add a dashboard/API test that seeds multiple vaults/datasets and asserts the UI exposes their names/counts, not just the upload form.

## Test coverage gaps
- No regression test catches stale `Content-Length` on `/api/kb/docs` alias responses after adding the deprecation field.
- `tests/test_dashboard_vector_ui.py` only checks static HTML/JS strings; it does not verify that existing vaults/datasets returned by the API are rendered or selectable.
- I did not run the full suite because the prompt says protected automated checks already passed; I ran only a targeted Python check for the alias response header behaviour.

## What I did not cover
- I did not audit unchanged prior-engagement recall internals beyond the changed call sites.
- I did not perform a live browser test of the dashboard; review was from HTML/JS plus API code.
- I did not stress-test concurrent upload/delete/search races; I checked the locking/atomic-write design by inspection only.