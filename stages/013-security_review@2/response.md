Verdict: pass

Blocking findings: none

Contents of `/tmp/fabro/security-review.md`:

```markdown
# Security review (round 2 re-review)

## Summary
- Findings: 0 blocking, 1 non-blocking.
- Re-reviewed only `/tmp/fabro/since-review.diff` as instructed. The two prior blocking findings are addressed in code: `/api/kb/docs` no longer reuses a stale `Content-Length`, and the Operator Actions dashboard now renders the `vaults`/`datasets` returned by `/api/vector/docs`.
- Acceptance criteria: 8/8 appear met based on the previous full review plus the fixes in this round.

## Changed-file triage
| File | Risk | Blast radius |
| --- | --- | --- |
| core/api_server/__init__.py | MEDIUM | Startup status/nudge only; one background-task path. |
| core/api_server/routes/__init__.py | LOW | Route registration/export only. |
| core/api_server/routes/kb_routes.py | MEDIUM | Deprecated dashboard API alias; 3 route handlers call `_with_deprecation`. |
| core/api_server/routes/scan_state_routes.py | MEDIUM | Session state/status hints consumed by dashboard/API clients. |
| core/api_server/routes/vector_routes.py | HIGH | Public dashboard upload/list/delete API for untrusted documents. |
| core/kb.py | HIGH | Compatibility shim for removed KB parser/status/search behaviour. |
| core/qa_agent/checks_skills.py | MEDIUM | QA recall guidance/planner hints. |
| core/session/lifecycle.py | HIGH | Scan lifecycle purge path for engagement vector vaults. |
| core/vector_store.py | HIGH | New vault/dataset storage, parsing, sanitisation, search, purge. |
| dashboard/js/setup-gates.js | MEDIUM | Operator UI renders API-sourced vault/doc metadata and calls upload/delete APIs. |
| dashboard/tabs/setup-gates.html | LOW | Static dashboard markup. |
| installers/install.sh | MEDIUM | Install bootstrap invokes static vector KB build/status. |
| installers/install_codex.sh | MEDIUM | Install bootstrap invokes static vector KB build/status. |
| installers/install_opencode.sh | MEDIUM | Install bootstrap invokes static vector KB build/status. |
| mcp_server/report_tools/recall.py | HIGH | Agent-facing recall path and untrusted-content fencing. |
| mcp_server/scan_engine/planner.py | MEDIUM | Recall planning/hint behaviour. |
| mcp_server/session_tools/__init__.py | MEDIUM | Public MCP action registration/help surface. |
| mcp_server/session_tools/kb_add.py | HIGH | Deprecated MCP ingestion alias for untrusted operator/target documents. |
| mcp_server/session_tools/skills.py | LOW | Help/status wording only. |
| mcp_server/session_tools/start.py | MEDIUM | New scan lifecycle purge trigger. |
| mcp_server/session_tools/vector_add.py | HIGH | New MCP ingestion path for files, URLs, and artifacts. |
| scripts/build_kb.py | MEDIUM | Static security corpus build/status/selftest CLI. |
| tests/test_api_kb_docs.py | LOW | Removed old KB API tests, replaced by vector API tests. |
| tests/test_api_vector_docs.py | LOW | API regression tests. |
| tests/test_build_kb.py | LOW | Build CLI tests. |
| tests/test_dashboard_vector_ui.py | LOW | Dashboard/API smoke test. |
| tests/test_kb_add.py | LOW | Removed old KB add tests, replaced by vector add tests. |
| tests/test_kb_core.py | LOW | Removed old KB core tests, replaced by vector store tests. |
| tests/test_kb_recall.py | LOW | Removed old KB recall tests, replaced by vector recall tests. |
| tests/test_planner.py | LOW | Planner regression tests. |
| tests/test_vector_add.py | LOW | MCP vector add tests. |
| tests/test_vector_recall.py | LOW | Vector recall tests. |
| tests/test_vector_store.py | LOW | Vector store tests. |

## Findings
### Non-blocking: dashboard vault rendering test is still mostly structural
`tests/test_dashboard_vector_ui.py` seeds multiple vaults/datasets and verifies the API payload, and it checks that the JS source references `data.vaults`, `vault.name`, and `dataset.docs`. It still does not execute `_renderVectorVaults()` or assert that seeded names/counts are actually rendered into DOM. This is a coverage weakness, not a blocker for this round, because the code path was manually inspected and now renders escaped vault/dataset names and counts.

## Test coverage gaps
- No JS DOM-level regression test exercises `_renderVectorVaults()` selection/rendering. A future typo in the render function or event binding could pass the current source-string test.
- Targeted tests run: `python -m pytest -q tests/test_api_vector_docs.py::test_kb_docs_aliases_return_deprecation_header_or_field tests/test_dashboard_vector_ui.py::test_setup_gates_uses_vector_vaults_not_kb_docs` (passed).

## What I did not cover
- Per re-review instructions, I did not re-audit unchanged regions from the original 3,957-line change. I relied on the previous review's conclusion for unchanged acceptance criteria and checked only the regions in `/tmp/fabro/since-review.diff` plus direct callers/guards needed to validate those fixes.
- I did not run the full test suite or perform browser-based dashboard testing.
```