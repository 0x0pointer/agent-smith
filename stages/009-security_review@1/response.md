Verdict: fail

Blocking findings: stale operational KB instructions remain in `docs/plan-5.1-local-kb-retrieval.md`; installer scripts lost executable mode; `test_recall_ignores_legacy_kb_dirs` would not catch a reintroduced legacy `kb/` read.

Contents of `/tmp/fabro/security-review.md`:

```markdown
# Security review

## Summary
Blocking findings: 3. Non-blocking findings: 0. The code removal largely closes the intended KB upload/URL-fetch/static-index surfaces, but the change leaves operational KB instructions in an obsolete docs file, drops executable bits from installer scripts, and has a weak required negative test for legacy `kb/` reads.

## Changed files risk / blast radius

| File | Risk | Blast radius |
|---|---:|---|
| `.gitignore` | LOW | Legacy local data ignore only. |
| `CLAUDE.md` | LOW | Agent usage docs. |
| `README.md` | LOW | User docs; install/recall guidance. |
| `core/api_server/__init__.py` | MEDIUM | API startup task path; KB nudge removed. |
| `core/api_server/routes/__init__.py` | MEDIUM | Dashboard router registration; removing import affects all `/api/kb/docs` reachability. |
| `core/api_server/routes/kb_routes.py` | HIGH | Deleted public dashboard upload/list/delete API; prior attack surface included multipart parsing and file deletion. Current callers: 0. |
| `core/api_server/routes/scan_state_routes.py` | MEDIUM | Clear-all endpoint cleanup behavior. |
| `core/kb.py` | HIGH | Deleted shared file/SQLite/document parsing module. Current runtime imports found: 0. History included a path-injection hardening commit; deletion removes, not re-adds, that surface. |
| `core/qa_agent/checks_skills.py` | MEDIUM | QA stuck-escalation technique brief generation. |
| `core/session/lifecycle.py` | MEDIUM | Session start/complete cleanup paths. |
| `dashboard/css/dashboard.css` | LOW | Removed file-input styling only. |
| `dashboard/js/setup-gates.js` | MEDIUM | Operator Actions polling/rendering; current polling still hits wishlist/setup gates only. |
| `dashboard/js/skills.js` | LOW | Label change for recall metrics. |
| `dashboard/tabs/setup-gates.html` | MEDIUM | Operator Actions UI; resource requests and setup gates remain. |
| `docs/dashboard-api.md` | LOW | API docs only. |
| `docs/plan-5.1-local-kb-retrieval.md` | MEDIUM | Documentation can still steer users/agents toward removed KB behavior. Finding below. |
| `installers/install.sh` | MEDIUM | User install entry point; executable bit regressed. Finding below. |
| `installers/install_codex.sh` | MEDIUM | User install entry point; executable bit regressed. |
| `installers/install_opencode.sh` | MEDIUM | User install entry point; executable bit regressed. |
| `mcp_server/report_tools/recall.py` | HIGH | Public `report(action="recall")` path reads local prior stores; 1 production dispatcher caller. `_parse_scope` rejects KB/docs/kind scopes and no `core.kb` import remains. |
| `mcp_server/scan_engine/planner.py` | MEDIUM | Planner recommendations/gate text; KB hints removed. |
| `mcp_server/session_tools/__init__.py` | MEDIUM | Public session action dispatch/help; `kb_add` no longer dispatched or listed. |
| `mcp_server/session_tools/kb_add.py` | HIGH | Deleted URL/file/artifact ingestion action; prior SSRF/path surface removed. Current callers: 0. |
| `mcp_server/session_tools/skills.py` | MEDIUM | Skill logging response text; KB recall hints removed. |
| `mcp_server/session_tools/start.py` | MEDIUM | Scan-start response text; KB norm removed. |
| `scripts/build_engagement_digest.py` | MEDIUM | Prior-engagement store generation; KB provenance/docs removed while digest remains. |
| `scripts/build_kb.py` | HIGH | Deleted network-fetching/static-KB builder. |
| `tests/test_api_kb_docs.py` | LOW | Deleted tests for removed API. |
| `tests/test_build_engagement_digest.py` | LOW | Digest regression coverage. |
| `tests/test_build_kb.py` | LOW | Deleted tests for removed builder. |
| `tests/test_dashboard_no_kb_docs.py` | LOW | Removal assertions for dashboard/API. |
| `tests/test_installers_no_kb_bootstrap.py` | LOW | Installer KB-reference assertions, but misses executable modes. |
| `tests/test_kb_add.py` | LOW | Deleted tests for removed action. |
| `tests/test_kb_core.py` | LOW | Deleted tests for removed core module. |
| `tests/test_kb_recall.py` | LOW | Deleted tests for removed KB tiers. |
| `tests/test_planner.py` | LOW | Planner no-KB regression coverage. |
| `tests/test_recall.py` | LOW | Prior recall/no-KB regression coverage; one weak assertion. Finding below. |
| `tests/test_session_no_kb.py` | LOW | Session/start/set_skill no-KB coverage. |
| `tests/test_vuln_escalation.py` | LOW | QA fallback expectation updated. |

## Findings

### Blocking: obsolete KB plan still contains operational removed-feature instructions
`docs/plan-5.1-local-kb-retrieval.md` is marked obsolete at the top, but the retained body still tells readers to use local KB recall before web search, run `build_kb.py`, use `scope:"kb"`/`scope:"docs"`, and call `session(action="kb_add")`. This violates acceptance criterion 6 and review focus 5: docs must not instruct users/agents to use removed KB/docs scopes or upload/build paths. Fix by replacing the body with a short historical note, or moving the old content behind an unmistakable archive that does not contain actionable current instructions.

### Blocking: installer scripts lost executable mode
`git diff --summary origin/main` shows `installers/install.sh`, `installers/install_codex.sh`, and `installers/install_opencode.sh` changed from `100755` to `100644`. Existing docs invoke them as `./installers/install*.sh`, so fresh users get `Permission denied` even though removing KB bootstrap did not require changing modes. Fix by restoring executable bits on all three installer scripts and adding/checking a mode assertion if possible.

### Blocking: required legacy-`kb/` negative test would pass if recall returned KB content
`tests/test_recall.py::test_recall_ignores_legacy_kb_dirs` ends with `assert "kb" not in out.lower() or "scope 'kb'" not in out.lower()`. Because this is an `or`, output containing legacy KB content still passes unless it also contains the exact phrase `scope 'kb'`. This does not prove the security consideration that runtime never reads legacy `kb/`; change it to assert the legacy content/source is absent, for example `assert "legacy kb data" not in out` and `assert "kb:" not in out.lower()`.

## Test coverage gaps
- No test checks the executable mode of the installer scripts, which regressed in this diff.
- The required legacy `kb/` ignored test is too weak to catch a reintroduced flat scan of `kb/sources`.
- The docs tests do not scan `docs/plan-5.1-local-kb-retrieval.md`, so stale operational KB instructions remained.

## What I did not cover
I did not rerun the full test suite because the prompt said automated checks already passed. I did not audit unchanged repository behavior outside one-hop callers and references from the changed regions. I did not manually exercise the dashboard in a browser; review was based on diff, route registration, grep, and targeted code inspection.
```