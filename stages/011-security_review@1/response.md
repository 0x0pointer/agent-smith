Verdict: fail

Blocking findings: `core/source_client.py:134` unfenced untrusted Source snippets; `core/source_client.py:78` malformed `k` can raise from bound consult.

# Security review

## Summary
- Findings: 2 blocking, 0 non-blocking.
- Functional acceptance criteria: 9/9 are substantially implemented in the diff, but the security requirement to fence untrusted Source snippets is not met, and a bound `consult` call can still raise on malformed input.
- I read `/tmp/fabro/change.diff` and the approved spec, compared the HIGH/MEDIUM changed regions with `origin/main`, checked callers/blast radius, and ran only targeted probes for suspected edge cases.

## Changed-file triage

| File | Risk | Blast radius / notes |
|---|---:|---|
| `CLAUDE.md` | LOW | Documentation only. |
| `core/session/lifecycle.py` | HIGH | Core `start()` / `complete()` state; dashboard/operator terminal paths call `complete()`. |
| `core/source_client.py` | HIGH | New local HTTP trust boundary; 3 production search call sites and 3 ingest/write-back call sites. New file, no history. |
| `core/sources.py` | HIGH | New registry parser and loopback URL validation; called by start/use_source and by the client guard. New file, no history. |
| `mcp_server/report_tools/__init__.py` | MEDIUM | Public MCP report dispatcher; adds `consult`. |
| `mcp_server/report_tools/findings.py` | HIGH | Public finding persistence path; schedules Source ingest after a successful finding. |
| `mcp_server/report_tools/recall.py` | HIGH | Public recall/consult output path; Source snippets enter model-visible responses. |
| `mcp_server/session_tools/__init__.py` | MEDIUM | Public MCP session dispatcher; set_skill becomes async wrapper and adds use_source. |
| `mcp_server/session_tools/complete.py` | HIGH | Completion gate path; schedules digest write-back on held-success path. |
| `mcp_server/session_tools/recovery_build.py` | MEDIUM | Recovery state now exposes bound Source metadata. |
| `mcp_server/session_tools/skills.py` | HIGH | `set_skill` auto-injects Source methodology into model-visible output; adds Source rebinding action. |
| `mcp_server/session_tools/start.py` | HIGH | Public session start binds Source by registry name. |
| `mcp_server/session_tools/status.py` | MEDIUM | Status output now exposes bound Source metadata. |
| `scripts/build_engagement_digest.py` | HIGH | Projects findings/assets/auth summaries into Source ingest notes and existing CLI digest. |
| `sources.yaml` | LOW | Empty sample registry only. New file, no history. |
| `tests/test_build_engagement_digest.py` | LOW | Tests. |
| `tests/test_recall.py` | LOW | Tests. |
| `tests/test_report_tools.py` | LOW | Tests. |
| `tests/test_session.py` | LOW | Tests. |
| `tests/test_session_source.py` | LOW | Tests. New file. |
| `tests/test_session_tools_helpers.py` | LOW | Tests. |
| `tests/test_source_client.py` | LOW | Tests. New file. |
| `tests/test_sources.py` | LOW | Tests. New file. |

History check: for modified HIGH/MEDIUM files, I compared the changed regions to `origin/main` and checked `git log -S` for the recall legacy-scope text, known-assets credential/token formatting, and set_skill dispatch. I did not find a prior security fix being removed or reintroduced. New files were not blamed per instructions.

## Findings

### Blocking — untrusted Source snippets are labelled and capped but not fenced
- File/line: `core/source_client.py:134` (rendering), reachable from `mcp_server/report_tools/recall.py:332`, `mcp_server/report_tools/recall.py:351`, and `mcp_server/session_tools/skills.py:261`.
- Attacker/path: a malicious target can get prompt-injection text recorded into finding evidence, that evidence is ingested into the bound local Source, and a later `report(action='recall'|'consult')` or full/medium `session(action='set_skill')` can render the returned snippet directly into the model-visible response. A malicious or compromised local Source can do the same directly through `/search`.
- Impact/exploitability: medium exploitability because Source must be bound and the note must be retrieved; concrete impact is model steering during scan workflow (for example, instructions to skip checks or file forged results) across the new memory boundary. The spec explicitly requires Source snippets to be labelled as data and capped/fenced; this implementation labels and caps, but appends snippet text as plain prose under a bullet.
- Required fix: render every Source snippet inside a fenced/quoted data block and neutralize fence delimiters in the snippet (or use a safe four-space/code-block renderer after whitespace normalization). Add tests that malicious snippets such as `Ignore previous instructions` and embedded backticks remain fenced in consult/recall/set_skill output.

### Blocking — malformed `k` raises from a bound Source consult instead of failing soft
- File/line: `core/source_client.py:78`, reached by `mcp_server/report_tools/recall.py:350` for `report(action='consult')`.
- Attacker/path: any MCP caller that can invoke `report(action='consult')` while a Source is bound can pass `data={query:'x', k:'bad'}`. `_do_consult` forwards the raw value, and `source_client.search()` evaluates `int(k or 3)` before its fail-soft HTTP `try` block. I confirmed this raises `ValueError` with a bound Source.
- Impact/exploitability: easy; one malformed API payload turns a best-effort lookup into an exception instead of a clear bounded response. This violates the change's fail-soft contract for an optional Source backend and leaves an untested input-validation gap.
- Required fix: coerce `k` through a helper that catches `TypeError`/`ValueError` and clamps to `1.._MAX_RESULTS` (or returns a clear validation message) before issuing the request. Add a regression test with a bound Source and non-integer `k`.

## Test coverage gaps
- No negative test asserts Source snippets are fenced/quoted against prompt-injection text; current tests only check the warning label and truncation.
- No test covers malformed `k` with a bound Source; the current no-source path returns before the bad conversion.
- No regression test covers default recall in an empty workspace with no Source bound; current behavior now reports “no matches” rather than the prior “no prior engagement stores found” message.
- The brief's two `BLE001` suppressions are used for fail-soft network calls; I did not flag them, but tests should keep asserting that exception logs do not include note bodies or secrets.

## Not covered
- I did not re-run the full test suite because the pipeline already did and the task asked not to.
- I did not run a live Source HTTP server or the companion Source repository.
- I did not audit unrelated repository areas beyond the changed regions, their direct callers, and the specific history/call-graph checks above.