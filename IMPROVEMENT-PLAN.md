# agent-smith — Improvement Plan (DRAFT, pending review)

> **Status:** DRAFT v1 — awaiting review and final modifications before build approval.
> **Date:** 2026-10-14
> **Provenance:** independent review of the current codebase (engine, coverage taxonomy, skills
> tree, tool runners, QA daemon, tests — Oct 2026 state, post-surface-ledger/skill-reinvocation
> work), plus a capability comparison against RedAmon (github.com/samugit83/redamon, v6.26.2).
> This is a forward plan, not a re-audit of `GAP-ANALYSIS.md` (July) — most of that file's items
> verified as fixed in the Oct codebase and are not repeated here.

**How to read this:** every item carries evidence (file:line where applicable), a proposed fix,
effort (S < 1 day / M < 1 week / L > 1 week), and status. Items marked **[DECIDE]** need your
call before the build starts. Build order is in §9.

---

## 0. What is already strong — do not break

Verified working in the Oct codebase; all Tier work must preserve these:

- Evidence-gated cell closures (artifact-backed, 401/403 rejection, proven-chain validation)
- Skill gates that clear only on real per-skill work (`gates.py:skill_worked`), honest
  `dismiss_gate` dead-ends, bounded cover-before-complete nudge
- Deterministic chaining: auth/cookie propagation, tech→payload routing, CVE gates,
  error-signal gates, 2-identity BOLA gate, OOB weaving (SSRF), value-ranked endpoints
- Knowledge graph (`core/graph/`) with candidate-chain suggestions wired into planner/recovery/QA
- Small-model spine: fixed-context overhead metering, measured-window profile detection
- Surface-Coverage Ledger + per-instance re-triggerable skills
- QA daemon (shortcuts / coverage / depth / health / skills checks) with the qa_reply loop

---

## 2. TIER 1 — Real holes (highest find-rate impact)

### 1.1 Coverage-taxonomy blind spots  [effort S]
- **`idor` cells only exist for path params.** `query/default` and `body_form/default`
  (`core/taxonomy.py:24-25`) generate no idor cell → `?user_id=` / `{"account_id":...}` BOLA is
  untracked by the matrix. The #1 API vuln class.
  Fix: add `idor` to query/body_form applicability; add a NAME_REFINEMENTS-style *widening* rule
  so high-value object-reference param names (`user_id`, `account_id`, `order_id`, …) force an
  idor cell on any param type.
- **`upload` endpoints are classified (rank 3) but generate no `file_upload` cell type** —
  upload coverage is unclosable; lives only in web-exploit skill prose (F1–F4).
  Fix: new cell type + applicability + autoclose handler (content-type/polyglot oracle).
- **WebSocket endpoints dead-end.** `taxonomy.py:125` classifies `/ws` but `endpoint/default`
  (`taxonomy.py:29`) has no websocket cells. Fix: `websocket/default` → `cswh_origin_check`,
  `ws_message_injection`, `ws_auth_replay`.
- **`deserial` only on cookies** (`taxonomy.py:28`), never body params where Java/PHP
  deserialization actually occurs. Fix: add to body_form/body_json applicability.

### 1.2 Client-side runtime primitive (`browser()` tool) + traffic corpus  [effort L]
The entire client-side class (DOM XSS confirmation, postMessage tracing, CSP-bypass validation,
CSWSH from a browser context, service-worker inspection) has **no execution primitive** — skills
describe it, nothing can run it. RedAmon's TrafficMind + `proxy_brain` proves the blueprint.
- New `scan(tool="browser")` (Playwright-driven: navigate / evaluate JS / network intercept /
  origin-spoofed WS handshake), artifact-storing, host-pinned to discovered endpoints.
- **Traffic corpus (TrafficMind-lite):** persist every `http()` request/response into a queryable
  corpus; compute **free passive signals on every response** (reflected params → XSS candidates,
  missing security headers, cookie flag issues, auth-carried markers) and auto-generate/refine
  matrix cells from them. Fails-open (corpus errors never block requests).
- Borrow their hardening lessons: signed per-run attribution, untrusted bodies rendered inert,
  replay host-pinned to origin transaction, egress guard with DNS-rebinding IP pin if the proxy
  form is ever adopted (a pure-corpus form over `http()` avoids most of this).

### 1.3 Findings-awareness for the existing fleet  [effort M]
10 summarizers serve 14 dispatched tools + ~40 Kali-resident ones; most output degrades to 5
generic lines and parsing lands on the model. The garak auto-file pattern already exists — extend it:
- **nuclei auto-file** (highest value): JSONL parser already extracts template-id/severity/CVE —
  add idempotent auto-filing with severity scaling (garak-style), dedup by target+template-id.
- **sqlmap → first-class `scan()` tool**: summarizer + sweep routing already exist; add dispatch
  entry + options mapping (background jobs, cell auto-close for sqli).
- **testssl / dalfox / jwt_tool / netexec wrappers**: JSON-output parsers → structured facts →
  findings where confidence is high. dalfox lets sweep XSS candidates be machine-confirmed.
- **ZAP passive alerts are currently discarded** — `tools/zap_runner.py` returns only URLs from
  the baseline scan; a `zap` dispatch entry parsing baseline alerts is the cheapest new scanner
  (image already pinned).
- Nuclei template families: default skips `fuzz/dast/takeover/token-spray`; add `templates=`
  passthrough beyond tags + per-engagement custom-template drop (protect from `-ut` churn).

---

## 3. TIER 2 — Engine polish  [effort M total]

| # | Gap | Evidence | Fix |
|---|-----|----------|-----|
| 2.1 | `rate_limits` captured but **write-only** | `envelope/assets.py:182-191`; no reader; fuzzers hard-code `-rate 50` (`handlers_net.py:42-43,67-68`, `spider.py:30,82`) | feed per-host throttle into tool rate flags; Retry-After backoff in sweep/http; flag endpoints with NO limit as a finding |
| 2.2 | GraphQL import not auto-chained | `import_graphql` exists (`discovery.py:846-875`) but discovery never invokes it on a live `/graphql` hit | hook into `_discover_ai_descriptors` |
| 2.3 | Multi-principal testing thin | only latest JWT threaded (`toks[-1]`); BOLA gate fires on 2 usernames only, not 2 tokens (`core/session/assets.py:124-136`) | A-vs-B object-access harness in sweep; fire gate on any 2 distinct principals |
| 2.4 | OOB auto-weaving SSRF-only | `_fire_oob_ssrf_probes` (`coverage.py:461-491`); planner leaves blind XXE/OAST-SQLi/DNS-exfil manual (`planner.py:358`) | extend the pattern to xxe/sqli/dns cells |
| 2.5 | Trufflehog `--no-verification` | leaked creds never validated | auto-wishlist a verification step per high-severity hit |
| 2.6 | Cookie capture only from `http_request` | `envelope/assets.py:122-155` | parse spider/nuclei response artifacts too |
| 2.7 | Multi-role discovery re-fetch | only latest JWT propagated | per-role re-fetch pass when ≥2 principals held |

---

## 4. TIER 3 — Missing attack domains & meta-skills

### 4.A High-frequency domains, currently zero coverage (verified absent in skills tree)

| # | Domain | Verified absence | Chains from | Priority |
|---|--------|------------------|-------------|----------|
| A1 | **SSL VPN / edge appliance exploitation** (FortiOS, Ivanti, Pulse, Citrix ADC, F5) | `fortinet/ivani/pulse/citrix => NONE` | ssl-tls-audit, credential-audit, analyze-cve | **P0** |
| A2 | **M365 / Entra ID / Google Workspace post-compromise** (illicit consent, token replay, Teams/SharePoint, eDiscovery, Power Platform) | `o365/sharepoint => NONE` | cloud-identity-federation, credential-audit | **P0** |
| A3 | **Thick-client & Electron pentest** (ASAR, contextIsolation/nodeIntegration, IPC, .NET decompile, embedded secrets) | `electron/asar/thick.client => NONE` | codebase, api-security | P1 |
| A4 | **Data & messaging infra abuse** (Kafka authz, RabbitMQ/ActiveMQ consoles, Elasticsearch depth, Grafana snapshots, Prometheus-metrics-as-secrets) | `kafka/rabbitmq/activemq => NONE`; grafana/prometheus exposure-checks only | network-assess, credential-audit, post-exploit | P1 |
| A5 | **Secrets-management attacks** (HashiCorp Vault token scope/SSH CA, CyberArk, KMS policy) | `hashicorp/cyberark => NONE` | post-exploit, cloud-security | P1 |
| A6 | **Java middleware exploitation depth** (WebLogic/JBoss/WebSphere consoles, deserialization chains) | `weblogic/jboss/websphere => NONE` | web-exploit, analyze-cve | P1 |
| A7 | Wi-Fi (WPA2/WPA3/PMKID/EAP) | `wpa2/pmkid => NONE` | network-assess | P2 |
| A8 | Firmware/IoT + BLE/Zigbee (+ RE tooling) | NONE | codebase, post-exploit | P2 |
| A9 | VoIP/SIP | `voip/asterisk => NONE` | network-assess | P3 |
| A10 | gRPC depth beyond enumeration | api-security:248-256 dead-ends when reflection off | api-security | P2 |

### 4.B Client-side skill content (pairs with Tier 1.2)
CSWSH methodology (Origin-bypass matrix), DOM clobbering, CSTI, CSP **bypass** (nonce reuse,
script gadgets, dangling markup, strict-dynamic abuse — currently only graded,
`web-exploit/SKILL.md:601`), service workers, HTTP/2 desync exploit body (current ref is a stub,
`refs/http-smuggling.md:45-54`), Fat GET / `:authority` cache variants, OTP-verification race.

### 4.D Meta-skills — find-rate multipliers on every target

| # | Meta-skill | Why |
|---|-----------|-----|
| D1 | **Version→CVE→exploit loop** — fingerprint → CPE mapping (cve-bin-tool / syft+grype) → searchsploit/nuclei validation → analyze-cve gate. Today tech→payload routing covers ssti/cmdi/traversal only | every fingerprint becomes actionable; deterministic |
| D2 | **Tech-stack playbooks** — extend the routing map into mandatory-check matrices (Flask→PIN/debugger, WebLogic→deser consoles, Grafana→snapshot leaks) | observation → obligation, deterministic |
| D3 | **Client-code audit** — deep JS/webpack/sourcemap reversing, secret harvesting, param extraction feeding the matrix | beyond spider route-mining |
| D4 | **Cred×service propagation matrix** — systematically spray every credential against every service | BOLA gate covers identities, not reuse breadth |
| D5 | **Exploit-dev / binary RE foundation** — pwntools + radare2/ghidra-headless in exec_sandbox | supports A8, A3, memory-corruption CVE validation |
| D6 | **Protocol fuzzing** — boofuzz/AFL++-style mutation (IoT/ICS/file formats) | today fuzzing = web-paths only |

---

## 5. Adopted from RedAmon (beyond Tier 0/1 items above)

### 5.1 Local security-knowledge retrieval (their RAG KB)  [effort M] — folds into D1/D2
- Sources: GTFOBins, LOLBAS, OWASP WSTG, ExploitDB, NVD, Nuclei templates, **our own skill refs**.
- `report(action='recall')` already does deterministic keyword search over engagement stores —
  extend it to a static corpus (BM25 first; FAISS hybrid later; local embeddings only by default,
  optional OpenAI-compatible offload). Fires before any web search; offline-capable.
- Biggest single small-model win available: look-up instead of memorize.
- **Detailed design:** `docs/plan-5.1-local-kb-retrieval.md` — three corpus tiers (static KB /
  per-engagement docs via `session(action='kb_add')` / prior stores), SQLite-FTS5 BM25 index,
  per-source ingest specs, untrusted-target-doc fence, sub-phases 5.1a–f + acceptance tests.
- **Status:** 5.1a–5.1e **COMPLETE** (`core/kb.py`, `scripts/build_kb.py` — 303,556 docs:
  cve 241k via cvelistV5 (NVD feeds retired), exploitdb 47k via Kali-image recovery, nuclei 14k,
  gtfobins/lolbas/wstg/skill_refs; AND-first BM25; selftest 4/4. `session kb_add` + dashboard
  `/api/kb/docs` uploads with untrusted fence; D1/D2 planner hooks (tech→recall suggestions,
  CVE-gates→recall-first); engagement docs EPHEMERAL — purged on completion/start, names-only
  audit trail).

### 5.2 Deterministic-first triage scoring (CypherFix pattern)  [effort M]
- Fixed risk model produces the full finding ranking with **no LLM** (likelihood-real ×
  likelihood-exploited × impact × reachability-from-graph). LLM only *corrects factors*, with
  evidence-verified quotes, and binds no tools.
- Harden our adjudication path; small models stop inventing severities.


### 5.5 Should-adopt hygiene  [effort S each]
- **docker-broker pattern** — filtering proxy in front of the Docker socket (image allowlist,
  deny `--privileged`/host-root binds) for our runners.
- **Skill self-improvement loop** — mine `training-data/eventstore` to propose skill revisions
  from finished sessions (their Skiller plugin analog).
- **Published STRIDE threat model** for agent-smith itself + release-gated hardening.
- **Auto-generated onboarding SKILL.md** for external agents from the live tool list (low pri).

### 5.6 Explicitly skipped (do not build)
| RedAmon element | Reason |
|---|---|
| Neo4j/Postgres multi-container stack | Our in-proc graph + JSON stores install in minutes; keep the shape |
| OpenVAS/GVM (170K NVTs) | ~40 GB weight; nuclei + nmap + D1 loop cover most; optional sidecar if a client demands VA scans |
| Fireteam multi-agent | Skill+gates design is more rigorous per-skill; background jobs cover parallelism. Borrow their hard bounds (no recursion, immutable phase snapshot, per-member approval registry) if we ever fan out agents |
| 400+ model matrix, webapp RBAC | Different product shape |
| CodeFix PR agent | `/remediate` + `/gh-export` cover the delta; borrow their secret-free-sandbox build pattern |

---

## 6. TIER 4 — Hygiene & doc drift  [effort S)

1. `skills/README.md:212` advertises a **phantom `/pivot-tunnel`** and omits 6 real skills
   (business-logic, param-fuzz, oauth-security, saml-sso, cloud-identity-federation,
   supply-chain) — regenerate the catalog from the tree (kills the phantom-class problem).
2. `scan()` docstring missing mobsf/mobsfscan rows (`scan_tools/__init__.py`).
3. Garak default-probe doc drift (code default `encoding,promptinject,leakreplay,misleading`,
   `handlers_ai.py:441`; docs still say `dan,…`).
4. Prowler/ScoutSuite layers documented-broken (`tools/kali/Dockerfile:460-463`) — land the
   designed sidecar fix or drop the layers.
5. `web-exploit/SKILL.md:638` stale in-repo ref path (`skills/web-exploit/refs/` → actual
   `skills/web/web-exploit/refs/`).
6. codebase LLM-package detection list still frozen (`codebase/SKILL.md:163-165` — missing
   mistralai/cohere/google-generativeai/ollama/litellm/bedrock/vertexai/vllm).
7. Duplicate installed command files (`threat-model.md` + `threat-modeling.md`).

---

## 7. Not pursued (considered, rejected in this review)

- **Wi-Fi/ICS/automotive now** — real domains but engagement-frequency-gated (4.C backlog).
- **Burp/Caido integration** — `burp_proxy` passthrough suffices; the browser primitive (1.2)
  covers the programmatic need without licensing entanglement.
- **amass wrap** — subfinder + osint skill suffice for now; revisit with D1 if enumeration
  coverage measurably lags in the benchmark.


---

## 9. Build order (proposed)

```
Phase 2  Tier 1.1 taxonomy cells (S) ∥ 5.4 scope guardrail (S) ∥ Tier 4 hygiene batch (S)
Phase 3  1.3 findings-awareness (nuclei auto-file → sqlmap → zap → testssl/dalfox/jwt_tool)
         ∥ 5.1 KB retrieval (BM25) ∥ 5.2 deterministic triage
Phase 4  Tier 2 engine polish batch (2.1–2.7)
Phase 5  1.2 browser() primitive + traffic corpus + 4.B client-side skill content
Phase 6  Tier 3 batch 1: A1/A2/A3 skills + D1/D2 meta-skills (+benchmark rows for each)
Phase 7  Tier 3 batch 2: A4–A6, D3–D6; 5.3 approval gates; re-run benchmark → compare
```

