# agent-smith — Autonomous Pentest Capability Gap Analysis

> **Purpose:** an engineer-shareable plan to evolve agent-smith from a hardened breadth-first
> coverage-checklist engine into an autonomous tester that reasons, chains, and deep-dives like
> an experienced human — and does so on smaller reasoning models (Qwen ~27B) as well as frontier
> models, through **architecture** rather than model intelligence.
>
> **How this was produced:** five parallel deep reviews against the real code (spider→testing
> pipeline; artifact/context chaining; skill quality & attack coverage; workflow & architecture;
> small-model optimization). 54 findings, cross-referenced and de-duplicated below.
>
> **Each finding carries:** gap · why it's a weakness · practical impact · concrete fix (file/function)
> · complexity · expected impact · model-class benefit (frontier / smaller / **both** preferred) · priority.

---

## 1. Executive summary

**The one-sentence thesis:** *agent-smith deterministically does the work the model should own
(fanning a 700-cell exhaustive matrix, emitting one canned payload per class) and leaves to the
model the work the system should own (chaining discoveries into follow-up attacks, prioritizing by
value, re-planning when new info arrives, propagating auth). Inverting that split is the single
highest-leverage change, and it helps small and frontier models simultaneously.*

Five independent reviews, from five different angles, converged on the **same root cause**: the
framework's "intelligence" is encoded as *prose the model must remember and choose to act on* (600+
lines in `pentester.md`, 25 KB of always-resident `CLAUDE.md`, 44 KB skills), backed by a **flat
coverage matrix** that cannot represent the things that actually drive an engagement — reachability,
trust boundaries, entities (creds/tokens/users), data flow, and attack chains. Because the central
model can't represent them, every "smart" behavior (prioritize, chain, re-plan, dedup) is pushed onto
the LLM and is therefore unreliable — and *most unreliable exactly on the smaller models the project
wants to support*.

**What's genuinely good and should be kept:** the envelope's artifact/asset extraction, the
discovery-layer enrichment (host-side OpenAPI fan-out, JS mining, liveness probing), the
closure-integrity gates (artifact-backed cell closures, proven-chain validation), the one-concrete-call
recovery brief, and the budget/artifact plumbing. These are the right shape; the problems are in the
*central model* and the *chaining/prioritization logic* layered on top.

**Redesign verdict:** **substantial at the core, incremental at the edges.** Replace the flat coverage
matrix with a shared **knowledge-graph world-model** + a **value-ranking planner** + a **declarative
attack-pattern/reference library** + a **deterministic chain/trigger engine**, while preserving the
well-built peripheral pieces. This is the same direction as the Neo4j migration already in the
project's plans — this review is direct, multi-angle evidence that it's warranted.

---

## 2. The convergent themes (read this before the findings)

Almost every one of the 54 findings reduces to one of these seven workstreams. This is where the
synthesis value is: fixing the *theme* fixes many findings at once.

| # | Workstream | Core move | Fixes findings | Model-class |
|---|---|---|---|---|
| **W1** | **Push-based chaining engine** | Turn discoveries into system-triggered follow-ups instead of relying on the model to remember to chain | CH-1..12, SP-10, WF-A3, AR-B2, SM-7 | **both** (biggest small-model win) |
| **W2** | **Knowledge-graph world-model** | Replace the flat matrix with a graph (Host/Service/Endpoint/Param/Cred/Token/Finding/Chain + reachability/auth/escalates edges); matrix becomes a *view* | AR-B1/B3/B8, WF-A1/A5, CH-12 | both |
| **W3** | **Targeted matrix (stop the 700-cell bloat)** | Name-aware param classification + value-ranked endpoint order so cells reflect real targets, not a mechanical grid | AR-B4, WF-A1/A7, SM-5 | both |
| **W4** | **Auth-aware discovery + richer spider** | Propagate the crawl's auth to the discovery re-fetch; keep form/method/WS/header/secret data instead of flattening to URLs | SP-1..11, CH-2/10 | both |
| **W5** | **Server-side sweep & schema import** | Let the server execute the mechanical work — OpenAPI/GraphQL → cells in one call; run the per-cell probe ladder and pre-fill closures | SM-4/5/10, SP-2/3, CH-6 | **both** (closes small↔frontier quality gap) |
| **W6** | **Small-model spine (correct budgeting)** | Drive profile + budget + pressure off the *measured* context window and *real* token counts, not env-name strings and output-only counting | SM-1/2/8/11 | **both** (fixes silent overflow) |
| **W7** | **Shared attack-pattern / reference library** | One canonical methodology layer (payloads, entropy, mass-assignment, IMDS, JWT…) referenced by skills; reasoning-first skills that route by observation | SQ1..7, AR-B7, SM-3, WF-A4/A6 | both |
| **W8** | **Attack-coverage: new skills** | Close entire missing categories a real attacker uses (cloud identity federation, supply-chain/CI-CD, SAML/SSO, client-side, auth-recovery flows, agentic-AI) | AC1..8 | both |

Plus one **cross-cutting security fix**: AR-B9 (uniformly fence attacker-controlled strings before they
enter Smith's own control-plane prompts — a prompt-injection surface).

---

## 3. Prioritized roadmap

Phased so each phase is independently shippable and de-risks the next. Complexity/impact are per the
findings; "unlocks" notes the dependency.

### Phase 0 — Quick wins (low complexity, high leverage; ship first)
Deterministic fixes that need no redesign and each fix real, demonstrable loss today.

| Fix | Finding | Why now |
|---|---|---|
| Value-rank endpoints in batch selection | WF-A1 (P0) | 1-function change; front-loads auth/admin/payment endpoints |
| Auth-propagate the discovery re-fetch | SP-1 (P0) | Unlocks the *entire* authenticated surface into the matrix |
| Keep full crawl output before parsing (stop 4k pre-parse truncation) | SP-11 (P1) | Deep crawls silently drop the long tail today |
| Name-aware param fanning | AR-B4 (P1) | Cuts matrix 3-5×, kills the floor-vs-integrity arms race |
| Capture Set-Cookie/session + lift trufflehog/semgrep secrets into known_assets | CH-2/CH-10 | Cookie-session apps currently depend on the model remembering a cookie |
| Decouple cloud/network gates from a pre-existing RCE gate | CH-7 | SSRF→IMDS with no shell currently fires nothing |
| Uniform `<<UNTRUSTED>>` fencing of target text in directives | AR-B9 (P1) | Closes a prompt-injection path into the control plane |
| Fix concrete skill bugs (SecureString skip, osint `/tmp/subdomains.txt`, web-exploit dual Phase-0, param-fuzz missing gates) | SQ4 | Missed secrets / dead steps / lost state today |

### Phase 1 — Deterministic engine + small-model spine (the core inversion)
This is where the framework stops depending on the model to remember to be smart.

- **W6 small-model spine:** count real tokens against the *measured* window (SM-1), unify profile on the
  installer-detected window (SM-2), decouple the four profile knobs (SM-8). *These are correctness bugs, not tuning.*
- **W5 server-side sweep + schema import:** `import_openapi`/`import_graphql` coverage actions (SM-4, SP-2/3);
  a server-side `endpoint_sweep` that runs the per-cell probe ladder, stores artifacts, and pre-fills
  closures for the model to adjudicate (SM-5/10) → then flip `enforce_coverage` on for medium/small.
- **W1 push-triggers (first tranche):** tech→payload routing (CH-1), CVE→exploit-validation (CH-3),
  error-signal→targeted injection (CH-4), second-role→BOLA (CH-5), evidence-driven gates instead of
  model-phrasing-driven (CH-11), auto-register discovered paths as cells (CH-6, SP-10).
- **W4 richer spider:** structured forms (method/enctype/fields), WS URLs, per-endpoint headers, JS
  secrets, sourcemaps (SP-5..9).

### Phase 2 — Knowledge-graph world-model (the substantial redesign)
- **W2:** introduce the graph (nodes: Host/Service/Endpoint/Param/Credential/Token/Finding/Chain;
  edges: hosts/authenticates/reaches/leaks/escalates_to/tested_for). Coverage matrix becomes a *view*.
  Consolidate the ~7 side-JSON stores into it (AR-B8). This unlocks deterministic value-ranking (WF-A1/A5),
  reachability-aware re-planning (WF-A3), and **graph-derived chain discovery** (AR-B3) — the highest-value
  pentest output, currently 100% model-declared.
- Re-home chain composition, dedup, and re-plan triggers into the planner over the graph (AR-B2).
- Refactor the fragile edges the redesign touches: split the `session_tools` god-module + typed
  `Blocker` registry (AR-B5), decompose `envelope.wrap` into a named pipeline with templated prompts (AR-B6).

### Phase 3 — Reasoning-first skills + attack-coverage expansion
- **W7:** stand up `skills/_shared/refs/` canonical modules; replace copy-pasted/contradictory blocks
  (SQ1/2/5/7); add "route by what you observed" steps (SQ3); refactor runbook skills (osint,
  credential-audit, container-k8s) toward the pattern-teaching style of business-logic/post-exploit/codebase (SQ6);
  condensed per-phase skill variants the planner feeds turn-by-turn (SM-3); declarative skill manifest (AR-B7).
- **W8 new skills:** cloud identity federation (AC1, P0), supply-chain/CI-CD (AC2), SAML/SSO/SCIM (AC3),
  client-side (WebSocket/CSWSH/postMessage/CSP-bypass) (AC4), auth-recovery flows & passkeys (AC5),
  agentic-AI (indirect injection, multi-agent, memory poisoning) (AC6), modern escape/desync depth (AC7/AC8).

---

## 4. Master findings table

Scannable index. IDs: **SP** spider · **CH** chaining · **SQ** skill-quality · **AC** attack-coverage ·
**WF** workflow · **AR** architecture · **SM** small-model. Detailed 8-part write-ups in §5.

| ID | Finding | Cx | Impact | Model | Pri |
|---|---|---|---|---|---|
| WF-A1 | Endpoint test order is registration-order, not value-ranked | low | high | both | **P0** |
| AR-B1 | Flat coverage matrix is the wrong central model → knowledge graph | high | high | both | **P0** |
| SP-1 | Discovery re-fetch is unauthenticated even after an authed crawl | med | high | both | **P0** |
| SP-2 | JS-mined routes register with no params → zero injection cells | med | high | both | **P0** |
| CH-1 | Tech/framework fingerprint persisted but never consumed | med | high | both | **P0** |
| AC1 | Cloud-native identity federation (OIDC CI/CD, IRSA, SSRF→IMDS chain) under-tested | med | high | both | **P0** |
| SQ1 | No shared methodology layer; logic copy-pasted with contradictory thresholds | med | high | both | **P0** |
| SM-1 | Context-pressure meter counts only ~10% of the window | med | high | both | **P0** |
| SM-2 | Profile keyed off env-name strings, not the measured window | med | high | both | **P0** |
| WF-A2 | Rigid linear phase pipeline punishes re-recon | med | high | frontier | P1 |
| WF-A3 | No server-side adaptive re-planning when new info arrives | med | high | both | P1 |
| WF-A4 | Machine "next probe" is one canned payload — contradicts skills | med | med | smaller | P1 |
| WF-A7 | Coverage floor forces breadth busywork & invites gaming | high | high | both | P1 |
| AR-B2 | Deterministic/model responsibility split is inverted | high | high | both | P1 |
| AR-B4 | Static applicability table over-fans the matrix (700 cells) | med | high | both | P1 |
| AR-B9 | Attacker-controlled strings flow into control-plane prompts unfenced | low | med | both | P1 |
| SP-3 | GraphQL never auto-expanded into endpoints/cells | high | high | both | P1 |
| SP-4 | Over-eager 404 pruning drops POST-only/auth-only endpoints | low | med | both | P1 |
| SP-5 | Playwright throws away form method/enctype/fields | med | high | both | P1 |
| SP-11 | Spider output truncated to 4k before discovery parses it | low | high | both | P1 |
| CH-2 | Cookie/session auth never captured (JWT-only) | med | high | both | P1 |
| CH-3 | Confirmed CVEs don't auto-trigger analyze-cve/metasploit | med | high | both | P1 |
| CH-4 | Error/body signals (Werkzeug, SQL errors) dead-end | med | high | both | P1 |
| CH-5 | Second user role doesn't trigger BOLA/BFLA | med | high | both | P1 |
| CH-6 | Discovered paths not auto-registered as cells | med | high | both | P1 |
| SM-3 | Skills are 30-44 KB prose walls, not profile-aware | high | high | both | P1 |
| SM-4 | OpenAPI→coverage fan-out is a manual model task | med | high | both | P1 |
| SM-5 | `enforce_coverage` off for small/medium; no server sweep | high | high | both | P1 |
| SQ2 | Hardcoded lists presented as "the set" (mass-assign, LLM detect, capabilities) | low | high | both | P1 |
| SQ3 | Context inference under-exploited (fingerprint→payload family) | low | high | both | P1 |
| SQ4 | Concrete skill bugs (SecureString skip, broken deps, dual phases) | low | med | both | P1 |
| AC2 | No supply-chain / CI-CD / dependency-confusion coverage | med | high | both | P1 |
| AC3 | No SAML / enterprise-SSO / SCIM; shallow JWT | med | high | both | P1 |
| AC4 | Client-side surface largely missing (WS/CSWSH, postMessage, CSP bypass) | med | high | both | P1 |
| AC5 | Auth-recovery flows (reset poisoning, magic-link, passkey) missing | low | high | both | P1 |
| AC6 | ai-redteam misses agentic vectors (indirect injection, multi-agent, memory) | med | high | both | P1 |
| WF-A5 | Findings never prioritized for deepening | low | med | both | P2 |
| WF-A6 | Cross-skill context passed as unstructured free-text | med | med | both | P2 |
| AR-B3 | Attack chaining model-declared, not graph-derived | high | high | frontier | P2 |
| AR-B5 | `session_tools` 3087-line god-module; stringly-typed blockers | med | med | smaller | P2 |
| AR-B6 | `envelope.wrap` overloaded; logic mixed with prompt copy | med | med | both | P2 |
| AR-B7 | Skill orchestration prose-encoded & triplicated per client | high | med | both | P2 |
| AR-B8 | State fragmented across ~7 JSON files, implicit joins | high | med | both | P2 |
| SP-6 | Source maps excluded from JS mining | med | med | frontier | P2 |
| SP-7 | No inline-secret/API-key/comment extraction from JS/HTML | med | med | both | P2 |
| SP-8 | Response headers/tech never per-endpoint → no header cells | med | med | both | P2 |
| SP-10 | Spider summarizer nags re-registration of already-registered endpoints | low | med | smaller | P2 |
| CH-7 | Env gates (cloud/net) only fire if an RCE gate already exists | low | med | both | P2 |
| CH-8 | Rate-limit signals never captured; fuzzing not throttle-aware | med | med | both | P2 |
| CH-9 | OOB callbacks not woven into generated payloads | med | med | both | P2 |
| CH-11 | Gates key off model-authored text, not deterministic tool evidence | med | med | smaller | P2 |
| SM-6 | CLAUDE.md 25 KB always-resident; tool-name translation burden | med | med | both | P2 |
| SM-7 | Initial skill *selection* left to model reasoning | low | med | both | P2 |
| SM-8 | `medium` threshold conflates capability with window size | med | med | smaller | P2 |
| SM-9 | Recovery warnings advisory below 90%; model must choose to act | low | med | smaller | P2 |
| SM-10 | next_batch test→close loop is manual bookkeeping | med | med | both | P2 |
| SQ5 | Brittle exact-string response oracles | low | med | both | P2 |
| SQ6 | Determinism gradient — osint/credential-audit/container-k8s are runbooks | med | med | frontier | P2 |
| SQ7 | Rotting pinned constants (baked years, dated route DBs, exploit URLs) | low | med | both | P2 |
| AC7 | Missing modern escape/escalation; detection ≠ bypass | med | med | both | P2 |
| AC8 | Shallow transport depth (H2 desync, single-packet race, WCD); `/pivot-tunnel` advertised but absent | med | med | both | P2 |
| SP-9 | WebSocket URLs never discovered (dead `websocket` gate) | med | low | frontier | P3 |
| CH-12 | known_assets endpoints/ports drive no follow-up | low | med | both | P3 |
| SM-11 | Profile detected once at start, never re-evaluated on model swap | low | low | smaller | P3 |

**Priority rollup:** 9× P0 · 27× P1 · 24× P2 · 3× P3.
**Model-class rollup:** ~46 **both** · ~5 smaller-primary · ~4 frontier-primary — i.e. the large majority
improve *both* classes through better system design, exactly the stated preference.

---

## 5. Detailed findings (8-part format)

> Only the highest-signal findings are expanded here for readability; the master table above is the
> complete list, and every ID maps to a fix location. Expansions are grouped by dimension.

### 5.1 Spider coverage & discovery→testing pipeline

**SP-1 — Discovery re-fetch is unauthenticated even after an authed crawl.**
Gap: `scan_tools.py:306` calls `discover_and_register(target, urls)` with no auth; `discovery._fetch`
(`discovery.py:249-269`) uses a bare aiohttp session — cookies reach only the Playwright process
(`scan_tools.py:168,220`). Why: spec fetch, form reads, JS mining, and the 404 liveness probe all run
anonymously, so on an auth-gated app the specs/forms/probes hit login walls and the matrix collapses to
the public surface; endpoints are also mis-stamped `auth_context="none"`. Impact: the authenticated
surface — the whole point of a credentialed pentest — never enters the matrix; the re-spider-with-auth
trigger produces almost no new cells. Fix: thread cookies/`known_assets.auth_tokens[-1]` into
`_handle_spider`→`discover_and_register`→`_fetch`; pass a real `auth_context`. Cx med · Impact high ·
**both** · **P0**. *Compounds with SP-4 and SP-11.*

**SP-2 — JS-mined routes register with no params → zero injection cells.** `discovery.py:313` registers
mined routes with `params: []`; `operations.py:96-137` then generates only endpoint-level cells, no
sqli/xss/ssti/idor. Modern SPA/API routes live in JS bundles, so a large slice of surface is a coverage
*illusion* — present, never injection-tested. Fix: infer params from the route (templatized `/{id}`→path
param, `?a=b`→query params, `fetch(...,{method,body})`→body param) at `discovery.py:210-218,307-315`.
Cx med · high · **both** · **P0**.

**SP-3 — GraphQL never auto-expanded** (only regex-mined as a param-less `/graphql` string). The skill
mandates per-operation registration but it's 100% manual → a weak model paraphrases the whole schema
into one stub (the exact failure the discovery layer prevents for REST). Fix: `_discover_graphql` that
POSTs introspection, fans query/mutation ops into endpoints+typed body params. Cx high · high · **both** · P1.

**SP-5 — Playwright discards form method/enctype/fields** (`playwright_spider.py:103-108` keeps only
`action`); host-side recovery re-fetches HTML unauthenticated and can't reproduce SPA-rendered forms.
POST forms register as GET, no params → no injection cells. Fix: serialize forms as
`{action,method,enctype,fields[]}` structured lines. Cx med · high · **both** · P1.

**SP-11 — Spider output truncated to 4k chars before discovery parses it** (`scan_tools.py:203`). Deep
crawls (the reason the 2h timeout exists) silently register only the first ~40-80 URLs; the interesting
deep admin/API routes are dropped before cell generation. Fix: pass the un-clipped list to
`discover_and_register`; keep the bounded summary via `artifact_raw`. Cx low · high · **both** · P1.
*(Also SP-4 over-eager 404 prune, SP-6 sourcemaps, SP-7 inline secrets, SP-8 per-endpoint headers,
SP-9 WebSocket URLs, SP-10 redundant re-registration nag — see table.)*

### 5.2 Artifact & context chaining (push vs pull)

The only truly deterministic (push) chains today are JWT+credential extraction (+the AUTH_MISSING retry
directive) and the endpoint-type gate at `add_endpoint`. **Everything else is pull-based** — it depends on
the model choosing to act, which small models routinely skip.

**CH-1 — Tech/framework fingerprint persisted but never consumed.** `_persist_httpx_assets`
(`envelope.py:247-255`) writes tech/server; the only reader is the writer. `planner._concrete_test_command`
(`planner.py:245-259`) emits a generic `{{7*7}}`/`;id` for *every* target regardless of Jinja2/Twig/ERB
or Express/Rails/Spring. Impact: the single most valuable chaining signal is inert — a Werkzeug/Jinja2
fingerprint that should immediately select Jinja2 SSTI RCE does nothing. Fix: a `tech→payload_profile` map
consumed by the planner + surface tech in the recovery brief. Cx med · high · **both** · **P0**.

**CH-2 — Cookie/session auth never captured** (JWT-only). `_inject_missing_auth_warning` even *tells* the
model to reuse a Set-Cookie value nothing ever stored. On the majority of classic web apps, authed testing
depends on the model remembering a cookie across turns; after compaction the session is lost. Fix: capture
`Set-Cookie` into `known_assets.session_cookies`; add to recovery + AUTH_MISSING reuse. Cx med · high · **both** · P1.

**CH-3 — Confirmed CVEs don't auto-trigger analyze-cve/metasploit.** `report()` stores `cve=` but no gate
consumes it; nuclei CVE hits aren't auto-persisted/filed. A critical CVE just sits as text. Fix: CVE branch
in `_auto_trigger_finding_gates` + nuclei branch in `_extract_and_persist_assets`. Cx med · high · **both** · P1.

**CH-4 — Error/body signals dead-end.** `_extract_body_signals` (`summarizers.py:206-217`) flags a Werkzeug
debugger ("potential RCE"), SQL errors, leaked secrets — then only appends to `anomalies`. A Werkzeug
debugger is a near-certain interactive RCE console; a reflected SQL error points at the injectable param.
Fix: route these into gates/targeted cells. Cx med · high · **both** · P1.

**CH-5 — Second user role doesn't trigger BOLA/BFLA.** 2+ role identities *can* coexist in the vault but
nothing detects "≥2 principals" to open a business-logic/BOLA gate; IDOR cells are single-identity `id=1`
vs `id=2`, not true horizontal-privilege BOLA (identity-A token fetching identity-B object). The #1 API vuln
class is only tested if the model decides to. Fix: detect the second-credential delta → gate; two-identity
IDOR harness. Cx med · high · **both** · P1.
*(Also CH-6 auto-register discovered paths, CH-7 decouple env gates, CH-8 rate-limit capture, CH-9 OOB into
payloads, CH-10 lift trufflehog/semgrep secrets, CH-11 evidence-driven gates, CH-12 ports→service gates.)*

### 5.3 Skill quality & attack coverage

Best pattern-teaching models to emulate: **business-logic, post-exploit, codebase** ("don't grep a static
list — infer from context"). Most brittle/runbook-style: **osint, credential-audit, container-k8s**.

**SQ1 — No shared methodology layer; contradictory copies.** Entropy analysis exists 3× with *different*
thresholds (business-logic "<40 bits", credential-audit ">128/<64", param-fuzz "<80 bits"); mass-assignment
lists hardcoded 3×; IMDS/escape/secret-grep copied across cloud/k8s/post-exploit with divergent syntax;
chain tables restated twice per skill and already disagreeing. Same token graded Critical or Clean depending
on entry path → non-reproducible audits. Fix: `skills/_shared/refs/` canonical modules referenced by a
one-liner. Cx med · high · **both** · **P0**. *(Note: Track 1's client-neutral chaining work already began
consolidating the per-client invocation duplication — this extends the same principle to methodology.)*

**SQ2 — Hardcoded lists presented as "the set."** codebase's LLM-detection allow-list (`codebase.md:146-149`)
misses mistralai/cohere/google-generativeai/ollama/litellm/Bedrock/vertexai/vllm — and the mandatory
`/ai-redteam` chain hinges on it matching; mass-assignment field lists, S3 suffixes, "all dangerous
capabilities" (missing CAP_BPF/PERFMON/DAC_READ_SEARCH/SYS_MODULE) are frozen. A model that memorizes N
strings can't invent the N+1th. Fix: teach the *derivation*, keep literals as labeled seed examples. Cx low
· high · **both** (small models lean hardest on the frozen list) · P1.

**SQ3 — Context inference under-exploited.** The model fingerprints then ignores it: web-exploit fires
`{{7*7}}` blindly instead of routing Flask→Jinja2 / Rails→ERB / Spring→SpEL (knowledge already in
`refs/ssti.md`); ai-redteam captures the provider then applies an identical script. Fix: "route by what you
observed" step in web-exploit / codebase / ai-redteam / cloud. Cx low · high · **both** · P1.

**SQ4 — Concrete bugs:** cloud-security `L401` filters SSM to `Type=='String'`, silently skipping
`SecureString` (where the secrets are); osint reads `/tmp/subdomains.txt` that no phase writes; web-exploit
has two conflicting "Phase 0"s; param-fuzz lacks the coverage gate + compaction-recovery its siblings have.
Cx low · med · **both** · P1.

**Attack-coverage gaps (think like an attacker, not a checklist):**
- **AC1 (P0)** Cloud-native identity federation: no OIDC CI/CD trust-policy audit
  (`token.actions.githubusercontent.com` + broad `sub`), no IRSA/workload-identity (SA-token →
  `AssumeRoleWithWebIdentity` → cloud creds), the SSRF→IMDSv2→role→credential chain never actually walked,
  no cloud-credential pivot from a shell. This is *the* dominant modern cloud escalation path, shallow/absent
  in all three relevant skills at once.
- **AC2** Supply-chain/CI-CD: no dependency-confusion (internal package names resolvable on public
  registries), no `.github/workflows` review (`pull_request_target`, unpinned action SHAs, OIDC trust), no PPE.
- **AC3** SAML/enterprise-SSO/SCIM entirely absent (XSW, `<ds:Signature>` stripping, golden SAML, SCIM
  `active=true` flips); JWT shallow everywhere (no `kid`/`jku`/`x5u`/`jwk`).
- **AC4** Client-side largely missing (WebSocket/CSWSH, postMessage, DOM clobbering, client-side PP gadgets,
  CSP *bypass* not just grading, CSTI).
- **AC5** Auth-recovery flows: password-reset poisoning, magic-link abuse, passkey/WebAuthn attacks, auth-specific races.
- **AC6** ai-redteam misses agentic vectors: multi-agent trust/privilege boundaries, write-side memory
  poisoning, first-class indirect/second-order injection, excessive-agency chain hunting.
- **AC7/AC8** Modern escape depth (cgroup-v2, CVE-2022-0492, userns, admission/Falco *bypass* not just
  detection) and transport depth (H2 desync, single-packet race, modern WCD, GraphQL alias auth-brute);
  `/pivot-tunnel` is advertised in README but the skill file doesn't exist.

### 5.4 Workflow & architecture

**AR-B1 (P0) — The flat coverage matrix is the wrong central model.** The central object is a list of
`(endpoint_id, param, injection_type, status)` cells; the entities that actually drive a pentest — hosts,
services, creds/tokens, users, files, findings, chains, trust boundaries — live in separate stores joined by
string IDs at read time. A grid can't express reachability ("this token authenticates that endpoint"), data
flow, or blast radius — so value-ranking, reachability-aware re-planning, finding prioritization, and chain
discovery are all *impossible to do deterministically* and get dumped on the LLM. Fix: a shared world-model
**graph** (nodes Host/Service/Endpoint/Param/Credential/Token/Finding/Chain; edges hosts/authenticates/
reaches/leaks/escalates_to/tested_for); the matrix becomes a *view*. This is the Neo4j migration already in
the project's plans — five reviews independently point here. Cx high · high · **both** · **P0**.

**AR-B2 (P1) — The deterministic/model responsibility split is inverted.** The system deterministically fans
a 700-cell matrix and emits one canned payload per class, while leaving chain composition, prioritization,
re-plan triggers, and semantic dedup to the model. It maximizes model bookkeeping load and under-uses the
machine for the graph reasoning it's good at. Fix: move chain discovery/value-ranking/dedup/re-plan triggers
into a deterministic planner over the AR-B1 graph; move payload *breadth* back to skill/data libraries the
model selects from. Let the model do judgment, not accounting. Cx high · high · **both** · P1.

**AR-B4 (P1) — Static applicability table over-fans the matrix.** `taxonomy.APPLICABILITY` fans `query/default`
into 9 injection types for *every* string param regardless of name — a `redirect_uri` gets sqli/xss/ssti cells;
a `q` gets ssrf/redirect cells. This is the root cause of 700-cell matrices and the whole floor-vs-integrity
arms race. Fix: name-aware param classifier (`redirect_uri`→{redirect,ssrf}; `file|path|template`→{traversal,
ssti,lfi}; `q|search`→{sqli,xss}). Cuts matrix 3-5×, raises hit-rate. Cx med · high · **both** · P1.

**AR-B9 (P1) — Attacker-controlled strings enter control-plane prompts unfenced.** `_concrete_next_call`
correctly fences endpoint/param values with `<<UNTRUSTED>>…<<END>>` (the team knows the risk), but finding
titles, escalation leads, and gate `trigger` strings are injected into summaries/directives unfenced. In a
pentest the target is adversarial; a crafted error message filed as a finding title could inject instructions
into Smith's steering channel. Fix: one `fence()` helper applied to *all* target-derived substrings. Cx low ·
med · **both** · P1.

**Workflow:** WF-A1 value-rank endpoints (**P0**, 1-function change); WF-A2 cyclic phases (stop the drift
warning that punishes re-recon); WF-A3 event-driven re-planning on `known_assets` deltas; WF-A4 payload ladder
vs one canned string; WF-A7 redefine "complete" as high-value-surface-covered + leads-resolved, not % of a
mechanical grid. Also AR-B3 graph-derived chain discovery, AR-B5 split god-module + typed Blocker registry,
AR-B6 envelope pipeline + templated prompts, AR-B7 declarative skill manifest, AR-B8 consolidate the ~7 JSON
stores.

### 5.5 Small-model optimization (the spine)

**SM-1 (P0) — Context-pressure meter counts only ~10% of the window.** `core/session/__init__.py:434-449`
charges only envelope response chars; it never counts the system prompt, CLAUDE.md (~25 KB), the loaded
SKILL.md (up to 44 KB), history, or model reasoning. Tier warnings fire off a number 5-10× too low → a 27B
model silently overflows and the server hard-rejects *before* the recovery directive ever fires. Fix: seed the
counter with fixed overhead + skill size at `set_skill`; approximate input tokens per turn; compute against the
*measured* window. Cx med · high · **both** · **P0**.

**SM-2 (P0) — Profile keyed off env-name strings, not the measured window.** The installer already queries the
live model server for its true window (`install_opencode.sh:166-219`), but `model_detect.py:80-99` picks the
profile from env-var model-name matching and falls to `full` when no name is present — so a local 27B behind a
generic OpenAI-compatible proxy runs under `full` (400 K-char budget, coverage hard-gated) and overflows
immediately. Fix: persist the detected window and resolve profile from it (≤~48 K→small, ≤~128 K→medium)
ranking above the name guess; derive budgets from the window. Cx med · high · **both** · **P0**.

**SM-3/4/5 (P1) — The mechanical-work spine.** Skills are 30-44 KB prose with no condensed variant (SM-3) →
loading one eats ~70% of the small budget before any state exists → the model loses the workflow mid-task.
OpenAPI→coverage fan-out is a manual per-operation transcription (SM-4) small models fumble. `enforce_coverage`
is *off* for small/medium (SM-5) so quality *degrades* on the models the project wants to support. Fixes:
condensed per-phase skill variants the planner feeds turn-by-turn; a server-side `import_openapi`/
`import_graphql` action; a server-side `endpoint_sweep` that runs the probe ladder and pre-fills closures →
then flip `enforce_coverage` on. *These are the single biggest small↔frontier quality-gap closers and cut
frontier token cost too.* Cx high/med/high · high · **both** · P1.
*(Also SM-6 trim CLAUDE.md + alias tool names so no translation is needed, SM-7 deterministic entry-skill
selection, SM-8 decouple profile knobs from param-count, SM-9 promote 80% recovery to a `required` obligation,
SM-10 system-driven test→close loop, SM-11 re-evaluate profile on resume/model-swap.)*

---

## 6. What to keep (do not rewrite)

The reviews were unanimous that these are well-built and should survive the redesign:
- **Envelope artifact/asset extraction + budgeting** (the JWT/credential auto-extract, artifact_raw escape hatch, cost/token plumbing).
- **Discovery-layer enrichment** (host-side OpenAPI fan-out, JS route mining, liveness probing) — extend it (auth, GraphQL, forms), don't replace it.
- **Closure-integrity gates** (artifact-backed cell closures, 401/403 rejection, proven-chain `transition_artifact_id` validation) — these are the honesty backbone.
- **One-concrete-call recovery brief** and the one-blocker-at-a-time completion surfacing — exactly right for small models.
- **The pattern-teaching skills** (business-logic, post-exploit, codebase) — use them as the template for refactoring the runbook skills.

---

## 7. Recommended sequencing (tl;dr for the team)

1. **Ship Phase 0 quick wins now** (WF-A1, SP-1, SP-11, AR-B4, CH-2/7/10, AR-B9, SQ4) — each is low-complexity
   and fixes demonstrable loss; no redesign needed.
2. **Build the small-model spine + server-side sweep/import (Phase 1)** — these are correctness fixes
   (SM-1/2) plus the mechanical-work offload (SM-4/5) that closes the small↔frontier gap and enables honest
   coverage enforcement everywhere.
3. **Commit to the knowledge-graph core (Phase 2)** — it's the keystone that makes value-ranking, adaptive
   re-planning, and graph-derived chains deterministic instead of model-hoped-for. Align with the existing
   Neo4j plan.
4. **Then expand reasoning-first skills + attack coverage (Phase 3)** — shared refs layer first (SQ1),
   then the net-new skill categories (AC1 cloud-identity is P0).

**North star:** every discovery becomes a graph node; every graph edge the system can traverse becomes a
deterministic follow-up the model doesn't have to remember; the model spends its budget on *judgment and
exploitation*, not on bookkeeping. That is what makes a 27B run look like a frontier run — and makes the
frontier run cheaper and deeper.
