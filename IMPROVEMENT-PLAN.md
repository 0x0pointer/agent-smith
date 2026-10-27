# agent-smith — Improvement Plan (DRAFT, pending review)


---

## 1. DEPTH=DANGER / DEEP-PIVOT — post-run punch list  (branch: `feat/depth-danger-pivot`)

Forensic review of danger run `a6d82e2d` (target `http://178.62.209.70:30081`, 107 findings /
57 crit / 30 high). **The two headline mechanisms are validated as working** and should ship:
gate **re-open-on-contradicting-evidence** fired twice (`post_exploit_rce` on a confirmed code-exec
primitive; `internal_network` on an SSRF finding → chained `container-k8s-security → network-assess`)
and **internal-host promotion + completion-block** fired (promoted `kubernetes.default.svc.cluster.local`,
blocked `complete` until scanned). The pivot produced real crit findings (SSRF→K8s API, SQLi
`pg_read_file`→K8s ServiceAccount token→authenticated K8s API). The items below are the gaps that
review exposed — fix before merge.

**Review correction (2026-10-27):** this punch list was re-scoped after a careful second pass.
Changes from the first draft: old **1.2 + 1.3 merged** (one root cause — an unsafe mid-run
`session.start()`); old **1.4 rewritten** (its "exclude the discovered 10.x bridge net" would blind
genuine 10.x / 172.16 targets); old **1.1 rescoped** to thin attribution stubs and **sequenced after**
the tunnel primitive (its cells are untestable until a route exists); old **1.5** gets a lean
skill-prose v1 before the full subsystem; old **1.6** reframed to build on the completion blocker that
already exists rather than add a second gate.

**Meta-concern (applies to every item):** memory `agent-smith-depth-regression` records that
*machinery accretion* is what regressed depth last time (core files 10→92; the lean mandatory-chain
skills out-found the new matrix/gate structure). `core`+`mcp_server` are now **185 `.py` files**. So
the bias is explicit: prefer a **guard / skill-prose / reuse-an-existing-engine** fix over a new
subsystem. Three of the five items below collapse to lean correctness fixes; the two that add
machinery (tunnel primitive, synthesis engine) are kept thin and staged.

**Execution order (dependency-correct):**
`1.1 safe re-init` → `1.2 own-IP exclusion` → `1.3 tunnel (lean v1)` → `1.4 matrix stubs` → `1.5 synthesis`.

### 1.1 Unsafe mid-run `session.start()` re-init wipes live state  [effort S]  ← **do first (correctness)**
*(merges draft 1.2 "operator-FYI missing" + draft 1.3 "target/depth/known_assets clobbered" — one root cause)*
Commit `8fa49d7` made `session.start()` **clear the wishlist** on a new scan; `start()` also resets
`target`/`depth` and empties `known_assets`. So when an MCP supervisor flap / "make it live" restart
re-issues `session.start()` **mid-run**, it silently: (a) **wipes the wishlist** — which is why the
deep-pivot operator-FYI (`_notify_operator_pivot`, `core/pivot.py:136`) left **0 wishlist items**
(draft 1.2 wasn't a dropped notify, it was a wiped store); and (b) resets `target` → last-promoted
pivot host, `depth` → default `thorough`, and empties `known_assets.ips/domains` (draft 1.3) — while
`gates` / `skill_history` / `surface_coverage` / 107 findings reload intact and danger-shaped. The
dashboard then reads as "scanning kubernetes.default on depth=thorough" when the real danger run is on
the app.
- Evidence: `session.json` `target=kubernetes.default.svc.cluster.local`, `depth=thorough`, empty
  `known_assets`, yet 2 reopened gates + danger-shaped skill_history + 107 findings; commit `8fa49d7`
  (`session.start()` → wishlist clear); **0** wishlist items, **0** `"Deep-pivot ACTIVE"` lines in
  `pentest.log` + event streams.
- Fix (one guard, not three): make `session.start()` **idempotent / safe when a live scan already
  exists** — if a running session with this id/target is on disk, **resume** it (don't re-init, don't
  wipe wishlist / known_assets, never overwrite `target` / `depth`). Find who re-issues `start`
  without `depth=danger` (watchdog / opencode respawn — see memory
  `spawn-auth-subscription-vs-api-credit`). Regression test: a restart/resume mid-danger-run preserves
  `target`, `depth`, `known_assets`, and the wishlist unchanged.

### 1.2 Scanner-infra over-promotion — exclude the scanner's OWN resolved IPs, never a CIDR  [effort S]
*(rewrites draft 1.4 — its "exclude the discovered 10.x bridge net" is dangerous and must NOT ship)*
`_scanner_infra_ip` (`core/netextract.py`) excludes only `172.17/16`, `172.18/16`, `192.168.65/24`,
so a Docker bridge in `10.0.0.0/8` slips through and the **Kali container's own IP gets promoted as an
"internal host"** (pentest.log L1320 `promoted … 10.110.0.3`; L1462 "the Kali container's own IP …
not an internal host").
- **Why the draft fix is wrong:** excluding the `10.x` bridge *net* would blind genuine targets —
  `netextract.py:48` deliberately keeps a corp `172.16/12` LAN scannable, K8s pod CIDRs **are** 10.x,
  and `tests/test_gate_reopen_on_evidence.py` uses `10.44.0.9` / `10.44.0.22` as *real* internal hosts.
  A CIDR exclusion would suppress exactly the hosts danger exists to find.
- Fix: at runtime resolve the **Kali container's own interface addresses** (`ip -o addr` /
  `hostname -I`) and exclude **exactly those addresses** (a /32 set), never a range. Keep the test that
  the scanner's own IP is never promoted — and add one asserting a genuine `10.x` / `172.16.x` host IS
  still promoted.

### 1.3 Pivot/tunnel primitive — ship a lean skill-prose v1 first  [effort M (v1) / L (full)]
*(rescopes draft 1.5)* Even with a confirmed RCE/shell there is no first-class way to stand up a SOCKS
tunnel through the foothold, so internal recon degrades to per-request SSRF-GET relay + curl (what
forced the (B)-phase improvisation in `a6d82e2d`). The design already *expects* tunneling
(`pivot_reachable()`, `core/pivot.py:74`, + the deep-pivot blocker say "tunnel through the foothold
first") but there's **no implemented path** (tunnel tooling = 0 occurrences in `pentest.log`).
- **Caveats the draft missed:** nmap over SOCKS must be `-sT` (connect) — raw `-sS` SYN can't traverse
  a SOCKS proxy; the tunnel agent is a **persistence artifact** needing teardown; it must be
  **opt-in / fail-soft and never a completion gate** (else no-shell targets stall); inbound tunnels
  raise egress/attribution concerns — lab-only.
- **Lean v1 (do this first, per the meta-concern):** add the chisel / ligolo-ng / msf
  `autoroute`+`socks_proxy` recipe to `/post-exploit` + `/lateral-movement` **skill prose**, plus a
  `proxychains`-wrap option on `kali()`. The model can then hand-drive pivot scans through the tunnel —
  most of the value, little new machinery.
- **Full v2 (only if v1 proves insufficient):** a primitive that consumes a shell/RCE artifact,
  deploys+manages the SOCKS endpoint, and registers its address so `scan()` / `kali()` transparently
  route through it. Prereq for 1.4's internal endpoints to be real scan surfaces.

### 1.4 Pivot hosts enter the matrix as thin attribution stubs  [effort S–M]  ← **after 1.3**
*(rescopes draft 1.1 — "top priority" was wrong: full cell fan-out before a route exists is harmful)*
Deep-pivot promotes a host into `known_assets` + the surface-coverage ledger + the `internal_network`
gate, but **nothing registers the reached endpoints into the coverage matrix under the new host**, so
the two systems diverge (ledger marks `kubernetes.default…` "covered"; matrix has **0 endpoints / 0
cells** for it — all 64 endpoints / 1125 cells carry `host=178.62.209.70:30081`; `"cluster.local"`
appears 0 times). That is the operator complaint "it's not clear which endpoint belongs to which host"
— in the matrix everything is one host. The K8s API ops the agent hit (`/api/v1/namespaces/.../pods|
secrets|configmaps`, `/version`, `/api/v1/nodes` — pentest.log L13733/L14048/L29803) are not rows.
- **Why NOT full fan-out (the draft's trap):** `_fan_out_cells` fans per-param injection cells **plus**
  always-on cross-cutting cells regardless of host type. Fanning a K8s-API host that way = a wall of
  mostly-N/A cells → trips QA `NA_ABUSE>30%` (memory `feedback_artifact_reuse`) and, on the full
  profile, raises the completion bar. Worse, the host-scan blocker (`completion_gates.py:116`) **fires
  on every profile**, so an *unreachable* pivot host with registered cells **hard-stalls `complete`**
  unless marked `documented-unreachable`.
- Fix (thin): register the host + the endpoints the pivot actually touched (`/api/v1/*` for a K8s API,
  or an `import_openapi` pull when reachable) as **attribution stubs with no injection fan-out** — host
  becomes attributable, matrix stays honest, no NA bloat. Mark an unreachable pivot host
  `documented-unreachable` so the host-scan gate doesn't stall. Fan out testable cells **only once 1.3
  can route to it**. Schema is already host-aware (`endpoint.host`; `_default_matrix_host`; host filter
  on `list_cells`) — it's just never fed a 2nd host.

### 1.5 Synthesis: feedback-first, reuse the lead-blocker that already exists  [effort M–L]
*(reframes draft 1.6)* **Symptom:** Phase C ("compose everything into proven chains + maximal
terminals") produced **0 new findings / 0 new chains** after the operator advanced to synthesis
(Oct 27 13:53), ~32 http/curl calls, stuck in sticky `SKIP_TOOL` curl-only HIRs; chain-building
actually happened earlier (Phase A on Oct 24 + the Oct-27-morning coverage window), so synthesis ran in
the wrong phase and Phase C degraded to a completion wind-down. The Deepen-next worklist isn't drained:
**31 findings still carry non-empty `escalation_leads`**, and on Oct 25 the model got **93
`type:suggest` candidates and dismissed them wholesale** ("REDUNDANT … no new provable bridges remain")
— one self-certified exhaustion. `core/graph/chains.py:3`: *"the kill chain is today 100%
model-declared … we only propose, never assert."*
- **What already exists (don't rebuild):** `_escalation_lead_blockers` (`completion_gates.py:46`)
  **already blocks `complete` on pending escalation_leads** — the enforcement layer is there. Its gap is
  that the model can self-resolve a lead to clear it, and it forces *follow-up of existing* leads, not
  *discovery* of new chains. So do **not** add a second synthesis gate: a gate without a mechanical
  sweep is the coverage gate that *games-then-stalled twice* (memory `coverage-gate-profile-aware`), and
  the coverage gate only works because `type:sweep` does the mechanical part — there is no "synthesis
  sweep" yet.
- **Fix — engine-first, lead with feedback:**
  - **Feedback-into-coverage (the load-bearing half — generalize `core/escalation.py`):** a synthesized
    primitive (cracked JWT secret, stolen SA token, file-read) **re-opens the relevant gate / registers
    the newly-reachable surface *during* exploitation** — synthesis becomes continuous, not terminal.
    Also fix the phase model so Phase C isn't a late operator-gated afterthought (B→C was operator-gated
    this run, which is why synthesis started at 13:53 while the model had done chain-work earlier).
  - **Synthesis sweep (analog of `type:sweep`):** deterministically attempt the cheap high-certainty
    bridges the graph implies — credential/secret reuse (cred X → every other service),
    stolen-token-against-API, `pg_read_file` reached `/var/run/secrets` → use the token — prove +
    auto-file the chain. Must **respect `rate_limits`** (today write-only — TIER 2.1) and engagement
    scope before any cred-spray. Feeds off 1.3 (pivot) + TIER-3 **D4** (cred×service matrix).
  - **Novelty-ranked proposer** (not a 93-item dump): rank `suggest` candidates by whether they reach a
    node / terminal / data-class **no filed chain reaches**; surface only the genuinely-new bridges.
  - **Adversarial dismissal check:** when the model marks a candidate dead/redundant, verify
    deterministically it reaches no unreached terminal; re-surface it if it does (don't trust the prose).
  - **Soft signal only:** surface a non-blocking "synthesis-debt" summary (unresolved `escalation_leads`
    + untried novel chains + untouched Deepen-next) via the existing `_escalation_lead_blockers` +
    `qa_alerts` channel — one operator/QA-reviewable adjudication, never a new hard `complete` block.
  - **Operational:** fix the degraded Phase C (sticky `SKIP_TOOL` curl-only HIR) — synthesis can't run
    regardless of design while the agent is restricted to curl.

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
- **Auto-generated onboarding SKILL.md** for external agents from the live tool list (low pri).

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

