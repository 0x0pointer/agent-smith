# Plan — `depth=danger` + deep post-exploit pivot

> Status: APPROVED FOR BUILD (decisions locked 2026-10-17). Branch: `feat/depth-danger-pivot` off `main`.
> Author: design review with operator. Reviewers: operator + Ricco.

## Motivation

In scan `db972fee` (`178.62.209.70:30081`) the agent used SSRF/SQLi-RCE to pivot into an
internal Kubernetes cluster — K8s API `10.110.32.1:443`, a Flask app pod `10.150.0.158:5000`,
postgres pod, and ~6 more `10.x` IPs — but **never scanned any of them**. Every tool action
targeted either `kali` or the perimeter host. Root cause (confirmed in code):

- **No IP promotion:** nothing ever writes `known_assets.ips`. SSRF-discovered IPs live only in
  the graph-visualization layer (`core/graph/build.py:310`), never become assets or coverage.
- **Endpoint-only, host-agnostic coverage:** the matrix has no host primitive; `meta.target` is a
  single scalar; endpoints carry no host and dedup on bare path (so hosts collide).
- **Advisory-only per-host tracking:** the surface ledger has a `host` unit but it only nudges;
  nothing blocks completion, and it's fed from `known_assets.ips` which is always empty.

So "pivot deeper" is a **build**, not a flag flip. This plan adds an opt-in aggressive mode.

## Locked decisions

1. **Normal scans (standard/thorough):** on internal-host discovery, raise a **wishlist `scope`
   item** ("approve pivot-scanning?") — do NOT auto-scan.
2. **Coverage:** Phase-2 **ledger-gate** now; defer the Phase-3 host-aware matrix.
3. **`danger` keeps HIR / human-in-the-loop** (it's a pentest-mode depth). Separately: **fix
   benchmark to actually suppress the self-resolvable HIRs** (today the docstring claims it does,
   the code doesn't).
4. **Per-host scan recipe:** naabu/nmap top-ports → httpx → nuclei; if a web service is found →
   spider + a capped set of endpoints. **No host cap in `danger`** (operator opted in to the blast
   radius). Benchmark: same, no cap.
5. **Branch:** `feat/depth-danger-pivot` off `main`.

## Design backbone — two predicates

Add to `core/session/__init__.py` (beside `PRESETS` / `_TRIGGER_MAP`), to avoid scattering literals:

- `THOROUGH_LIKE = {"thorough", "danger"}`; `is_thorough_like(depth) -> depth in THOROUGH_LIKE`
  — replaces every `== "thorough"` / `in ("standard","thorough")` consumer so `danger` inherits
  all thorough behavior.
- `deep_pivot_enabled(session) -> session.get("depth") == "danger" or session.get("scan_mode") == "benchmark"`
  — the single gate for all *new* pivot behavior; reaches both `danger` (pentest) and `benchmark`
  without coupling the two independent fields.

---

## Phase 1 — the `danger` depth classifier (== thorough)

1. **Preset** — `core/session/__init__.py:65` (mirror thorough's unlimited limits):
   ```python
   "danger": {
       "label":       "Danger (thorough + deep pivot)",
       "description": "Thorough + autonomous internal-host pivot after SSRF/RCE "
                      "(promote discovered hosts, port-scan + re-run recon/web/api per host)",
       "max_cost_usd":     None,
       "max_time_minutes": None,
       "max_tool_calls":   0,
   },
   ```
2. **Thorough-like propagation** — swap literal checks for `is_thorough_like(depth)` at:
   - `mcp_server/session_tools/complete.py:203` — routes to `_thorough_gate` (3 mandatory passes; the thing that stops auto-complete)
   - `mcp_server/session_tools/blocker_response.py:143`
   - `mcp_server/session_tools/recovery_build.py:10`
   - `core/qa_agent/checks_depth.py:233,265` — white-box passes / premature-complete block
   - `core/qa_agent/checks_skills.py:97` — business-logic directive
   - `mcp_server/report_tools/gates.py:84,162` — credential-audit gate (`in ("standard","thorough","danger")`)
   - `mcp_server/scan_engine/envelope/pressure.py:81` — checkpoint cadence
   - `mcp_server/session_tools/__init__.py:190` — enum doc string (`recon|standard|thorough|danger`)

   *After Phase 1, `depth=danger` is behaviorally identical to `thorough`.*

---

## Phase 2 — deep-pivot behavior (gated on `deep_pivot_enabled`)

### 2a. Promote discovered internal hosts to assets *(the missing primitive)*
- New shared util `core/netextract.py` — lift `_IP_RE` / `_internal_ip` (RFC1918) / `_hosts_in_text`
  out of `core/graph/build.py:310-399` so the graph and the new promotion share one implementation.
- New hook `_promote_internal_hosts(...)` in `mcp_server/scan_engine/envelope/assets.py` (beside
  `_extract_and_persist_assets:258`): when `deep_pivot_enabled`, scan finding evidence + HTTP/SSRF
  tool output for internal IPs and call `update_known_assets("ips", [...])`. This single write
  cascades: `_host_instances()` (`core/session/assets.py:143`) picks them up.

### 2b. Drive per-host scanning via the surface ledger *(lean; reuses existing machinery)*
- `core/session/surface_ledger.py:46` (`SKILL_UNITS`) — add `network-assess` to the **`host`** unit
  (today only post-exploit / reverse-shell / lateral-movement map to `host`).
- `core/session/assets.py` — extend `_ledger_record_assets:191` so adding `ips`/`domains` records
  host instances for host-unit skills (today only `_ledger_record_creds` records hosts, on creds).
- Auto-open the existing `internal_network` gate (`mcp_server/report_tools/gates.py:143`) directly on
  IP promotion, instead of depending on the agent writing a keyword note.

### 2c. Block completion while internal hosts are unscanned *(the actual fix)*
- Under `deep_pivot_enabled`, flip the ledger `host` unit from advisory → **blocking**:
  `mcp_server/session_tools/complete.py` / `coverage_gates.py` emit a completion blocker when there
  are promoted internal hosts with no per-host scan recorded. This prevents "Phase A exhausted while
  10 internal hosts unscanned."

### 2d. Per-host scan recipe
When a promoted internal host is pending, the agent (driven by the start norm + escalation directive)
runs, per host: **naabu/nmap top-ports → httpx → nuclei**; if a web service is found →
**spider + a capped set of endpoints** registered host-qualified (full-URL path, see Phase-3 note).
The ledger `host` unit is marked covered once a port-scan tool has fired against that host
(`attribute_covered`, `surface_ledger.py:256`). **No host cap** in danger/benchmark.

### 2e. Generalize the exploit-escalation push to `danger`
- `core/qa_agent/checks_health.py:279` — change guard from `scan_mode != "benchmark"` to
  `not deep_pivot_enabled(session)`.
- Enrich the directive (`:308`) to name the behavior: *"promote the discovered internal host(s),
  tunnel via kali(), and run naabu/nmap → httpx → nuclei (+ spider if web) against each — do not stop
  at the finding."*

### 2f. Agent norm at start
- `mcp_server/session_tools/start.py:59` — add a deep-pivot instruction block (sibling to the
  benchmark block) when `deep_pivot_enabled`: the pivot → promote → per-host-scan loop + tunnel
  patterns (chisel / ssh SOCKS + proxychains, `skills/network/lateral-movement/SKILL.md:399-424`).

### 2g. Scope-safety split *(pentest-vs-danger difference)*
- **Non-deep-pivot** pentest (standard/thorough): on internal-host discovery raise a **wishlist
  `scope` item** ("found N internal hosts via pivot — approve scanning?") via `core/wishlist.py`
  (`category="scope"`), NOT auto-scan. (Scope is advisory-only today — `core/quick_log.py:93` — and
  internal IPs aren't blocked — `http_tools.py:85` — so the wishlist is the control that keeps normal
  scans conservative.)
- **Deep-pivot** (danger/benchmark): auto-promote + scan, still honoring the `out_of_scope` list, **no
  host cap**.

### 2h. Fix benchmark HIR suppression *(new workstream)*
Today `_hir()` (`core/qa_agent/hir.py:14`) "always fires regardless of scan mode" — the
`lifecycle.py:67` claim that benchmark = "no HIR triggers" is false, and `daemon.py:76`'s "suppressed
in benchmark" comment is aspirational.
- **Fix:** in `_hir()`, when `scan_mode == "benchmark"`, suppress the **self-resolvable QA-daemon
  HIRs** — `HIR_AUTH_FAILURE`, `HIR_BUDGET_LIMIT`, `HIR_NO_ENDPOINTS`, `HIR_TARGET_UNREACHABLE`,
  `HIR_REPEATED_TOOL_FAILURE`, `HIR_STUCK_ON_TARGET` — converting each to a non-blocking steering
  nudge ("continue autonomously; <original guidance>") instead of pausing the scan.
- **Keep** the watchdog-level events (`HIR_NO_PROGRESS` `smith/progress.py`, `HIR_POLICY_REFUSAL`
  `smith/refusal.py`) — those are about a dead/refusing process, not pentest judgment, and benchmark
  still needs respawn-on-death. *(Flag for review: confirm these two stay on in benchmark.)*
- `danger` is explicitly **unaffected** — it keeps all HIRs (human-in-the-loop).

---

## Phase 3 — deferred (not in this build)

True host-aware coverage: extend `core/coverage/operations.py:108` endpoint model with a
`host`/`base_url` field + dedup key + `_recount`, so internal web apps (e.g. the `10.150.0.158:5000`
Flask pod) get real per-host matrix cells. Deferred — Phase 2's ledger-gate already gives
"each host gets scanned and blocks completion" without this invasive change. Until then, per-host web
endpoints are registered with host-qualified full-URL paths (which survive `_normalize_path` and so
disambiguate).

---

## File-by-file change list

| File | Change | Phase |
|---|---|---|
| `core/session/__init__.py` | add `danger` preset; `THOROUGH_LIKE`, `is_thorough_like`, `deep_pivot_enabled` | 1 |
| `mcp_server/session_tools/complete.py` | `is_thorough_like`; ledger host-blocker under deep-pivot | 1,2c |
| `mcp_server/session_tools/blocker_response.py` | `is_thorough_like` | 1 |
| `mcp_server/session_tools/recovery_build.py` | `is_thorough_like` | 1 |
| `mcp_server/session_tools/__init__.py` | enum doc `…|danger` | 1 |
| `mcp_server/report_tools/gates.py` | credential-audit gate + danger; `internal_network` gate on IP promotion | 1,2b |
| `mcp_server/scan_engine/envelope/pressure.py` | `is_thorough_like` | 1 |
| `core/qa_agent/checks_depth.py` | `is_thorough_like` (2 sites) | 1 |
| `core/qa_agent/checks_skills.py` | `is_thorough_like` | 1 |
| `core/netextract.py` (new) | shared IP/host extraction (refactor from `graph/build.py`) | 2a |
| `core/graph/build.py` | import extraction from `netextract` (no behavior change) | 2a |
| `mcp_server/scan_engine/envelope/assets.py` | `_promote_internal_hosts` under deep-pivot | 2a |
| `core/session/assets.py` | `_ledger_record_assets` records host instances on ips/domains | 2b |
| `core/session/surface_ledger.py` | `network-assess` → `host` unit; blocking flag for deep-pivot | 2b,2c |
| `mcp_server/session_tools/coverage_gates.py` | deep-pivot host-coverage completion blocker | 2c |
| `core/qa_agent/checks_health.py` | escalation guard → `deep_pivot_enabled`; enriched directive | 2e |
| `mcp_server/session_tools/start.py` | deep-pivot norm block | 2f |
| scope-discovery hook (envelope/assets or a new checker) | non-deep-pivot → wishlist `scope` item | 2g |
| `core/qa_agent/hir.py` | benchmark suppresses self-resolvable HIRs | 2h |
| `core/session/lifecycle.py` | fix the `scan_mode` docstring to match reality | 2h |

## Testing

- **Unit:** preset present; `is_thorough_like` / `deep_pivot_enabled`; `danger` routes to the thorough
  gate; `_promote_internal_hosts` extracts internal IPs → `known_assets.ips`; ledger host instances go
  pending on IP add; completion blocked under deep-pivot with pending hosts; escalation fires under
  `danger`; benchmark suppresses the 6 daemon HIRs but not watchdog ones.
- **Regression (critical):** standard/thorough behavior UNCHANGED — no auto internal scanning; a
  wishlist `scope` item is raised instead; `danger` keeps all HIRs.
- **Scenario replay:** the db972fee case (SSRF → 10.x) under `danger` → hosts promoted,
  `internal_network` gate opens, completion blocked until per-host scans recorded.

## Safety

Internal pivot-scanning is aggressive and legitimate only on authorized labs. It is gated behind
explicit `danger`/`benchmark` opt-in, honors `out_of_scope`, and is never auto-enabled for
standard/thorough (those get a wishlist approval request). Ports/dashboard stay loopback-only.

## Build order

1. Phase 1 (preset + predicates + propagation) — self-contained, low risk, land + test first.
2. Phase 2a→2b→2c (promotion → ledger host unit → completion blocker) — the core capability.
3. Phase 2d→2f (recipe wiring, escalation, start norm).
4. Phase 2g (scope wishlist for normal scans).
5. Phase 2h (benchmark HIR suppression) — independent; can land in parallel.
