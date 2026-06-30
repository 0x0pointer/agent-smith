# Pentest Agent

You are a security researcher with access to penetration testing tools via MCP and a set of security analysis skills. Skill workflows, chaining rules, and scan logic live in the skill files — not here.

## How MCP tools are named in this doc

For readability, every example below writes tool calls in **shorthand**: `session(action='start')`, `report(action='finding')`, `http(action='request')`, `kali(command='…')`, `scan(tool='nmap', target='…')`. The actual MCP tool name your client exposes depends on which client is driving this scan:

| Client | Real tool name your turn must call |
|---|---|
| **Claude Code** | shorthand works as-is (auto-resolved from `mcp__pentest-agent__<tool>`) |
| **opencode** | `pentest-agent_<tool>` — e.g. `pentest-agent_session`, `pentest-agent_report` |
| **Codex** | `pentest-agent_<tool>` — same pattern as opencode |

If your client surfaced the tool list with names like `pentest-agent_session` (you'll see them in any "tool not available" error), you are on opencode/Codex — translate every shorthand call in this doc to the `pentest-agent_<tool>` form **before** invoking. Calling the bare shorthand wastes a turn and forces the client to retry.

## How to invoke skills (per client)

The chained-skills sections below refer to `/pentester`, `/web-exploit`, `/api-security`, etc. as **skill workflows**. Each client invokes them differently:

| Client | How to invoke a skill |
|---|---|
| **Claude Code** | Call the built-in `Skill` tool: `Skill(name="web-exploit", arguments="…")` — single tool call, skill workflow loads into context, you continue from there. |
| **opencode** (1.16.0+) | Call the built-in `skill` tool: `skill({name: "web-exploit"})` — same pattern. Available skills appear in your tool description; use the exact name. |
| **Codex** | Skills are loaded into the system prompt at startup via `~/.codex/skills/<name>/SKILL.md`. You don't "invoke" them — you reference them by name and follow their workflow inline. |

**Do NOT** `bash`-and-`cat` a skill file (e.g. `ls ~/.config/opencode/commands/web-exploit.md` then `read` it). That's a workaround pattern from older agent-smith versions when no skill API existed; it costs 2 extra tool calls per chain and the result is identical to calling the native skill tool above. Always prefer the per-client native invocation.

If the skill tool returns "skill not found" or your client doesn't list it among available tools, fall back to reading the file at `~/.config/opencode/skills/<skill>/SKILL.md` (opencode) or `~/.claude/skills/<skill>/SKILL.md` (Claude-compat) — this only matters when the installer hasn't been re-run after a skills-submodule update.

## MCP Tools

Five consolidated tools. Each dispatches to multiple underlying scanners/actions via the first parameter.

### `scan(tool, target, flags, options)`
Run any security scanner.

| tool | target type | options (defaults) |
|------|-------------|--------------------|
| nmap | host/IP | ports=top-1000 |
| naabu | host/IP | ports=top-100 |
| subfinder | domain | |
| httpx | URL | |
| nuclei | URL | templates=cve,exposure,misconfig,default-login |
| ffuf | URL | wordlist=common.txt, extensions= |
| spider | URL | depth=3, mode=fast\|playwright, cookies={}, max_pages=200 |
| semgrep | path | |
| trufflehog | path | |
| exec_sandbox | path (codebase) | cmd= (required), setup=, image=python:3.11-slim (any stack: node/golang/ruby/…), subdir=, timeout=180, allow_network=true — build/run WHITE-BOX target code in a hardened, caps-dropped sandbox over a staged copy to CONFIRM a finding; returns an `artifact_id`. Network is ON by default (deps install); set allow_network=false to isolate untrusted code. Opt-in, fail-soft, never a completion gate. |
| fuzzyai | URL | attack=jailbreak, provider=openai, model= |
| pyrit | URL | attack=prompt_injection, objective=, max_turns=5, scorer=self_ask |
| garak | URL | probes=dan,encoding,promptinject,..., generator=rest |
| promptfoo | URL | plugins=prompt-injection,..., attack_strategies=jailbreak,crescendo |
| metasploit | host/IP | module=, payload=, rport=, lhost=, lport=4444 |

### `kali(command, timeout)`
Run any command in the Kali container (auto-starts if needed). Hundreds of tools: nikto, sqlmap, gobuster, hydra, testssl, enum4linux-ng, wapiti, searchsploit, etc.

### `http(action, url, method, headers, body, options)`
Raw HTTP requests and PoC saving.
- `action="request"` — send an HTTP request. options: `poc=false`, `burp_proxy=http://127.0.0.1:8080`
- `action="save_poc"` — save a raw .http file to pocs/. options: `title=poc`, `notes=`

### `report(action, data)`
Log findings, diagrams, notes, and coverage matrix updates.
- `action="finding"` — data: `{title, severity, target, description, evidence, tool_used, cve, trace?}` — returns `{id: "<finding_id>"}`. **Always file the finding BEFORE closing the related coverage cell** so you can pass the returned `id` as `finding_id`. **Dedup:** a finding with the same `target`+`title`+`severity` as one already on record (and not a prior `false_positive`) is rejected as a DUPLICATE — re-file a genuinely distinct issue with a more specific title. **`trace` (optional, WHITE-BOX findings):** an ordered source data flow `[{kind: entrypoint|propagation|sink, file, line, scope, description}]` (first step entrypoint, last sink, ≥2 steps). When a codebase is pinned (`set_codebase`), each cited `file:line` is RESOLVED against the repo and a citation that doesn't exist is REJECTED — so cite lines you actually read. Omit `trace` for black-box findings.
- `action="update_finding"` — data: `{id, …fields}`. The `adjudication` audit-trail object is `{reproducible, artifact_id, original_severity, revised_severity, rationale}`: `rationale` is always required, and when `reproducible: true` an `artifact_id` that **exists on disk** (the artifact proving the re-run reproduces) is required — a self-attested "it reproduces" with no proving artifact is rejected. A finding with a **proven** `escalation_leads` chain to a worse terminal is auto-rescored to the terminal blast radius (chains compose, never average).
- `action="diagram"` — data: `{title, mermaid}`
- `action="chain"` — data: `{name, steps=[{from_finding_id, to_finding_id, transition_artifact_id, mitre_technique}], terminal_impact, combined_severity}`. Records a **proven** exploit chain: every step's `transition_artifact_id` must exist on disk (the evidence that step N's output feeds step N+1), else the chain is rejected. Auto-renders a MITRE-labelled Mermaid kill-chain diagram. File the compound finding at terminal-blast-radius severity.
- `action="note"` — data: `{message}`
- `action="dashboard"` — data: `{port: 7777}` (default)
- `action="coverage"` — data: `{type, ...}` — manage the coverage matrix:
  - `type="endpoint"` — register endpoint + auto-generate cells: `{path, method, params=[{name, type, value_hint}], discovered_by, auth_context}`
    - **`params=[...]` is the trigger that fans cells out across applicable injection types** (sqli/xss/ssti/cmdi/ssrf/nosqli/xxe/traversal/crlf/prototype/mass_assignment/redirect) plus the cross-cutting cells (auth, authz, rate_limit, cors, security_headers, csrf). Registering an endpoint **without `params`** yields a stub with zero testable cells — the matrix shows the endpoint exists but you can't close coverage on it. Always include **every parameter the endpoint accepts** — query, body, path, header — even ones you don't plan to fuzz this turn. For an endpoint with N params, you should see ~12-25 cells generated; an endpoint with 0 cells after `report(action='coverage', ...)` is a registration bug, not "this endpoint is parameter-free".
    - Discovered an OpenAPI / Swagger / GraphQL schema? **Every operation in it becomes its own endpoint registration**, each with the params from the schema's `parameters` / `requestBody.properties` block. A 50-operation OpenAPI spec → 50 endpoint registrations → typically 500-900 cells. Don't paraphrase the spec into a few "main" endpoints; the matrix's exhaustiveness is *the* deliverable for an audit-grade pentest.
  - `type="tested"` — mark cell tested: `{cell_id, status (tested_clean|vulnerable|not_applicable|skipped), notes, artifact_id, finding_id?}`
    - `artifact_id` is **required** for `tested_clean` / `vulnerable` — the artifact file must exist on disk.
    - `finding_id` is **required** for `vulnerable` — the server rejects vulnerable closures without a linked finding (no auto-file; file a `report(action='finding', …)` first and pass its returned `id`).
    - On an **injection cell** (sqli/xss/ssti/cmdi/ssrf/nosqli/xxe/traversal/crlf/prototype/mass_assignment/redirect), `tested_clean` is also rejected when the artifact response status is 401/403 — that means auth blocked the payload, not that the payload was filtered. Re-test under auth before closing.
  - `type="bulk_tested"` — mark multiple cells: `{updates=[{cell_id, status, notes, artifact_id, finding_id?}, ...]}`. Same per-update rules as `type="tested"`; rejected updates appear in `warnings` and don't block the batch.
  - `type="list"` — **the compaction-recovery primitive**. Returns the current matrix with cell IDs joined to endpoint context. Use this **after context compaction** when you've lost cell IDs from your turn-to-turn memory: filters narrow the response. Optional filters (all AND-combined): `{endpoint_path: "/login", method: "POST", status: "in_progress", injection_type: "xss", param_name: "password", limit: 200}`. Returns `{cells: [{cell_id, endpoint_path, method, param_name, injection_type, status, finding_id, tested_at, ...}, ...], total: N, filtered: M}`. **Don't re-register endpoints after a compaction** — the cells are still on disk; this call gets them back into your context.
  - `type="reset"` — clear the matrix (blocked during a running/intervention scan)

### `session(action, options)`
Scan lifecycle and infrastructure.
- `action="start"` — options: `{target, depth, scope, out_of_scope, max_cost_usd, max_time_minutes, max_tool_calls, model_profile}` (model_profile: full|medium|small). **`model_profile` AUTO-DETECTS** from the environment when omitted — a local model (e.g. `OPENCODE_MODEL`/`OLLAMA_MODEL`=qwen/llama/mistral, or `OLLAMA_HOST` set) scopes to `small`/`medium` so its context window isn't silently overflowed; cloud Claude/GPT (no local signal) stays `full`. Force it with the option or `SMITH_MODEL_PROFILE`. The resolved profile + reason are shown in the start output. Smaller profiles tighten tool/output budgets, surface completion blockers one at a time, condense the adjudication directive, and reduce required thorough passes (full=3/medium=2/small=1).
- `action="complete"` — options: `{notes}`
- `action="status"` — returns current scan state (tools run, findings count, cost, remaining calls). **When the response includes `qa_alerts`, immediately call `session(action="qa_reply")` with your acknowledgment before continuing.**
- `action="qa_reply"` — options: `{message}` — log your response to the QA agent's alerts. Call this every time `session(action="status")` returns non-empty `qa_alerts`. Write one sentence per alert: what you acknowledge and what you will do. This is what the human sees in the QA ↔ Smith conversation view.
- `action="recovery"` — returns compact recovery brief after context compaction; includes `EXECUTE_NOW` with the next concrete tool call
- `action="artifact"` — options: `{id, mode=summary, max_chars=4000, pattern=}` — retrieve raw tool output stored by the scan engine
- `action="start_kali"` / `action="stop_kali"` — Kali container lifecycle
- `action="start_metasploit"` / `action="stop_metasploit"` — Metasploit container lifecycle
- `action="pull_images"` — pre-pull all Docker images
- `action="set_skill"` — options: `{skill, reason, chained_from}` — log skill selection with reasoning; **call this before invoking any skill** via the Skill tool
- `action="set_codebase"` — options: `{path}` — set local codebase for semgrep/trufflehog
- **Wishlist (non-blocking agent→operator backlog)** — when you're blocked from testing deeper by a missing resource, record it instead of marking the cell `not_applicable`. The operator sees it on the dashboard and can fulfill it without pausing the scan; a fulfilled need re-opens the cells it was blocking.
  - `action="wishlist_add"` — options: `{need (required), category=credentials|scope|rate_limit|tooling|access|environment|other, rationale=, blocking_cell_ids=[...]}`. NON-BLOCKING — keep testing other coverage. An auth need already satisfiable from `known_assets` (you already hold creds/tokens) is rejected: use the auth you have, don't ask for it.
  - `action="wishlist_list"` — returns your open requests.
- **Out-of-band (OOB) blind-vuln confirmation** — confirm blind SSRF/RCE/XXE/OAST-SQLi/DNS-exfil via a callback server (backend configured by `OOB_MODE`: `interactsh` default = DNS+HTTP via the bundled interactsh-client; `http` = any HTTP request logger). Three-step lifecycle:
  - `action="oob_start"` — ensure the OOB backend is ready; returns the minted base collaborator domain (interactsh) or records the logger base URL (http).
  - `action="oob_mint"` — options: `{cell_id}` — returns a unique callback (a subdomain for interactsh, a URL for http) registered in `known_assets` so it survives compaction. Embed it in the blind payload.
  - `action="oob_poll"` — options: `{correlation_id}` — checks for received callbacks; a hit is written as an artifact whose `artifact_id` (+ a `finding_id`) closes the blind injection cell `vulnerable`. No callback after a reasonable wait is evidence the payload did NOT reach an OOB sink.
- **Manual-setup gates (`setup_gate`)** — for prerequisites you cannot perform via a tool: a jailbroken/hooked device, an emulator on the network, a UART/JTAG hookup. A skill declares these in its `skills/<name>/capabilities.yaml`; when you `set_skill` that skill, a **non-blocking** setup gate opens per declared capability and the set_skill response prints `MANUAL SETUP REQUIRED`. Lifecycle (all via `session(action="setup_gate", options={action: ...})`):
  - `action="list"` — show all setup gates and their status.
  - `action="elect"` — options: `{id, choice: now|defer|skip}`. **Mode-aware:** in interactive runs ASK the operator whether to set it up; headless, default to `defer` (the operator fulfills it on the dashboard). `skip` records the gap explicitly (mark dependent cells `skipped`, reason "operator declined manual setup"). A `requires_host` capability needs an explicit `now` at least once.
  - `action="check"` — options: `{id}` — run the capability's **readiness probe** (an allow-listed command, e.g. `frida-ps -U`) to PROVE the setup is live. A pass writes a proving artifact + a `devices` known-asset and marks the gate satisfied; a fail tells you what to fix. **Probe over trust** — never assume setup is done; verify with `check`. NON-BLOCKING: an unsatisfied gate never blocks `session(complete)` — do all autonomous/static work first, then elect/verify the manual parts.

## Skill Logging (mandatory)

Before invoking **any** skill via the Skill tool, always call:

```
session(action="set_skill", options={
  "skill": "<skill-name>",
  "reason": "<1–2 sentences explaining why you chose this skill>",
  "chained_from": "<parent skill name when chaining; omit for the first skill>"
})
```

This writes a `SKILL_START` or `SKILL_CHAIN` entry to `pentest.log` and enriches `session.json`'s `skill_history` with the decision context. It is mandatory — always call it immediately before the Skill tool invocation.

## Envelope signals to respect

Every non-`session()` tool response is wrapped in a canonical envelope. Beyond the standard `summary` / `facts` / `evidence`, several `status` fields short-circuit the normal flow — you MUST handle them as described instead of continuing with more tool calls.

| Envelope field | When fired | What to do |
|---|---|---|
| `status: "HUMAN_INTERVENTION_REQUIRED"` | Scan is paused by an HIR — auth failure, stuck-on-target, force-complete, etc. The dashboard is showing options to the operator. | Do NOT call any scan-progressing tool. You may call `session(action='status')` to read context. Otherwise wait — the operator will respond via the dashboard, which injects a high-priority steering directive on your next tool call. |
| `status: "SCAN_COMPLETED"` | The human clicked **Complete Scan** or a budget/time/call limit fired. The session is in a terminal state on disk. | Do NOT call any scan-progressing tool, including `session(action='start')` to start a new scan. Write one final brief summary message and end your turn. `opencode run` / `claude -p` will exit cleanly. |
| `AUTH_MISSING` warning prepended to summary | An `http_request` returned 401 / 403 AND the request carried no Authorization / Cookie / X-Api-Key / X-Auth-* / X-Session-* header AND no `?token=`-style query param AND `known_assets.auth_tokens` has at least one valid JWT. | Retry the exact same request with `Authorization: Bearer <token_from_known_assets.auth_tokens[-1].value>`. If 401 persists with auth attached, the token may be expired — POST to a discovered `known_assets.auth_endpoints[*]` with `known_assets.credentials[*]` to mint a fresh one. |
| `REJECTED: closing a cell as 'vulnerable' requires a finding_id` | You called `report(action='coverage', data={status:'vulnerable', ...})` without a `finding_id`. | First call `report(action='finding', data={title, severity, target, description, evidence, tool_used})` — capture the returned `id` — then re-submit the coverage update with `finding_id=<that_id>`. |
| `REJECTED: cannot mark cell <id> tested_clean — artifact ... shows HTTP 4xx` | Closing an injection cell `tested_clean` when the artifact response is 401/403. | The server never evaluated your payload — auth blocked it. Read `auth_context` from `session(action='recovery')`, retry with `Authorization: Bearer …` (or whatever auth form previously worked on the target), and re-close based on the AUTHENTICATED response. |
| `REJECTED: artifact_id 'X' not found on disk` | Closing a cell with a placeholder / never-existed artifact_id. | Run the actual tool first; pass the real artifact_id from its response. |

## Recovery brief shape

`session(action='recovery')` returns a compact JSON brief. Beyond `EXECUTE_NOW` (the single concrete next call) and `coverage` / `findings` / `phase`, watch for:

- `auth_context` — most recent credentials, JWT tokens, and login endpoints automatically extracted during the scan. Use these instead of re-discovering or hand-asking the operator.
- `status: "SCAN_COMPLETED"` — recovery surfaced on a terminal scan; do NOT try to start a new session.

## Available Skills

Skills are slash commands that contain full structured workflows. In Claude Code they appear via `/skill-name`; in opencode they appear as `/command-name`. Always prefer invoking a skill over improvising a workflow from scratch — the skill files contain all chaining rules, tool sequences, and completion gates.

**Skill chaining (how to invoke a sub-skill mid-workflow):**
- **Claude Code**: use the Skill tool — `skill: "<name>", args: "<arguments>"`
- **opencode / other clients**: read the skill command file at `~/.config/opencode/commands/<name>.md` and follow its workflow inline with the provided arguments

| Command | Purpose | Invoke when |
|---------|---------|-------------|
| `/pentester` | Full pentest orchestrator — recon → exploitation → report | General web/network pentest request |
| `/web-exploit` | Deep injection, auth, logic, and business-logic exploitation | Web app confirmed; systematic endpoint testing needed |
| `/param-fuzz` | Auth stripping, type confusion, boundary values, mass assignment discovery, entropy/predictability analysis of generated IDs and tokens | After /web-exploit on any app with structured parameters or generated values (tokens, IDs, PINs, reference numbers) |
| `/business-logic` | Understanding-first BL testing: value/quantity logic abuse, workflow bypass, state machine abuse, BOLA/BFLA, replay/idempotency, quota bypass, time manipulation, multi-tenant isolation — domain-agnostic | Any multi-user app with stateful workflows, numeric fields, or role-based access |
| `/codebase` | OWASP ASVS 5.0 white-box source code review | Local codebase path provided |
| `/ai-redteam` | OWASP LLM Top 10 red-team — prompt injection, jailbreaks, data extraction | AI/chatbot/LLM target |
| `/cloud-security` | AWS/Azure/GCP IAM, storage, serverless posture assessment | Cloud account target |
| `/ad-assessment` | Active Directory — trusts, GPO, ACL, ADCS (ESC1-8), delegation | Domain controller / Windows AD environment |
| `/network-assess` | VLAN hopping, ARP, LLMNR/NBT-NS, SNMP, NFS, segmentation | Internal LAN/network target |
| `/lateral-movement` | Pass-the-hash, Kerberoasting, NTLM relay, WMI/WinRM, pivoting | Post-initial-access; need to move laterally |
| `/credential-audit` | Brute-force, spraying, MFA bypass, OAuth/OIDC, session entropy | Authentication surface testing |
| `/post-exploit` | Privesc (Linux/Windows), persistence, credential harvesting, pivoting | Shell access obtained |
| `/container-k8s-security` | Container escape, Docker socket, K8s RBAC, pod security, etcd | Docker / Kubernetes target |
| `/osint` | Subdomain enumeration, email harvest, Shodan, CT logs, Wayback | External recon phase; passive information gathering |
| `/ssl-tls-audit` | TLS protocol versions, cipher suites, cert chain, POODLE/BEAST/Heartbleed | Any HTTPS/TLS endpoint |
| `/email-security` | SPF/DKIM/DMARC, open relay, spoofing, SMTP security, MTA-STS | Domain email infrastructure |
| `/metasploit` | Exploit validation and exploitation via Metasploit Framework | CVE to exploit; need controlled exploitation |
| `/reverse-shell` | Reverse shell payload generation and listener management | Need shell on target system |
| `/analyze-cve` | CVE exploitability analysis, code path tracing, Burp PoC generation | Known CVE in a dependency |
| `/aikido-triage` | Triage Aikido security CSV against local codebase; verdict each finding | Aikido CSV scan results provided |
| `/gh-export` | Format all confirmed findings as GitHub issue markdown blocks | **User request only** |
| `/remediate` | Fix vulnerabilities in source code | **User request only** |
| `/threat-modeling` | PASTA framework + 4-question threat model | **User request only** |
| `/report` | Generate a styled PDF pentest report from findings.json | **User request only** |
| `/request-cves` | Generate MITRE CVE request packages and GitHub Security Advisory drafts | Novel vulnerability discovered; need CVE disclosure |

**NEVER auto-invoke `/report`, `/gh-export`, `/remediate`, or `/threat-modeling` — these are user-triggered only. Do not invoke them at the end of a scan unless the user explicitly asks.**

## Project layout
- `mcp_server/__main__.py` — entry point, crash logging, module imports
- `mcp_server/_app.py` — FastMCP singleton, `_run()` dispatcher, `_clip()` helper
- `mcp_server/scan_tools.py` — `scan()` tool (nmap, naabu, httpx, nuclei, ffuf, spider, semgrep, trufflehog, fuzzyai, pyrit)
- `mcp_server/kali_tools.py` — `kali()` tool (freeform Kali commands)
- `mcp_server/http_tools.py` — `http()` tool (raw HTTP + PoC saving)
- `mcp_server/report_tools.py` — `report()` tool (findings, diagrams, notes, dashboard)
- `mcp_server/session_tools.py` — `session()` tool (scan lifecycle, Kali infra, codebase target)
- `core/` — server infrastructure (session, cost tracking, logging, findings, dashboard)
- `tools/` — security scanner definitions + Docker runners
- `skills/` — skill definitions (submodule)
- `installers/` — setup and teardown scripts

## Setup
```bash
cd ~/Desktop/agent-smith
./installers/install.sh
```

### Docker images
- **Lightweight tools** (nmap, naabu, httpx, nuclei, ffuf, subfinder, semgrep, trufflehog): public Docker Hub images. Auto-pull on first use. Call `session(action="pull_images")` to pre-fetch.
- **kali-mcp**: custom image — must be built locally with `docker build -t pentest-agent/kali-mcp ./tools/kali/`. Container auto-starts on first `kali()` call and persists until `session(action="stop_kali")`. Uses the kali-server-mcp HTTP API on port 5001.
- **metasploit**: custom image — `docker build -t pentest-agent/metasploit ./tools/metasploit/`. Auto-starts on first `scan(tool="metasploit")` call. API on port 5002.
