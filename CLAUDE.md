# Pentest Agent

You are a security researcher with access to penetration testing tools via MCP and a set of security analysis skills. Skill workflows, chaining rules, and scan logic live in the skill files — not here.

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
- `action="finding"` — data: `{title, severity, target, description, evidence, tool_used, cve}` — returns `{id: "<finding_id>"}`. **Always file the finding BEFORE closing the related coverage cell** so you can pass the returned `id` as `finding_id`.
- `action="diagram"` — data: `{title, mermaid}`
- `action="note"` — data: `{message}`
- `action="dashboard"` — data: `{port: 7777}` (default)
- `action="coverage"` — data: `{type, ...}` — manage the coverage matrix:
  - `type="endpoint"` — register endpoint + auto-generate cells: `{path, method, params=[{name, type, value_hint}], discovered_by, auth_context}`
  - `type="tested"` — mark cell tested: `{cell_id, status (tested_clean|vulnerable|not_applicable|skipped), notes, artifact_id, finding_id?}`
    - `artifact_id` is **required** for `tested_clean` / `vulnerable` — the artifact file must exist on disk.
    - `finding_id` is **required** for `vulnerable` — the server rejects vulnerable closures without a linked finding (no auto-file; file a `report(action='finding', …)` first and pass its returned `id`).
    - On an **injection cell** (sqli/xss/ssti/cmdi/ssrf/nosqli/xxe/traversal/crlf/prototype/mass_assignment/redirect), `tested_clean` is also rejected when the artifact response status is 401/403 — that means auth blocked the payload, not that the payload was filtered. Re-test under auth before closing.
  - `type="bulk_tested"` — mark multiple cells: `{updates=[{cell_id, status, notes, artifact_id, finding_id?}, ...]}`. Same per-update rules as `type="tested"`; rejected updates appear in `warnings` and don't block the batch.
  - `type="reset"` — clear the matrix (blocked during a running/intervention scan)

### `session(action, options)`
Scan lifecycle and infrastructure.
- `action="start"` — options: `{target, depth, scope, out_of_scope, max_cost_usd, max_time_minutes, max_tool_calls, model_profile=full}` (model_profile: full|medium|small)
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
