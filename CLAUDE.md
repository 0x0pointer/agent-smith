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
| spider | URL | depth=3 |
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
- `action="finding"` — data: `{title, severity, target, description, evidence, tool_used, cve}`
- `action="diagram"` — data: `{title, mermaid}`
- `action="note"` — data: `{message}`
- `action="dashboard"` — data: `{port: 5000}`
- `action="coverage"` — data: `{type, ...}` — manage the coverage matrix:
  - `type="endpoint"` — register endpoint + auto-generate cells: `{path, method, params=[{name, type, value_hint}], discovered_by, auth_context}`
  - `type="tested"` — mark cell tested: `{cell_id, status (tested_clean|vulnerable|not_applicable|skipped), notes, finding_id}`
  - `type="bulk_tested"` — mark multiple cells: `{updates=[{cell_id, status, notes, finding_id}]}`
  - `type="reset"` — clear the matrix

### `session(action, options)`
Scan lifecycle and infrastructure.
- `action="start"` — options: `{target, depth, scope, out_of_scope, max_cost_usd, max_time_minutes, max_tool_calls}`
- `action="complete"` — options: `{notes}`
- `action="status"` — returns current scan state (tools run, findings count, cost, remaining calls)
- `action="recovery"` — returns compact recovery brief after context compaction
- `action="start_kali"` / `action="stop_kali"` — Kali container lifecycle
- `action="start_metasploit"` / `action="stop_metasploit"` — Metasploit container lifecycle
- `action="pull_images"` — pre-pull all Docker images
- `action="set_codebase"` — options: `{path}` — set local codebase for semgrep/trufflehog

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
