# agent-smith

> **For authorized security testing only.**
> Only use this tool against systems you own or have explicit written permission to test.
> Unauthorized access to computer systems is illegal and unethical.

An AI-driven penetration testing agent. Claude acts as the orchestrator — it decides which tools to run, in what order, and when to stop. Security tools run inside ephemeral Docker containers or a persistent Kali Linux container. Results stream into a live dashboard.

Licensed under the [Apache License 2.0](LICENSE).

---

## How it works

```
You (/pentester scan target.com)
  └── Claude Code
        └── MCP server (python -m mcp_server)
              ├── Lightweight tools — docker run --rm (nmap, nuclei, httpx, …)
              ├── Kali container    — persistent kali-mcp (nikto, sqlmap, ffuf, …)
              └── FastAPI dashboard — live findings at http://localhost:5000
```

Claude decides what to run. Hard limits (cost / time / call count) are enforced server-side — when any limit is hit, the tool returns a stop signal and Claude writes the final report.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Claude Code  (AI orchestrator)                                  │
│    Plans scan · calls MCP tools · reasons over results           │
└──────────────────────────┬──────────────────────────────────────┘
                           │ MCP (stdio)
┌──────────────────────────▼──────────────────────────────────────┐
│  mcp_server/  (MCP tool layer)                                   │
│    network · web · exploitation · ai_red_team                    │
│    scan · reporting · infra                                      │
└───┬──────────────────┬────────────────────┬──────────────────────┘
    │                  │                    │
    ▼                  ▼                    ▼
┌───────────┐  ┌───────────────┐  ┌────────────────────────────────┐
│  Docker   │  │  Kali Linux   │  │  core/                         │
│ containers│  │  container    │  │    session · cost · logger      │
│ (ephemeral│  │  (persistent) │  │    findings · api_server       │
│   --rm)   │  │  port 5001    │  └─────────────┬──────────────────┘
└─────┬─────┘  └──────┬────────┘               │
      │               │                         ▼
      ▼               ▼              ┌─────────────────────┐
┌─────────────────────────────┐      │  FastAPI dashboard  │
│  Target                     │      │  localhost:5000     │
│  (URL · IP · codebase)      │      │  5 tabs             │
└─────────────────────────────┘      └─────────────────────┘
```

---

## Quick start

### Requirements

| Dependency | Install |
|---|---|
| [Docker Desktop](https://www.docker.com/products/docker-desktop/) | must be running |
| [Poetry](https://python-poetry.org) | `curl -sSL https://install.python-poetry.org \| python3 -` |
| [Claude Code](https://docs.anthropic.com/en/docs/claude-code) | `npm install -g @anthropic-ai/claude-code` |
| [Node.js](https://nodejs.org) v18+ | required for server-side Mermaid diagram rendering (`npx`) |

### Install

```bash
git clone <repo-url>
cd agent-smith
./installers/install.sh
```

The installer handles everything: Poetry dependencies, API key prompts, MCP registration, and skill installation.

> **After install, fully quit and reopen Claude Code.** The MCP server connects at startup — tools won't be available until you do this.

### Run

Open Claude Code and use a slash command:

```
/pentester scan https://example.com
/pentester scan 192.168.1.0/24 depth=recon
/pentester check codebase at /path/to/project
/threat-model
/analyze-cve lodash 4.17.20 CVE-2021-23337
/aikido-triage ~/Downloads/findings.csv /path/to/codebase
```

Claude calls `start_dashboard` automatically. Open `http://localhost:5000` to watch findings appear in real time.

### Optional: build the Kali image

Required for `kali_exec`, `run_ffuf`, `run_spider`, and `run_pyrit`:

```bash
docker build -t pentest-agent/kali-mcp ./tools/kali/
```

~10 minutes, ~3 GB. Includes PyRIT, ffuf, katana, sqlmap, nikto, and ~50 other tools.

---

## Project layout

```
mcp_server/              MCP tool layer (Claude-callable tools)
  __main__.py            entry point  →  python -m mcp_server
  _app.py                FastMCP singleton + shared helpers
  network.py             run_nmap, run_naabu, run_subfinder
  web.py                 run_httpx, run_nuclei, run_ffuf, run_spider
  code_analysis.py       run_semgrep, run_trufflehog, set_codebase_target
  exploitation.py        http_request, save_poc, kali_exec
  ai_red_team.py         run_fuzzyai, run_pyrit
  scan.py                start_scan, complete_scan, log_note
  reporting.py           report_finding, report_diagram, start_dashboard
  infra.py               start_kali, stop_kali, pull_images

core/                    Server infrastructure
  session.py             Scan scope, depth presets, hard limit enforcement
  cost.py                Per-tool token/cost tracking → session_cost.json
  logger.py              Structured session log → logs/session_*.log
  findings.py            findings.json read/write (findings + diagrams)
  api_server.py          FastAPI web server (dashboard + REST API)

tools/                   Docker tool definitions + runners
  base.py                Tool dataclass
  docker_runner.py       Async docker run --rm wrapper
  kali_runner.py         Persistent Kali container lifecycle
  nmap / naabu / httpx / nuclei / subfinder / semgrep / trufflehog / fuzzyai

tools/kali/              Kali image
  Dockerfile             Builds pentest-agent/kali-mcp
  pyrit_runner.py        CLI shim for Microsoft PyRIT

skills/                  Slash command definitions
  pentester.md
  analyze-cve/SKILL.md
  threat-modeling/SKILL.md
  aikido-triage/SKILL.md
  gh-export/SKILL.md

templates/
  dashboard.html         5-tab dashboard (Findings · Topology · Components · Threat Model · Logs)

threat-model/            Threat model reports (*.md) — auto-displayed in the Threat Model tab

installers/              install.sh · uninstall.sh
```

---

## Documentation

| Doc | Contents |
|---|---|
| [docs/tools.md](docs/tools.md) | All MCP tools — parameters, purpose, examples |
| [docs/kali-toolchain.md](docs/kali-toolchain.md) | Full `kali_exec` command reference |
| [docs/skills.md](docs/skills.md) | Slash commands, chaining guide, examples |
| [docs/dashboard-api.md](docs/dashboard-api.md) | FastAPI endpoints, response shapes |
| [docs/extending.md](docs/extending.md) | How to add new tools and skills |
