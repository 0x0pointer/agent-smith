<p align="center">
  <img src="https://nullpointer.studio/design/FullLogo_Transparent.png" alt="nullpointer.studio" width="320">
</p>

# agent-smith

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=0x0pointer_agent-smith&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=0x0pointer_agent-smith) [![Bugs](https://sonarcloud.io/api/project_badges/measure?project=0x0pointer_agent-smith&metric=bugs)](https://sonarcloud.io/summary/new_code?id=0x0pointer_agent-smith) [![Coverage](https://sonarcloud.io/api/project_badges/measure?project=0x0pointer_agent-smith&metric=coverage)](https://sonarcloud.io/summary/new_code?id=0x0pointer_agent-smith)

**The pentest framework built for the tester who wants to think, not babysit.**
You bring the expertise. agent-smith brings 50+ tools, the methodology, and the execution — and the two of you close findings that neither could reach alone.

> ⚠️ **Authorized testing only.** Use against systems you own or have explicit written permission to test. Unauthorized access is illegal.

<p align="center">
  <img src="docs/gifs/pen-final.gif" alt="agent-smith running a full /pentester scan from recon through reporting" width="900">
</p>

---

## Why agent-smith

- 🧠 **The LLM is the brain, not a payload library.** Skills teach *methodology*; the LLM invents the actual attacks. No two scans look 100% alike.
- 🔗 **Skills chain themselves.** `/pentester` finds an injection point and pivots into `/web-exploit`; `/codebase` finds an LLM call site and pivots into `/ai-redteam`. The agent decides what runs next based on what it just found.
- 🛠 **Bring your own LLM.** Claude Code, OpenAI Codex, [OpenCode](https://opencode.ai) (any provider — OpenAI, Gemini, Ollama, OpenRouter, local models), or any MCP-capable client. Smith auto-scales its context budget to small / local models, so it even runs **fully local on your own GPU** — no API bills, nothing leaving your network. ([setup →](docs/installation.md#self-hosted-local-model-dgx-spark--vllm))
- 📦 **End-to-end deliverables.** Findings, PoCs (Burp-ready `.http` files), threat models, code patches, GitHub issues, and CVE submission packages — all generated for you.
- 🐳 **Sandboxed by default.** Every scanner runs inside an ephemeral Docker container. Hard cost / time / call-count limits enforced server-side.
- 🔍 **Depth enforcement.** A background QA daemon watches Smith and pushes it to go deeper — catching stalls, premature completion, and shortcut behaviour, escalating to you when it's genuinely stuck. ([details →](docs/operating.md#qa-depth-enforcement))
- 🧪 **Evidence, not guesses.** Every finding is artifact-backed and passes a senior-review **adjudication gate**. Blind vulns are confirmed **out-of-band** via a callback server; multi-step attacks are recorded as **proven exploit chains**; white-box findings carry a **source trace** whose `file:line` is resolved against the repo — a hallucinated location is rejected at the door.
- 📊 **A dashboard built for collaboration.** Start scans, switch between them, and see **what every tool found** (ports, subdomains, endpoints, template hits, secrets by location) at `localhost:7777` without reading logs — then steer Smith from what you just read, answer its pauses, and export the results. ([tour →](#the-dashboard) · [API →](docs/dashboard-api.md))

---

## The new way: skills as pattern teachings

Most pentest automation ships a giant payload library and runs it linearly. agent-smith does the opposite. **Skills are not scripts — they are prompts that teach the LLM a way of *thinking*.** A skill describes the vulnerability class, the surface area, the verification logic, and the chaining rules, then leaves the actual attacks to the model.

| Traditional security tools | agent-smith |
|---|---|
| Fixed payload list | LLM-generated payloads, contextual to each target |
| One tool per phase | Skills compose — `/codebase` enriches `/pentester`, which enriches `/post-exploit` |
| Stops at first success | Keeps probing until the cost / time / coverage budget is hit |
| Generates a PDF | Findings, PoCs, patches, threat models, coverage matrix, CVE packages, and more |
| Same scan every time | Two runs against the same target produce different attack paths |

The skills are inspiration. The LLM is the operator.

---

## See it in action

<table>
  <tr>
    <td width="50%">
      <p align="center"><strong><code>/pentester</code> — full autonomous engagement</strong></p>
      <img src="docs/gifs/pen-final.gif" alt="pentester running from recon through reporting" width="100%">
      <p><sub>Recon → fingerprint → exploit → loot → report. The agent decides every step.</sub></p>
    </td>
    <td width="50%">
      <p align="center"><strong><code>/codebase</code> — white-box ASVS review</strong></p>
      <img src="docs/gifs/code-final.gif" alt="codebase skill performing an ASVS 5.0 review" width="100%">
      <p><sub>Source → routes → sinks → ASVS chapters → enriched context for every downstream skill.</sub></p>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <p align="center"><strong><code>/ai-redteam</code> — OWASP LLM Top 10 + AITG</strong></p>
      <img src="docs/gifs/ai-final.gif" alt="ai-redteam executing prompt injection and jailbreak chains" width="100%">
      <p><sub>Prompt injection, jailbreaks, model extraction, MCP runtime attacks, and post-access infra checks.</sub></p>
    </td>
    <td width="50%">
      <p align="center"><strong><code>/remediate</code> — auto-generated patches</strong></p>
      <img src="docs/gifs/fix-final.gif" alt="remediate skill writing fixes for every confirmed finding" width="100%">
      <p><sub>For every confirmed finding the agent writes a code or config patch and verifies it doesn't break the build.</sub></p>
    </td>
  </tr>
</table>

---

## What you can do

Drop any of these the moment you start your client. `/pentester` orchestrates everything; the single-purpose skills give you laser focus.

| Command | What it does |
|---|---|
| `/pentester scan https://staging.example.com depth=thorough` | Full hands-off engagement: OSINT → recon → web-exploit → post-exploit → report |
| `/codebase path=./src` | White-box OWASP ASVS 5.0 review across 16 chapters / 427 requirements |
| `/analyze-cve lodash 4.17.20 CVE-2021-23337` | Traces a CVE from user input to sink in your tree, decides if you're exploitable, writes a Burp PoC |
| `/ai-redteam https://your-app.com/api/chat depth=thorough` | OWASP LLM Top 10 (2025) + AITG v1 + MCP Top 10 runtime attacks |
| `/request-cves` | MITRE CVE form + GHSA draft + disclosure report + vendor email, per qualifying finding |
| `/threat-modeling` | PASTA + STRIDE — component map, data-flow diagram, attack tree, risk register |

> 💡 35+ skills total — full catalog and chaining map in **[docs/skills.md](docs/skills.md)**.

---

## Two ways to work with Smith

The industry is racing toward full automation. We think that's the wrong finish line.

The best pentests have always been about the *interplay* between a skilled tester and their tooling — the tester brings context, intuition, and judgment; the tools provide speed, coverage, and consistency. agent-smith is built around that conviction. Autonomous mode exists and it's genuinely powerful, but **Augmented mode is where the framework does its best work**: Smith handles 50+ parallel tool runs, tracks coverage, and writes the deliverables, while you stay in the loop to redirect scope, respond to intervention pauses, and make the calls that no AI should make alone.

The dashboard isn't a progress bar — it's the collaboration interface.

<table>
  <tr>
    <td width="50%" style="border-left: 3px solid #7b6fff; padding: 1em;">
      <h3>⭐ Augmented Mode — recommended</h3>
      <p>A human expert drives the strategy. Smith handles the heavy lifting — running 50+ tools in parallel, tracking coverage, writing the report. You steer via the dashboard: respond to intervention pauses, inject directives, shift scope mid-scan.</p>
      <p><strong>Best for:</strong> High-value engagements · Complex targets · When expert judgment shapes the approach</p>
      <pre><code>claude          # interactive — you steer, Smith executes</code></pre>
    </td>
    <td width="50%" style="border-left: 3px solid #00ff88; padding: 1em;">
      <h3>Autonomous Mode</h3>
      <p>Give Smith a target — it runs the full engagement end-to-end with no human input. Returns a report with every finding verified and a working proof-of-concept.</p>
      <p><strong>Best for:</strong> Continuous testing · CI/CD pipelines · Recurring red-team drills · Self-serve by dev teams</p>
      <pre><code>claude -p "/pentester scan https://staging.example.com depth=thorough"</code></pre>
    </td>
  </tr>
</table>

---

## Quick start

| Requirement | Notes |
|---|---|
| [Docker Desktop](https://www.docker.com/products/docker-desktop/) | Must be running — all scanners are sandboxed |
| [Poetry](https://python-poetry.org) | `curl -sSL https://install.python-poetry.org \| python3 -` |
| **One LLM client** | Claude Code · Codex · OpenCode (BYO LLM) · any MCP client |
| [Node.js](https://nodejs.org) v18+ | Optional — server-side Mermaid pre-rendering |

```bash
git clone --recursive <repo>
cd agent-smith
./installers/install.sh          # Claude Code  (or install_codex.sh / install_opencode.sh)
```

> ⚠️ **After install, fully restart your client** — the MCP server connects at startup.

**Start a scan from the dashboard.** The installer puts a `smith` command on your PATH
(`~/.local/bin/smith`):

```bash
smith start        # Postgres + dashboard at http://127.0.0.1:7777 — prints the link and an operator token
smith status       # health of database / dashboard / orchestrator
smith stop
```

Open `<dashboard_url>/#k=<operator_token>`, enter a **target** and a **depth**, and press **Start Scan**.
Scope, out-of-scope and a [Source](#sources-and-the-work-queue) are under *Advanced options*.
([details →](docs/installation.md#control-plane-smith))

Prefer the terminal? `claude` and `/pentester scan https://target` still works exactly as before; the
dashboard then follows that single scan.

### …or one-click in the cloud — GitHub Codespaces

No local Docker required. **Code → Codespaces → Create**, and the devcontainer provisions everything on create: the native harness (Poetry + MCP server, registered with Claude Code *and* OpenCode), all skills, the all-modules Kali tools image, Metasploit, and the recon scanner images. The MCP server is re-ensured on every container start, so a resumed Codespace comes up connected.

| Codespaces secret | Purpose |
|---|---|
| `ANTHROPIC_API_KEY` **or** `CLAUDE_CODE_OAUTH_TOKEN` | Claude auth — API billing vs. subscription |
| `TS_AUTH_KEY` | Tailscale — joins the Codespace to your lab so tools reach targets **and receive reverse-shell / OAST callbacks** |

The harness runs natively; only the hacking tools are containerized. A Codespace has no public inbound IP, so callbacks ride the **tailnet** — `SMITH_LHOST` is auto-wired to the Codespace's Tailscale IP. Every port stays **private** by default (the dashboard is a control plane; the MCP and Kali ports are command-execution surfaces — never expose them publicly).

**Full setup** — other clients (Codex, OpenCode, custom MCP), self-hosted local models (vLLM / DGX Spark), Windows / PowerShell, and the optional Kali & Metasploit images → **[docs/installation.md](docs/installation.md)**.

> 🛡️ **Running a real engagement?** Smith ingests attacker-controlled data and can run commands, so prompt injection is a design reality — run it in an isolated, disposable VM. See **[docs/production-isolation.md](docs/production-isolation.md)**.

---

## The dashboard

The dashboard is the **Agent-Smith Pentester Platform**, with two levels. The **platform pages** are about every scan and
are always available; the **scan pages** appear in the rail once you open one scan.

| Platform page | What it answers |
|---|---|
| **Home** | Type a target and start. Below: how many scans are active, which ones need you, open findings by severity, and the most serious findings across all scans. |
| **Scans** | Every instance of Smith. Active scans are live cards (status, progress, findings so far, Open / Resume / Stop); the history table filters by target, status and depth. |
| **All findings** | Every finding of every scan in one list. Filter by severity, app or scan, group by app / severity / scan, export CSV. Opening one shows its evidence and reproduction. |
| **Apps** | Scans grouped by target host: when each app was last tested, what is open on it, and **Scan again** with the same settings. |
| **Knowledge** | A workspace over the [Source](https://github.com/0x0pointer/Source) notes vaults registered in `sources.yaml`. Notes on the left; the reader in the middle, with related notes and a **Map** of how notes link; and the **Brain** on the right: ask a question in plain words and get an answer written from your notes, with numbered citations that open the note. An answer can be saved back to the vault. With Source installed next to agent-smith, **New vault** creates a vault for you, and a vault that is not running can be started from the page. |

**New scan** (top bar, Home, or *Scan again* on an app) is a four-step wizard: target → depth
(Recon / Standard / Thorough / Danger, each explained in plain words) → optional details (the app's
**source code folder** for a white-box test, notes for Smith such as a test account, extra scope,
what never to touch, a time or cost limit, a knowledge vault) → review, with a box confirming you
are authorized to test the target.

**White-box scans.** In Details, paste the path of the folder that holds the app's code, or click
**Browse** to pick it. The folder is on the machine the platform runs on; the platform checks it
exists and tells you what it found (*"16 folders, 24 files · Git repository · Python"*). Smith then
reviews the code with the `/codebase` skill and uses what it learns to guide and confirm the testing
of the live target. Scans started this way carry a **white-box** tag on their card.

| Scan page | What it answers |
|---|---|
| **Findings** | How many issues, by severity (the tiles are the filter). Group by severity or by endpoint, sort by confirmed / severity / newest, and export as Markdown, CSV or JSON. A legend explains each verification label. |
| **Coverage** | Which endpoint × parameter × attack-type cells are tested, vulnerable, skipped or still pending. |
| **Tool Results** | What each tool actually found: one card per tool with a headline (*"8 open ports on 2 hosts"*), the de-duplicated results, every run, and its raw output (secrets masked). **Steer Smith on this** opens the instruction box pre-filled with that tool's context. |
| **More** | Operator Actions, Topology, Components, AI Red Team, Skills, World Model, Threat Model, Metrics, Timeline (one chronological feed of tool calls, instructions, quality checks, reviews and queued work) and the raw Logs. |

The command panel above every page shows the scan's progress (Exploitation → Coverage sweep →
Synthesis → Done) and one line saying what Smith is doing right now. **Needs you** in the top bar
collects everything waiting on the operator: a paused scan, an idle scan, requests from Smith,
manual setup steps and high-priority quality alerts.

### Scans run side by side

Each scan started from the dashboard gets **its own tool-server process, workdir, containers and
Docker network**. Session state, findings, coverage and logs never mix, every log line is tagged
with its scan ID (`[run-1a2b3c4d]`), and the log views follow the scan you have selected.

> Per-scan tool servers are implemented for the **Claude Code** worker. OpenCode and Codex workers
> still share the installed server, so run those one scan at a time.

### Idle scans

When Smith stops — its turn ended, the process exited, or it hung and was shut down — the scan goes
**idle**. Nothing is respawned behind your back: the scan stays open and waits. Send an instruction
or press **Resume scan** and Smith picks up where it left off. For unattended runs that should keep
going on their own, set `SMITH_AUTO_RESUME=1`.

### Sources and the work queue

A **Source** is a knowledge base running on your machine (a vector-embedding store of methodology
and of what earlier engagements found), registered in `sources.yaml`. Bind one to a scan under
*Advanced options* and Smith consults it while testing.

A bound Source also feeds the scan's **work queue**. When notes are added or edited — for example
what a PR scanner learned about a pull request — each change becomes a queued item, and an idle
Smith is started on it: read the notes, register the new endpoints, domains and features, and run
the pentester workflow against them. Items are handed over **one at a time**, each in its own agent
turn, so a burst of updates cannot push each other out of context or be forgotten. Integrations can
queue an item directly:

```bash
curl -X POST http://127.0.0.1:7777/api/runs/<run-id>/work \
  -H "Authorization: Bearer <operator_token>" -H "Content-Type: application/json" \
  -d '{"title": "PR 412", "text": "PR 412 adds POST /api/export. Test it."}'
```

→ **[docs/installation.md](docs/installation.md#source-updates-and-the-work-queue)** for the details
and the settings (`SMITH_AUTO_RESUME`, `SMITH_WORK_QUEUE_DISABLED`, `SMITH_WORK_POLL_SECONDS`).

---

## How it works

```
You (/pentester scan target.com)
  └── Your LLM (Claude / GPT / Gemini / local …)
        └── MCP server (python -m mcp_server)
              ├── Lightweight scanners — docker run --rm (nmap, nuclei, httpx, …)
              ├── Kali container       — persistent kali-mcp (nikto, sqlmap, ffuf, …)
              ├── Metasploit container — exploit validation
              └── FastAPI dashboard    — live findings at localhost:7777

smith start  (optional control plane)
  ├── Postgres            — runs, per-scan snapshots, dashboard tokens, work queue
  └── Dashboard + orchestrator
        ├── one worker + one tool server per scan  (isolated workdir, containers, network)
        └── work queue    — Source updates → one queued item at a time for an idle scan
```

The LLM decides what to run; each tool's output is aggregated and returned to the model, which chooses the next action. Hard cost / time / call-count limits are enforced server-side. Full component diagram, repository layout, and scan deliverables → **[docs/architecture.md](docs/architecture.md)**.

---

## Every scan builds training data

Every pentest Smith runs is also a **structured, redacted dataset of the engagement** — each *decision → action → result → finding* is captured as a schema-versioned event stream and retained per engagement (with the raw artifacts the model actually saw). It's a **byproduct: the capture is passive, read-only, leak-scanned, and never influences the scan** (opt out with `SMITH_EVENTS_DISABLED=1`).

The value compounds: **the more pentests you run, the more data you accumulate — and the better the model you can distill from it.** Pool the streams into a behaviour-cloning dataset and fine-tune a small open-weight base with QLoRA into a **LoRA adapter that runs *as Smith* locally**. Diversity of targets beats raw volume.

→ **[docs/training-data.md](docs/training-data.md)** — what's captured, the safety model, and the exporter + DGX Spark QLoRA harness.

---

## Resume & recall a prior engagement

A stopped or finished scan is reusable work. Snapshot it into a durable **engagement store**, then pick up where you left off instead of re-testing from scratch:

```bash
python3 scripts/build_engagement_digest.py     # → engagements/<name>/ : digest.md + resume.json + assets/coverage/findings
```

- **Resume** — start a new scan and ingest the store: it merges the prior creds / tokens / endpoints, re-registers the endpoints, and **trust-skips the already-tested cells** so effort goes to what's left.
  `/pentester scan target.com resume=engagements/<name>`  (or `resume=auto` to match the store by target)
- **Recall** — `report(action="recall", data={query:"…"})` keyword-searches the prior corpus mid-scan: findings, saved PoCs, raw tool outputs, **and the agent's own prior notes and decisions** — *"have I reasoned about this endpoint / tech / error before?"* — each hit tagged with its source.

## Recall prior engagements

`report(action=\"recall\", data={query:\"…\"})` searches prior engagement stores only: findings,
saved PoCs, raw tool outputs, and the agent's prior notes/decisions under `engagements/*`.

- Default scope is the prior engagement corpus.
- `scope:\"engagements\"` is supported explicitly.
- `path:\"engagements/<name>\"` scopes recall to one prior store.

To create a store from a completed or stopped scan:

```bash
python3 scripts/build_engagement_digest.py
```

Trust-and-skip assumes an unchanged target; use `mode=context` to load prior results as advisory context without skipping. Both build on the per-engagement event stream above, so the more you scan, the more prior context each new engagement can draw on.

---

## Documentation

**Getting started**
- [installation.md](docs/installation.md) — every client, self-hosted local models, Windows, optional images

**Concepts**
- [architecture.md](docs/architecture.md) — component diagram, project layout, what a scan produces
- [skills.md](docs/skills.md) — full skill catalog, chaining map, per-skill reference
- [training-data.md](docs/training-data.md) — every scan builds a redacted dataset you can distill into a local LoRA adapter

**Operating Smith**
- [operating.md](docs/operating.md) — scan modes, Human Intervention (HIR), lifecycle, QA depth enforcement
- [production-isolation.md](docs/production-isolation.md) — running Smith sandboxed in production
- [dashboard-api.md](docs/dashboard-api.md) — FastAPI endpoints and response shapes

**Reference**
- [tools.md](docs/tools.md) — all MCP tools: parameters, purpose, examples
- [kali-toolchain.md](docs/kali-toolchain.md) — full `kali` command reference

**Contributing**
- [extending.md](docs/extending.md) — adding new tools and skills
- [testing.md](docs/testing.md) — running the test suite, coverage, adding tests

> **Adding a new skill?** Skills live in a separate repo ([github.com/0x0pointer/skills](https://github.com/0x0pointer/skills)) pulled in as a git submodule. After adding a skill there, update the submodule pointer (`git add skills && git commit`) and re-run the installer to deploy it.

---

## Credits & attribution

The AI red-team layer builds on two open resources from [Arcanum Security](https://arcanum-sec.github.io/):

- **Arcanum Prompt Injection Taxonomy (PITAX)** — the 172-node taxonomy (intents / techniques / evasions / inputs) shipped behind `redteam(action="taxonomy")` and used to drive the attack engine. <https://arcanum-sec.github.io/arc_pi_taxonomy/> · licensed **CC BY 4.0**.
- **P4RS3LT0NGV3** — the payload-obfuscation *techniques* reimplemented (clean-room, no third-party code) in the `transform()` engine. <https://arcanum-sec.github.io/P4RS3LT0NGV3/>

## License

GNU Affero General Public License v3.0 — see [LICENSE](LICENSE).

> Built for offensive-security professionals. Use it to make the internet safer.
