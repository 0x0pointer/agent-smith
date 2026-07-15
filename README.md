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
- 📊 **A dashboard built for collaboration.** Watch findings, topology, coverage, and the threat model populate in real time at `localhost:7777` — and steer Smith mid-scan, respond to intervention pauses, and fulfill its resource wishlist. ([API →](docs/dashboard-api.md))

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

> 💡 25+ skills total — full catalog and chaining map in **[docs/skills.md](docs/skills.md)**.

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

**Full setup** — other clients (Codex, OpenCode, custom MCP), self-hosted local models (vLLM / DGX Spark), Windows / PowerShell, and the optional Kali & Metasploit images → **[docs/installation.md](docs/installation.md)**.

> 🛡️ **Running a real engagement?** Smith ingests attacker-controlled data and can run commands, so prompt injection is a design reality — run it in an isolated, disposable VM. See **[docs/production-isolation.md](docs/production-isolation.md)**.

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
```

The LLM decides what to run; each tool's output is aggregated and returned to the model, which chooses the next action. Hard cost / time / call-count limits are enforced server-side. Full component diagram, repository layout, and scan deliverables → **[docs/architecture.md](docs/architecture.md)**.

---

## Every scan builds training data

Every pentest Smith runs is also a **structured, redacted dataset of the engagement** — each *decision → action → result → finding* is captured as a schema-versioned event stream and retained per engagement (with the raw artifacts the model actually saw). It's a **byproduct: the capture is passive, read-only, leak-scanned, and never influences the scan** (opt out with `SMITH_EVENTS_DISABLED=1`).

The value compounds: **the more pentests you run, the more data you accumulate — and the better the model you can distill from it.** Pool the streams into a behaviour-cloning dataset and fine-tune a small open-weight base with QLoRA into a **LoRA adapter that runs *as Smith* locally**. Diversity of targets beats raw volume.

→ **[docs/training-data.md](docs/training-data.md)** — what's captured, the safety model, and the exporter + DGX Spark QLoRA harness.

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

## License

GNU Affero General Public License v3.0 — see [LICENSE](LICENSE).

> Built for offensive-security professionals. Use it to make the internet safer.
