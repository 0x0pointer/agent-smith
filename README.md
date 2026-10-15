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

## Resume & recall a prior engagement

A stopped or finished scan is reusable work. Snapshot it into a durable **engagement store**, then pick up where you left off instead of re-testing from scratch:

```bash
python3 scripts/build_engagement_digest.py     # → engagements/<name>/ : digest.md + resume.json + assets/coverage/findings
```

- **Resume** — start a new scan and ingest the store: it merges the prior creds / tokens / endpoints, re-registers the endpoints, and **trust-skips the already-tested cells** so effort goes to what's left.
  `/pentester scan target.com resume=engagements/<name>`  (or `resume=auto` to match the store by target)
- **Recall** — `report(action="recall", data={query:"…"})` keyword-searches the prior corpus mid-scan: findings, saved PoCs, raw tool outputs, **and the agent's own prior notes and decisions** — *"have I reasoned about this endpoint / tech / error before?"* — each hit tagged with its source.

## Local security-knowledge KB (offline lookup before any web search)

```bash
python3 scripts/build_kb.py --all               # → kb/index.db : GTFOBins + LOLBAS + WSTG + skill refs (+ ExploitDB CSV)
python3 scripts/build_kb.py --source nvd        # bulk sources, explicit
python3 scripts/build_kb.py --status            # manifest, doc counts, staleness
```

`report(action="recall", data={query:"sudo suid shell", scope:"kb"})` answers from the local KB
(BM25 over SQLite FTS5) plus engagement docs and prior stores — `scope: all | kb | docs |
engagements`, kind filters like `kb+nvd`. Details: `docs/plan-5.1-local-kb-retrieval.md`.

**Ships with install, opt-in for the network corpus:** the installers always index the skill refs
(local, zero network) and then *prompt* for the full KB (GTFOBins+LOLBAS+WSTG+ExploitDB, ~60 MB
download) — force with `--with-kb` / `SMITH_INSTALL_KB=1`, skip silently with `--no-kb` /
`SMITH_INSTALL_KB=0` (unattended installs). CVEs stay a printed opt-in. The corpus is never
committed to git (~3.3 GB; ExploitDB no-redistribution) — each engagement's digest records which
KB snapshot its `recall(scope:'kb')` queries ran against (source, upstream ref, doc count).

### Adding content to the KB

**A. Permanent — available to every engagement (static KB, tier A)**

1. **No-code drop-in (this machine, instantly searchable):** put `.md`/`.txt`/`.json`/`.csv` files
   in a new folder under `kb/sources/`:

   ```bash
   mkdir -p kb/sources/acme-playbooks && cp ~/engagement-notes/*.md kb/sources/acme-playbooks/
   # immediately searchable — no build step, works with or without kb/index.db
   ```

   Recall labels these hits `[custom source — not indexed]` (deterministic flat scan, no BM25).
   Note `kb/` is gitignored — a drop-in lives on this machine only.

2. **Versioned source in the repo (shared, BM25-indexed):** add an entry to the registry in
   `scripts/build_kb.py` — a fetcher (or `None` for local dirs) plus an ingester returning docs:

   ```python
   def ingest_acme(raw: Path, out: Path) -> list[dict]:
       docs = []
       for path in sorted(Path("docs/acme-playbooks").glob("*.md")):
           docs.append(_doc(f"kb:acme/{path.name}", "acme", path.stem,
                            path.read_text(encoding="utf-8")))
       return docs

   INGESTERS["acme"] = (None, ingest_acme)          # None → no fetch, local files
   ```

   Then `python3 scripts/build_kb.py --source acme` — the docs land in `kb/index.db`
   (BM25-ranked, snippet-highlighted), get normalized flat files as zero-index fallback,
   appear in `--status`, and become a recall kind filter (`scope:"acme"`). Sources fetched
   from upstream (clone/download) follow the same pattern — copy an existing fetcher.

**B. Per-engagement — docs for THIS pentest target only (tier B)**

Attach client documentation, PDFs/API docs found on the target, or saved tool output at session
start or mid-scan — they land in `kb/sessions/<sid>/`, are searchable immediately via
`recall(scope:'docs')`, and `build_engagement_digest.py` copies them into the engagement store so
future engagements on the same target find them too:

```
session(action="kb_add", options={path: "./client-docs"})               # dir or file (trusted)
session(action="kb_add", options={url: "http://target/api-docs.json"})  # fetched → UNTRUSTED
session(action="kb_add", options={artifact_id: "spider_1843_abc"})      # saved tool output
session(action="kb_add", options={path: "manual.pdf", untrusted: true}) # override default

report(action="recall", data={query: "admin console JWT", scope: "docs"})
```

`url:`/`artifact_id:` sources default **UNTRUSTED** (attacker-influenceable target content) and
render with an injection warning in recall output — data, never instructions.
### How added content is used at runtime

All three paths are picked up on the **next query — no rebuild, no restart** (recall rescans disk on
every call). What happens to each:

| Path | Indexing | When Smith reaches it | Lifecycle |
|---|---|---|---|
| **A. `kb/sources/<name>/` drop-in** | flat keyword scan, hit labeled `[custom source — not indexed]`; folder name becomes a filterable kind (`scope:'acme-playbooks'`) | CLAUDE.md norm (*recall before web*); **not** the D1 tech-fingerprint hints (those require the FTS index with cve/exploit/nuclei kinds) | permanent, machine-local |
| **B. Dashboard upload / `session kb_add`** | tier-B flat scan via `scope:'docs'` (always works, index or not); OpenAPI uploads parse to one block per operation | the **steering note fires immediately** — Smith's next tool call carries *"KB DOCS ATTACHED — recall(scope:'docs')"*, so it actively searches, typically mid-scan | ephemeral: purged on completion/new scan; names-only audit trail in the digest |
| **C. Client docs pre-scan (`kb_add path:`)** | same as B, trusted by default | same as B | same as B |

Worked examples: drop a runbook into `kb/sources/acme-playbooks/` and the next `recall('jump host
credentials')` surfaces it; upload `swagger.json` from the dashboard mid-scan and Smith gets params,
auth flows and hidden endpoints from *your* spec when it registers those endpoints; UNTRUSTED-flagged
uploads render fenced — Smith uses the facts but never obeys text inside them.

To promote a drop-in to BM25 + manifest + `--status` tracking, add the small ingester (above) and
run `build_kb.py --source <name>`. Parsers: pdf
(`pdftotext` → `pypdf` → salvage), docx (`textutil`/`pandoc`), html, json/yaml with an
OpenAPI/GraphQL-aware pass (one block per operation), md/txt/csv raw — every skip is reported,
nothing is fatal.

**Dashboard upload (no CLI needed):** the **Operator Actions** tab has an "Engagement documents"
section — pick file(s), optionally flag them target-sourced (UNTRUSTED), Upload. Files land in the
same `kb/sessions/<sid>/` store, Smith gets a steering note to `recall(scope:'docs')` them, and the
list stays visible (with remove buttons) for the rest of the engagement.

**Persistence semantics — static vs per-engagement:**
- **Static KB** (`kb/sources/` + `kb/index.db`): permanent, machine-local, survives every scan.
  Preload a fresh install with `python3 scripts/build_kb.py --all` (+ `--source nvd` for CVEs —
  ~241k CVEs via the official cvelistV5 repo, ~1.3 GB raw clone; `SMITH_CVELIST_START_YEAR`
  controls the range). Nothing ever deletes it except `--refresh` rebuilds.
- **Engagement docs** (`kb/sessions/<sid>/`): **ephemeral by design** — purged automatically when
  the scan completes (or a new scan starts, sweeping crashed-session leftovers). Only the file
  NAMES survive in `session.json`'s `known_assets.kb_docs` and in the engagement digest as an
  audit trail; client/target content is never copied into prior-engagement stores. Data
  minimization: a completed pentest leaves no client documents behind.

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

## License

GNU Affero General Public License v3.0 — see [LICENSE](LICENSE).

> Built for offensive-security professionals. Use it to make the internet safer.
