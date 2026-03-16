# Skills Reference

Skills are slash commands that expand into detailed instructions for Claude. They live in a separate repo ([github.com/0x0pointer/skills](https://github.com/0x0pointer/skills)) pulled in as a git submodule at `skills/`, and are installed into `~/.claude/commands/` or `~/.claude/skills/` by `install.sh`.

---

## `/pentester`

Full penetration test — recon through exploitation through reporting.

```
/pentester scan https://example.com
/pentester scan 192.168.1.0/24 depth=recon
/pentester scan 10.0.0.1 depth=thorough max_cost_usd=1.00
/pentester check codebase at /path/to/project
```

**What it does:**

1. Calls `start_dashboard` — opens live findings tracker at `http://localhost:5000`
2. Runs `run_naabu` + `run_subfinder` in parallel for initial recon
3. Runs `run_httpx` to confirm live web services
4. Calls `report_diagram` with a Mermaid diagram of discovered topology
5. Runs `run_nuclei` on live web targets
6. Runs `run_spider` to map all endpoints
7. Runs deep scanning with `kali_exec` (nikto, sqlmap, testssl, …) based on depth
8. Runs `run_ffuf` on interesting paths
9. Calls `report_finding` for every confirmed vulnerability
10. Calls `complete_scan` (blocked until diagram + PoCs are present)

**Depth presets:**

| Depth | Tools | Cost | Time | Calls |
|---|---|---|---|---|
| `recon` | naabu + subfinder + httpx | $0.10 | 15 min | 10 |
| `standard` | recon + nuclei + spider + ffuf | $0.50 | 45 min | 25 |
| `thorough` | standard + full Kali toolchain | $2.00 | 120 min | 60 |

---

## `/analyze-cve`

Traces a CVE in a project dependency — checks whether the vulnerable code path is actually reachable from user input, assesses real exploitability, and generates a Burp Suite HTTP PoC.

```
/analyze-cve lodash 4.17.20 CVE-2021-23337
/analyze-cve pymupdf 1.26.4 https://nvd.nist.gov/vuln/detail/CVE-2024-12345
/analyze-cve express 4.18.2 CVE-2024-29041
```

**What it does:**

1. Reads the NVD page for the CVE (description, affected versions, patch diff)
2. Locates the vulnerable package in the codebase
3. Traces the call chain from user-controlled input to the vulnerable function
4. Assesses exploitability: reachable? user-controlled input? authentication required?
5. Generates a `curl` command and Burp Suite HTTP request to test the vulnerability
6. Calls `report_finding` if exploitable

---

## `/threat-model`

Structured threat model using the PASTA framework (Process for Attack Simulation and Threat Analysis) with STRIDE analysis and attack trees.

```
/threat-model
/threat-model focus on the authentication system
/threat-model for the payment processing flow
```

**What it produces:**

- Component map (Mermaid diagram)
- Data flow diagram (Mermaid)
- Attack tree for the highest-risk component (Mermaid)
- STRIDE threat table (Spoofing / Tampering / Repudiation / Info Disclosure / DoS / Elevation)
- Risk register with likelihood × impact scores
- Prioritised mitigation plan
- `threat-model/threat-model-<app>.md` — saved to the repo root

The report is automatically displayed in the **Threat Model** tab of the dashboard. Mermaid diagrams are pre-rendered server-side (dark theme). If you run multiple threat models, use the dropdown in the tab to switch between them.

---

## `/aikido-triage`

Triage every finding in an Aikido SAST/SCA CSV export against the actual codebase. Verdicts each finding as `KEEP OPEN` or `CLOSE` with code evidence.

```
/aikido-triage ~/Downloads/findings.csv /path/to/codebase
```

**What it does:**

1. Reads every row in the CSV
2. For each finding, reads the flagged file and traces the relevant code path
3. Assigns a verdict and category:
   - `KEEP OPEN` — real vulnerability, confirmed in code
   - `CLOSE: False Positive` — code does not match the finding pattern
   - `CLOSE: File Removed` — flagged file no longer exists
   - `CLOSE: Not Exploitable` — vulnerable function imported but never called with user input
4. For complex SCA findings, chains into `/analyze-cve` for full dataflow analysis

**Outputs:**

| File | Description |
|---|---|
| `findings-reviewed.csv` | Original CSV with `recommended_action`, `close_category`, `analyst_notes`, `evidence` columns added |
| `project-security-review.html` | Self-contained HTML report with stats bar, full findings table, and per-finding evidence cards with syntax-highlighted code |

---

## `/gh-export`

Formats all confirmed findings from `findings.json` as copy-pasteable GitHub issue blocks, following the AppSec reporting guide template. After generating each block, patches the finding in `findings.json` with the formatted text so the dashboard can surface it.

```
/gh-export
```

**Output format per finding:**

```markdown
**Summary:** <one sentence>

**Impact:** <concrete attacker capability>

**Severity Level:** Critical | High | Medium | Low

## Steps To Reproduce:
1. ...

## PoC
\`\`\`
raw curl / HTTP request
\`\`\`

## Supporting Material/References:
* Affected target: ...
* Tool: ...
```

Once `/gh-export` has run, each finding in the **Findings** tab shows a **clipboard icon button**. Click it to copy that finding's GitHub issue block directly to your clipboard — ready to paste into a GitHub issue.

---

## `/ai-redteam`

Red-team assessment of AI/LLM endpoints using the OWASP LLM Top 10 (2025) framework. Systematically tests all 10 categories using four complementary tools.

```
/ai-redteam https://ai-app.com/api/chat provider=openai depth=standard
/ai-redteam https://ai-app.com/v1/chat provider=rest depth=thorough
/ai-redteam https://ai-app.com/api/chat depth=quick
```

**What it does:**

1. Calls `start_scan` with target, depth, and limits
2. Calls `start_dashboard` — live findings tracker
3. **Recon & fingerprinting** — probes the endpoint for model identification, response format, rate limiting, tool/function calling surface, and hidden parameters
4. Calls `report_diagram` with an architecture diagram of the AI system (trust boundaries, guardrails, tool layer, RAG)
5. **Automated scanning** — runs tools in parallel based on depth:
   - FuzzyAI: single-turn jailbreak fuzzing (jailbreak, prompt injection, system prompt leak, PII extraction, XSS injection)
   - Garak: probe-based scanning (DAN, encoding attacks, data leakage, hallucination, malware generation)
   - promptfoo: plugin-based evaluation (134 plugins — excessive agency, RAG poisoning, reasoning DoS, MCP attacks)
   - PyRIT: multi-turn orchestrated attacks (crescendo, jailbreak with configurable objectives)
6. **Targeted multi-turn attacks** — based on Phase 2 results, runs focused attacks on weak categories (tool parameter fuzzing, authority marker rotation, multi-objective payloads)
7. **Manual verification & PoC** — reproduces each finding with `http_request`, saves confirmed exploits via `save_poc`
8. Calls `report_finding` for every confirmed vulnerability — mapped to OWASP LLM category
9. Produces OWASP coverage summary showing which categories were tested and what was found
10. Calls `complete_scan` and chains into `/gh-export`

**Tools used:**

| Tool | Coverage | Type |
|------|----------|------|
| FuzzyAI (CyberArk) | LLM01, LLM02, LLM05, LLM07 | Single-turn fuzzing |
| Garak (NVIDIA) | LLM01, LLM02, LLM05, LLM07, LLM09 | Probe-based scanning |
| promptfoo | LLM01, LLM05, LLM06, LLM08, LLM09, LLM10 | Plugin-based evaluation |
| PyRIT (Microsoft) | LLM01, LLM02, LLM07, LLM09 | Multi-turn orchestration |

**Depth presets:**

| Depth | Tools | Cost | Time | Calls |
|---|---|---|---|---|
| `quick` | FuzzyAI (jailbreak + system-prompt-leak) | $0.10 | 10 min | 5 |
| `standard` | FuzzyAI (all attacks) + Garak (top probes) + PyRIT (prompt_injection) | $0.50 | 30 min | 15 |
| `thorough` | All 4 tools + multi-turn crescendo + manual follow-up | $2.00 | 90 min | 40 |

---

## Chaining skills

Skills are designed to be chained automatically during an engagement:

```
Before a pentest
  └── /threat-model          identify high-risk areas to focus the scan

During a pentest (/pentester)
  ├── /analyze-cve            if nuclei or semgrep finds a CVE dependency
  ├── /ai-redteam             if an LLM endpoint is discovered
  └── runs automatically

For AI/LLM targets (instead of /pentester)
  └── /ai-redteam             OWASP LLM Top 10 assessment

After a pentest
  ├── /aikido-triage          if an Aikido CSV export is available
  └── /gh-export              format all findings as GitHub issues
```

Claude chains these automatically based on context — you can also invoke them manually at any point.
