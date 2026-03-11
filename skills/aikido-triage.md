---
name: aikido-triage
description: Triages an Aikido security findings CSV against a local codebase. For each finding, reads the flagged file, traces the code path, and verdicts it as KEEP OPEN or CLOSE with a specific reason. Outputs a reviewed CSV and a self-contained HTML evidence report. Run this at the end of a pentest when an Aikido CSV is available.
argument-hint: [path/to/findings.csv] [path/to/codebase]
user-invocable: true
---

# Aikido Findings Triage Workflow

You are triaging an Aikido SAST/SCA/secret-scanning CSV export against a local codebase. Your job is to read every finding, investigate the flagged code, and verdict each one with evidence. At the end you produce a reviewed CSV and a self-contained HTML report.

**Do not guess. Read the actual files before rendering a verdict.**

---

## Arguments

Parse from the user's invocation:
- `CSV_PATH` — path to the Aikido CSV export
- `CODEBASE_PATH` — absolute path to the local codebase to investigate

If either argument is missing, ask the user before proceeding.

---

## Phase 1 — Parse the CSV

1. Read `CSV_PATH` with the Read tool.
2. Parse every row. Key columns to extract per finding:
   - `aikido_issue_id` — unique ID
   - `type` — `sast` | `open_source` | `leaked_secret` | `eol`
   - `severity` — critical / high / medium / low
   - `affected_file` — relative path to the flagged file
   - `related_cve` — CVE or advisory ID (may be empty)
   - `rule` — rule name that fired
   - `start_line` / `end_line` — flagged line range
   - `installed_version` / `patched_version` — for SCA findings
   - `affected_package` — for SCA/EOL findings

3. Group findings by `type` so you can batch-investigate efficiently.

---

## Phase 2 — Investigate Each Finding

Work through findings type by type. For each one, read the flagged file and apply the investigation playbook for that type.

### 2a — `leaked_secret` findings

**Step 1 — Does the file exist?**

Use the Read tool on `CODEBASE_PATH/affected_file`. If the file does not exist:
→ Verdict: **CLOSE — File Removed**
→ Note: "File does not exist at HEAD. Finding references removed code in git history."
→ Move on. Do not investigate further.

**Step 2 — Read the flagged lines.**

Read `start_line` to `end_line` (expand by ±3 lines for context).

Apply these patterns:

| What you see | Verdict |
|---|---|
| `ENV.fetch(...)`, `ENV[...]`, `ENV.fetch(..., nil)` | **CLOSE — False Positive** (env var read) |
| `${{ secrets.* }}` (GitHub Actions) | **CLOSE — False Positive** (GH Actions secret) |
| `${VARIABLE_NAME}` in .npmrc/.env.example | **CLOSE — False Positive** (env var placeholder) |
| `--mount=type=secret` in Dockerfile | **CLOSE — False Positive** (Docker build secret) |
| A long regex, UA string, or binary-looking data | **CLOSE — False Positive** (pattern mismatch) |
| An actual hardcoded token/key/password string | **KEEP OPEN** — check liveness if possible |
| A real URL with embedded credentials (user:pass@host) | **KEEP OPEN** |

For `sidekiq-sensitive-url` rule: check whether the flagged content is a Redis URL with credentials or just a gem declaration. Almost always a false positive in Gemfile/Gemfile.lock.

**Step 3 — If hardcoded secret found:**
- Note the exact line and masked value
- Check if `secret_liveness` column says `active` — if so, escalate to critical
- Verdict: **KEEP OPEN — Hardcoded Secret**

---

### 2b — `sast` findings

**Step 1 — Read the flagged file and lines.**

Read `CODEBASE_PATH/affected_file` at `start_line` ± 10 lines of context.

**Step 2 — Apply rule-specific investigation:**

**NoSQL injection (`NoSQL injection attack possible`)**
- Trace what the flagged call actually does. Follow the call chain:
  1. What does the flagged function call?
  2. Does it call a NoSQL driver (MongoDB, Redis query, Elasticsearch, Mongoose)?
  3. Or does it call an HTTP client (axios, fetch, HTTParty)?
- Check `CODEBASE_PATH/Gemfile` and `CODEBASE_PATH/package.json` for NoSQL drivers.
- If no NoSQL driver exists in the stack: **CLOSE — False Positive**

**SQL injection (`SQL injection`, `string-based query concatenation`)**
- Read the flagged method. Check:
  1. Is there actual string interpolation into a raw SQL string? (`"... #{variable}"`)
  2. What is the type of the interpolated variable? (Ruby `Date`, `Integer`, `String`?)
  3. Is it executed via `select_all`, `execute`, or `connection.exec`?
  4. Trace the variable back to its source — is it user-controlled?
- If raw interpolation exists but type coercion removes the injection vector: **KEEP OPEN — Medium** (dangerous pattern, mitigated)
- If raw interpolation with no type coercion on a user-controlled string: **KEEP OPEN — High**
- If interpolation is of a hardcoded or server-side-only value: **CLOSE — False Positive**

**Unpinned GitHub Actions (`3rd party Github Actions should be pinned`)**
- Read the workflow file at the flagged line.
- Check if `uses:` has a SHA pin (`@abc123def...`) or only a tag (`@v2`, `@main`).
- Tag-pinned or branch-pinned: **KEEP OPEN — Real Finding**
- SHA-pinned: **CLOSE — False Positive**

**NODE_AUTH_TOKEN (`Use of NODE_AUTH_TOKEN`)**
- Read the flagged line. If value is `${{ secrets.* }}`: **CLOSE — False Positive**
- If hardcoded token value: **KEEP OPEN**

**Other SAST rules**
- Read the flagged lines. Apply judgment: is the finding actually present in the code, or is it a pattern-match on a non-vulnerable construct? Document what you found.

---

### 2c — `open_source` / SCA findings

For each SCA finding:

**Step 1 — Identify the vulnerable function from the CVE/advisory.**

Use your knowledge of the CVE to identify what specific function/class is vulnerable. If you need more detail, use `/analyze-cve` to do a full dataflow trace.

**Step 2 — Check if the package is used in application source code.**

Use Grep to search for imports of the package in the application source:
- JS/TS: `import .* from 'package-name'` or `require('package-name')`
- Ruby: `require 'package'` or check Gemfile for direct gem declaration vs transitive

**Step 3 — Apply these verdicts:**

| Scenario | Verdict |
|---|---|
| Package not imported anywhere in app source (transitive/build-only) | **CLOSE — Not Exploitable** |
| Package imported but vulnerable function never called | **CLOSE — Not Exploitable** |
| Package imported, vulnerable function called, no user input reaches it | **CLOSE — Not Exploitable** |
| Package imported, vulnerable function called with user-controlled input, no sanitization | **KEEP OPEN** |
| devDependency only (webpack-dev-server, jest, babel plugins) | **CLOSE — Not Exploitable** |

**Step 4 — For complex SCA findings with user-reachable code paths:**
Run `/analyze-cve` skill to do a full dataflow trace before rendering the verdict.

---

### 2d — `eol` findings

- Read the version file (`.ruby-version`, check `package.json` for the framework version).
- Confirm the actual installed version.
- Look up the EOL date from your knowledge.
- If EOL date has passed: **KEEP OPEN — Real Finding**
- Document the EOL date and recommended upgrade path.

---

## Phase 3 — Assign Final Verdicts

For every finding, assign:

| Field | Values |
|---|---|
| `recommended_action` | `KEEP OPEN` or `CLOSE` |
| `close_category` | `False Positive` / `File Removed` / `Not Exploitable` / `Real Finding` |
| `analyst_notes` | One sentence — what you found and why |
| `evidence` | Specific file:line references and code fragments proving the verdict |

---

## Phase 4 — Output the Reviewed CSV

Write a new CSV to the same directory as the input CSV, named `<original-name>-reviewed.csv`.

**Column set (lean — do not include empty cloud/VM/container columns from the original):**

```
aikido_issue_id, type, severity, affected_file, related_cve, rule, start_line,
recommended_action, close_category, analyst_notes, evidence
```

Rules:
- Wrap any field containing commas in double quotes
- Use ` | ` (space-pipe-space) as separator within the `evidence` field — never commas
- Keep `analyst_notes` to one sentence with no commas
- Every row must have exactly 11 fields

---

## Phase 5 — Generate the HTML Evidence Report

Write a self-contained HTML file to the same directory as the CSV, named `<project-name>-security-review.html`.

### HTML structure (follow this exactly)

```
1. <header>  — project name, analyst, date, branch/source
2. Stats bar — total / close / keep open / false positive / file removed / not exploitable counts
3. Jump nav  — anchor links to each section
4. Full summary table — all findings, colour-coded by severity and action
5. KEEP OPEN section — one detailed card per finding with full code evidence
6. FALSE POSITIVES section — one card per finding with evidence showing why it's a FP
7. FILE REMOVED section — simple table (no code to show)
8. NOT EXPLOITABLE section — one card per finding with code evidence
9. <footer>
```

### Card anatomy (for sections 5, 6, 8)

Each finding card must contain:
- Finding ID, severity badge, type, file:line
- `recommended_action` badge
- **Verdict paragraph** — plain English explanation
- **Fix** (for KEEP OPEN only) — exact command or code change required
- **Evidence code block** — the actual lines from the file, syntax-highlighted, with line numbers and comments explaining what is or isn't vulnerable

### Code block style

Use `<pre>` blocks with dark background. Add inline `<span>` highlights:
- `class="highlight"` — red, for the vulnerable or suspicious line
- `class="ok"` — green, for the safe/correct pattern
- `class="comment"` — gray, for explanatory annotations added by the analyst

### Severity badge colours

- Critical → red background
- High → orange background
- Medium → yellow background
- Low → green background

### Action badge colours

- KEEP OPEN → red
- CLOSE → green

### Close category badge colours

- False Positive → blue
- File Removed → purple
- Not Exploitable → green
- Real Finding → red

### CSS

Embed all CSS in a `<style>` block in `<head>`. No external dependencies — the file must be fully self-contained and openable offline.

Use a clean, professional light theme. Monospace font for file paths and code. System font stack for prose.

---

## Phase 6 — Summary to User

After writing both files, output a short summary:

```
## Triage complete

**CSV:** /path/to/reviewed.csv
**Report:** /path/to/report.html

| Action     | Count |
|------------|-------|
| KEEP OPEN  | N     |
| CLOSE      | N     |
| — False Positive | N |
| — File Removed   | N |
| — Not Exploitable| N |

**Keep open findings:**
- [ID] severity — short description
- ...
```

---

## Rules

- **Read every flagged file before rendering a verdict.** Never close a finding based on the rule name alone.
- **Batch independent reads in parallel** — read multiple files in one response when they don't depend on each other.
- **Use `/analyze-cve` for complex SCA findings** where user input may reach the vulnerable function. Do not skip this.
- **For `leaked_secret` findings on files that exist**: always read the exact flagged lines. Do not assume it's a false positive without looking.
- **Preserve line numbers** in all code snippets — use the actual line numbers from the source file.
- **Do not fabricate code.** Only quote lines you have actually read from the file.
- **Write the HTML last** — after all verdicts are finalized, so the report is complete.
- **Do not include empty columns** in the output CSV — strip the cloud/VM/container/ARN columns from the original Aikido export.

---

## Finding type quick reference

| Aikido `type` | Primary check | Most common outcome |
|---|---|---|
| `leaked_secret` | Does file exist? Then read flagged lines. | False Positive or File Removed |
| `sast` — NoSQL | Trace call chain to actual DB driver | Almost always False Positive if MySQL/Postgres stack |
| `sast` — SQLi | Read raw SQL method, check interpolation + type coercion | Medium finding, often partially mitigated |
| `sast` — Actions | Check for SHA pin vs tag pin | Real finding if tag-pinned |
| `open_source` | Grep app source for import, check if vulnerable function used | Often Not Exploitable (transitive/build-only) |
| `eol` | Read version file, check EOL date | Always a real finding if EOL date passed |
