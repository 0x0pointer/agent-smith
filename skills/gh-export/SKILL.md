---
name: gh-export
description: Formats all confirmed pentest findings from findings.json into copy-pasteable GitHub issue markdown blocks, following the AppSec reporting guide template.
argument-hint: [optional: path to findings.json]
user-invocable: true
---

# GitHub Issue Export

## Purpose

Read `findings.json` from the current pentest session and produce one copy-pasteable GitHub issue markdown block per confirmed finding.

Each block follows the AppSec reporting guide format — concrete impact, reproducible steps, raw PoC — so developers can act immediately without back-and-forth.

## Workflow

1. Read `findings.json` from the repo root (or the path provided in `$ARGUMENTS` if given)
2. For each entry in `findings[].findings` (skip diagram entries):
   - Format it using the template below
   - Check `pocs/` for any `.http` file whose name contains a keyword from the finding title — if found, read it and paste the content into the PoC block
   - After formatting the block, call `http_request` with method `PATCH`, url `http://localhost:5000/api/findings/{finding.id}`, body `{"gh_issue": "<the formatted markdown block>"}`, and headers `{"Content-Type": "application/json"}` — this couples the block to the finding in the dashboard
3. Print all blocks consecutively with a `---` separator between them
4. After the last block, print a one-line summary: `X issue(s) ready to file — copy each block above into a GitHub issue.`

## Output Template

For every finding, output exactly this structure (omit `## Browsers Verified In` for non-browser/non-web findings):

~~~markdown
**Summary:** <one sentence: what the vulnerability is and which component/endpoint is affected>

**Impact:** <what an attacker can concretely do — name the data exposed, the privilege gained, or the service disrupted. Never write "could lead to" — write "allows an attacker to". One short paragraph.>

**Severity Level:** <Critical | High | Medium | Low>

## Steps To Reproduce:

1. <exact first step — full URL, parameter name, payload>
2. <exact second step>
3. <what to observe in the response that confirms the issue>

## PoC

```
<paste the raw curl command, HTTP request from pocs/*.http, or tool output excerpt that proves exploitability>
```

## Supporting Material/References:

* <CVE ID if applicable, otherwise omit this line>
* Affected target: <target URL or file path from the finding>
* Tool: <tool_used value from the finding>
* <any additional evidence: key excerpt from raw tool output>
~~~

## Rules

- **One block per finding** — never merge two findings into one issue
- **Impact must be concrete** — derive it from the finding's `description` and `evidence` fields; never invent hypothetical consequences
- **Steps to Reproduce must be self-contained** — include full URLs and exact payloads so a developer can reproduce without asking questions
- **PoC block is mandatory** — if a matching `.http` file exists in `pocs/`, paste its full content; otherwise extract the most relevant raw evidence line from the `evidence` field (e.g. the curl command, the HTTP request, or the tool's finding line)
- **Severity mapping**: critical → `Critical`, high → `High`, medium → `Medium`, low → `Low`
- Output only the markdown blocks and the final summary line — no extra prose, no headers, no explanation around the blocks
