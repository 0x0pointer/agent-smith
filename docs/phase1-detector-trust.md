# Phase 1 — Detector-trust research: correct cells → tools → endpoint_sweep

Goal: make the coverage matrix the *honest, achievable* definition of "done". That
needs three things, in order:
1. **The correct cells** — the matrix must test what a real pentest tests (validated
   against OWASP **ASVS V5** and the **WSTG** Input-Validation + category lists), not
   an arbitrary subset.
2. **The right tools installed** — for each cell, a tool in our kali image that can
   produce *trustworthy* detector evidence.
3. **What it means per `endpoint_sweep`** — per cell: tool, VULN-trust, CLEAN-trust,
   evidence, and the sweep action.

The crux is **CLEAN-trust** (does "scanner found nothing" mean genuinely safe?). The
old grind regression was false `tested_clean`. So Partial cells get a distinct
`scanned_clean` status, and only high-trust detectors auto-close/`tested_clean`.

---

## 1. Gap analysis — current cells vs ASVS V5 / WSTG-INPV

Current injection cells (`core/taxonomy.py` APPLICABILITY):
`sqli, nosqli, xss, ssti, cmdi, ssrf, xxe, traversal, crlf, prototype,
mass_assignment, redirect, idor, smuggling, deserial`
Cross-cutting: `cors, csrf, security_headers, rate_limit, method_tampering, cache,
jwt, race, bfla`.

| ASVS V5 / WSTG-INPV item | Covered by a current cell? | Action |
|---|---|---|
| SQLi (5.3.4/5.3.5, INPV-05) | `sqli` ✓ | keep |
| NoSQL (5.3.4, INPV-05.6) | `nosqli` ✓ | keep |
| ORM injection (INPV-05.7) | `sqli` (subsumed) | keep (note) |
| OS command (5.3.8, INPV-12) | `cmdi` ✓ | keep |
| **Code/eval injection (5.2.4, INPV-11)** | partial (cmdi ≠ eval) | **ADD `code_injection`** or fold |
| XSS reflected/stored/DOM (5.3.x, INPV-01/02) | `xss` (conflated) | keep (1 cell, pragmatic) |
| SSTI (5.2.5, INPV-18) | `ssti` ✓ | keep |
| SSRF (5.2.6, INPV-19) | `ssrf` ✓ | keep |
| XXE / XML injection (5.5.2/5.3.10, INPV-07) | `xxe` ✓ | keep |
| Path traversal / LFI (5.3.9, INPV-11.1) | `traversal` ✓ | keep |
| RFI (INPV-11.2) | partial | note (fold into traversal) |
| CRLF / HTTP splitting (INPV-15) | `crlf` ✓ | keep |
| HTTP smuggling (INPV-15) | `smuggling` ✓ | keep |
| Open redirect (5.1.5, INPV-?) | `redirect` ✓ | keep |
| Mass assignment (5.1.2) | `mass_assignment` ✓ | keep |
| Deserialization (5.5.1/5.5.3) | `deserial` (cookie-only) | **broaden applicability** |
| **LDAP injection (5.3.7, INPV-06)** | ❌ | **ADD `ldap`** |
| **XPath injection (5.3.10, INPV-09)** | ❌ | **ADD `xpath`** |
| **HTTP Parameter Pollution (5.1.1, INPV-04)** | ❌ | **ADD `hpp`** |
| **Host header injection (INPV-17)** | partial (`cache`) | **ADD `host_header`** |
| **SMTP/IMAP injection (5.2.3, INPV-10)** | ❌ | **ADD `smtp_injection`** (email eps) |
| SSI injection (INPV-08) | ❌ | note (rare — defer) |
| JSON injection / eval (5.3.6/5.5.4) | ❌ | note (minor — defer) |
| Format string (5.4.2, INPV-13) | ❌ | note (rare in web — defer) |
| HTTP verb tampering (INPV-03) | `method_tampering` ✓ | keep |
| **GraphQL** (WSTG API) | endpoint TYPE only | **ADD `graphql`** cells (introspection/batching/field-authz) |

### Non-injection ASVS/WSTG topics (pentest view) worth as cells
| Topic (chapter) | Current | Action |
|---|---|---|
| Cookie flags Secure/HttpOnly/SameSite (Session) | ❌ | **ADD `cookie_security`** (one-response, Phase-0 style) |
| Verbose errors / stack-trace / debug disclosure (Error Handling, V7) | ❌ (model files findings, no cell) | **ADD `verbose_errors`** (one-response) |
| Unrestricted file upload / type bypass (V12) | `upload` endpoint type only | **ADD `file_upload`** for upload eps |
| Excessive data exposure (API) | ❌ | model-only (reasoning) |
| Clickjacking | `security_headers` (X-Frame) ✓ | keep |
| Auth: brute/MFA/pw-policy/user-enum | `/credential-audit` skill | keep skill-driven |
| Session fixation / token entropy | `/param-fuzz`, `jwt` | keep skill-driven |
| Business logic / value abuse / workflow | `race`, `/business-logic` | keep skill-driven |
| TLS / transport / data-at-rest | `/ssl-tls-audit` | keep skill-driven |

**Recommended cell additions:** `ldap, xpath, hpp, host_header, smtp_injection,
graphql, code_injection`, cross-cutting `cookie_security, verbose_errors`, and
`file_upload` for upload endpoints. Broaden `deserial` beyond cookies.

### Proposed APPLICABILITY (the "correct cells")
```
query/default:     + hpp, ldap, xpath              (search/lookup params)
body_form/default: + ldap, xpath
body_json/default: + ldap, hpp, code_injection
header/default:    (smuggling, crlf, xss, ssrf, host_header)  + host_header
cookie/default:    (sqli, xss, deserial)
endpoint/default:  + cookie_security, verbose_errors          (one-response)
upload/*:          + file_upload                              (upload eps)
graphql/*:         graphql_introspection, graphql_batching, graphql_field_authz
email-ish eps:     + smtp_injection
```
(LDAP/XPath fan only onto params that plausibly hit a directory/XML backend — gate
by value_hint where possible to avoid bloating every text param.)

---

## 2. Tool arsenal — current + installs

**Already in the kali image:** `sqlmap, commix, xsser, wapiti, nikto, skipfish,
zaproxy, nuclei (+dast), wpscan, jwt_tool, ffuf/feroxbuster/katana/wfuzz,
interactsh-client (OOB), testssl/sslyze`.

**To install (upgrades detector CLEAN-trust from Partial → Automatable):**
| Tool | Cell(s) upgraded | Install |
|---|---|---|
| **dalfox** | `xss` (reflected/stored/DOM, context-aware) | prebuilt release binary (arm64/amd64) |
| **SSTImap** | `ssti` (multi-engine confirm + exploit) | git + pip (maintained tplmap fork) |
| **nosqli** (Charlie-belmer, Go) | `nosqli` | prebuilt binary / go |
| **arjun** | param discovery (find params to test) | pip |
| **graphql-cop** + **graphw00f** | `graphql_*` | pip |
| (optional) **gopherus / ssrfmap** | `ssrf` exploitation depth | git |

No good specialist exists for `ldap / xpath / hpp / host_header / smtp_injection /
ssi` — those stay **nuclei -dast + wapiti + targeted manual probe** (Partial).

---

## 3. Detector-trust + endpoint_sweep table (with the new tools/cells)

VULN-trust = a "vulnerable" verdict is a true positive. CLEAN-trust = "no finding"
means genuinely clean (the honesty crux).

| Cell | Detector (after installs) | VULN | CLEAN | Evidence / OOB | Sweep action | Tier |
|---|---|---|---|---|---|---|
| sqli | `sqlmap --level --risk` | High | High | sqlmap verdict | vuln→finding / `tested_clean` | **Auto** |
| cmdi | `commix` (+OOB blind) | High | Med-High | commix / OAST | vuln→finding / `tested_clean` | **Auto** |
| code_injection | `commix --technique` + eval polyglot | High | Med | evaluated output | vuln→finding / `scanned_clean` | Partial |
| ssrf | OOB payload + `oob_poll` | High | Med | interactsh hit | vuln on callback / `scanned_clean` | **Auto** |
| xxe | OOB (XML entity) + `wapiti` | High | Med | interactsh hit | vuln on callback / `scanned_clean` | **Auto** (XML eps) |
| xss | **dalfox** | High | Med-High | dalfox PoC | vuln→finding / `scanned_clean` | **Auto** (reflected) |
| ssti | **SSTImap** | High | Med-High | engine+exec proof | vuln→finding / `scanned_clean` | **Auto** |
| nosqli | **nosqli** | High | Med | operator-inj verdict | vuln→finding / `scanned_clean` | **Auto** |
| traversal | `nuclei -dast` lfi + `../etc/passwd` sig | High | Med | file-content match | vuln→finding / `scanned_clean` | Partial |
| crlf | `nuclei -dast` crlf | Med-High | Med | injected header | vuln→finding / `scanned_clean` | Partial |
| redirect | `nuclei -dast` redirect + Location | High | Med-High | Location header | vuln→finding / `scanned_clean` | **Auto** |
| ldap | `nuclei -dast` + manual `*)(uid=*` | Med | Low | auth bypass / error | vuln→finding / leave pending | Partial/Model |
| xpath | manual `' or '1'='1` XPath + error | Med | Low | XPath error / bypass | vuln→finding / leave pending | Partial/Model |
| hpp | manual dup-param + behavior diff | Med | Low | param-precedence diff | vuln→finding / leave pending | Model |
| host_header | manual `Host:`/`X-Forwarded-Host` override | Med-High | Med | reflected host / pw-reset poison | vuln→finding / `scanned_clean` | Partial |
| smtp_injection | manual CRLF in email field | Med | Low | header inj observed | vuln→finding / leave pending | Model |
| graphql | **graphql-cop / graphw00f** | Med-High | Med-High | introspection on / batching | vuln→finding / `tested_clean` | **Auto** (graphql eps) |
| smuggling | `nuclei` smuggling / manual | Med | Low | desync observed | model | Model |
| prototype | manual `__proto__` + behavior | Low-Med | Low | pollution effect | model | Model |
| deserial | manual (ysoserial-class) | Low-Med | Low | gadget effect | model | Model |
| idor / bfla | 2-user diff (no tool) | reasoning | reasoning | cross-user access | model | Model |
| mass_assignment | extra-field + privilege diff | reasoning | reasoning | privilege change | model (auto-link on find) | Model |
| **cross-cutting** ↓ | | | | | | |
| cors/csrf/security_headers/cache | one response | — | — | headers | **Phase 0 ✓** | Auto |
| cookie_security | one response (Set-Cookie flags) | High | High | flag presence | **Phase 0-style auto** | Auto |
| verbose_errors | one response / error-trigger | High | Med | stack trace / debug body | **Phase 0-style auto** | Auto |
| rate_limit | burst of N requests | High | Med-High | 429 absence | sweep (burst) | Partial |
| method_tampering | OPTIONS / verb swap | High | Med | allowed verbs | sweep | Partial |
| jwt | **jwt_tool** (alg:none, weak secret) | High | Med-High | forged token accepted | sweep | **Auto** |
| file_upload | manual (type/ext bypass) | Med | Low | shell upload | model | Model |

---

## 4. What the `endpoint_sweep` becomes

Per app/endpoint, auth-injected (session JWT + correct content-type), the sweep
orchestrates **engines by tool** (not per-cell) and maps structured output → cells:

1. **`sqlmap`** per injectable param → sqli (full verdict, both directions).
2. **`dalfox` + `SSTImap` + `nosqli`** → xss / ssti / nosqli (Auto after install).
3. **`nuclei -dast` + `wapiti`** one pass → traversal / crlf / redirect / xxe / ldap
   / host_header (`vulnerable` on confirmed, `scanned_clean` otherwise).
4. **OOB-instrumented probes** → ssrf / xxe / blind-cmdi (`vulnerable` on callback).
5. **`jwt_tool`** → jwt; one-response checks → cookie_security / verbose_errors.
6. **`graphql-cop`/`graphw00f`** on graphql endpoints.
7. **Untouched (model-only):** idor, bfla, mass_assignment, hpp, smtp_injection,
   prototype, deserial, smuggling, file_upload, business-logic.

**Honesty rules baked in:**
- `vulnerable` auto-close only from **high-confidence** detectors (sqlmap-confirmed,
  OOB callback, dalfox/SSTImap PoC, evaluated SSTI) — never a raw noisy ZAP/nuclei
  alert (those surface to the model to confirm).
- Partial-clean is **`scanned_clean`** (labeled "a real scanner tested this, not
  deep-verified"), never `tested_clean`.
- Model-only cells are **never** touched by the sweep.
- Every closure cites the tool artifact; auth-block / reuse-cap guards stay.

This makes the Auto + Partial cells (the bulk) closeable honestly and cheaply, so
the now-enforced coverage floor is reachable — then we raise it.

---

## Self-critique
- **CLEAN-trust is the whole game** — keep `scanned_clean` distinct or we recreate
  the grind regression.
- **Auth/state**: sweeps must inject the captured JWT + correct body format or every
  cell false-negatives (401) — the auth-block guard will (correctly) reject those.
- **Scanner false-positives** (ZAP/nuclei dast noisy) → only high-confidence
  detectors auto-file `vulnerable`.
- **Per-param cost**: batch by tool (one wapiti / nuclei-dast pass covers many
  cells); reserve per-param sqlmap for injectable-looking params.
- **LDAP/XPath/HPP fan-out**: gate by value_hint so we don't add 3 dead cells to
  every text param.
