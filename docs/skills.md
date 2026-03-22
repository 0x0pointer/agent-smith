# Skills Reference

Skills are slash commands that expand into detailed instructions for Claude. They live in a separate repo ([github.com/0x0pointer/skills](https://github.com/0x0pointer/skills)) pulled in as a git submodule at `skills/`, and are installed into `~/.claude/commands/` or `~/.claude/skills/` by `install.sh`.

---

## `/codebase`

White-box source code security review structured around OWASP ASVS 5.0 (427 verification requirements). Reads and understands application source code to build a security knowledge base that enriches all downstream skills.

```
/codebase /path/to/project depth=standard
/codebase /path/to/project depth=thorough focus=auth
/codebase /path/to/project depth=quick
```

**What it does:**

1. **Orientation** — identify tech stack, framework, dependencies, project structure, configuration
2. **Attack surface mapping** — extract ALL route/endpoint definitions from source code with auth/middleware annotations
3. **Auth architecture** — map authentication mechanism, session config, authorization model, token handling (ASVS V6-V10)
4. **Automated scanning** — semgrep SAST + trufflehog secret scanning in parallel
5. **Dangerous pattern analysis** — injection, output encoding, deserialization, input validation, file handling, business logic (ASVS V1-V5)
6. **Infrastructure review** — cryptography, TLS config, secret management, data protection, error handling, IaC (ASVS V11-V16)
7. **Security profile output** — structured summary for downstream skills + ASVS coverage map

**Depth presets:**

| Depth | What runs | Cost | Time | Calls |
|---|---|---|---|---|
| `quick` | Orientation + automated scanning (semgrep + trufflehog) | $0.10 | 15 min | 10 |
| `standard` | quick + route mapping + auth review + dangerous patterns | $0.50 | 45 min | 30 |
| `thorough` | full ASVS-mapped review + IaC + crypto + source-to-sink tracing | $2.00 | 120 min | 60 |

**Chains into:** `/threat-model` (real architecture from code), `/pentester` (targeted scanning of discovered endpoints), `/web-exploit` (source-to-sink context), `/cloud-security` (IaC verification), `/analyze-cve` (full code context for CVE tracing).

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
| `thorough` | standard + full Kali toolchain | $2.00 | 120 min | unlimited |

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

## `/remediate`

Generates specific, implementable fixes for every finding in `findings.json`. Produces code patches (unified diff), configuration changes, dependency updates, and IaC fixes — not generic advice but actual before/after code.

```
/remediate depth=thorough
/remediate finding-id-here
```

**What it does:**

1. Reads all findings from the dashboard API
2. For each finding (critical/high first), generates a specific fix based on the vulnerability type and framework
3. PATCHes each finding with a `remediation` object containing: summary, diff, before/after code, effort level, breaking change flag, OWASP references, and verification step
4. Uses the finding's `reproduction` command as the regression test: "run this after the fix — it should now fail"

**Dashboard integration:** Each finding with remediation shows a "Fix" button that expands to show the diff, effort level, and verification steps.

**Export integration:** `/gh-export` includes a `## Remediation` section in each GitHub issue when remediation data is present.

**Depth presets:**

| Depth | What runs | Cost | Time | Calls |
|---|---|---|---|---|
| `quick` | Summary fix + effort level per finding | $0.10 | 10 min | 10 |
| `thorough` | Full diff + before/after + references + verification per finding | $0.50 | 30 min | 30 |

---

## `/gh-export`

Formats all confirmed findings from `findings.json` as copy-pasteable GitHub issue blocks, following the AppSec reporting guide template. Now includes a `## Remediation` section with code diffs and verification steps when `/remediate` has run. After generating each block, patches the finding in `findings.json` with the formatted text so the dashboard can surface it.

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

## `/osint`

Deep passive OSINT reconnaissance using the MITRE ATT&CK Reconnaissance framework. All techniques are passive — no active exploitation.

```
/osint secureby.design thorough
/osint example.com depth=standard
/osint acme-corp.io depth=quick
```

**What it does:**

1. Calls `start_scan` with target domain and depth
2. **DNS & WHOIS** — registrant info, name servers, MX/TXT/NS records, DNSSEC status
3. **Certificate Transparency** — subdomain discovery via crt.sh, historical cert analysis, wildcard detection
4. **Email harvesting** — theHarvester across all sources, SMTP verification (VRFY/EXPN/RCPT TO), catch-all detection
5. **Infrastructure mapping** — amass, dnsrecon, fierce, whatweb, wafw00f, dnstwist (typosquatting)
6. **Subdomain takeover detection** — CNAME enumeration, dangling record identification, service-specific fingerprints
7. **Wayback Machine** — archived endpoints, deprecated APIs, leaked secrets in JS bundles, historical architecture
8. **Social media & GitHub** — org repos, commit author emails, secrets in code, employee discovery
9. **Cloud storage enumeration** — S3, Azure Blob, GCS bucket fuzzing
10. **Document metadata extraction** — metagoofil + exiftool for employee names, software versions, GPS coordinates
11. Calls `report_diagram` with infrastructure map
12. Calls `complete_scan` — chains into `/pentester` if active scanning is authorized

Every finding is scored by confidence: **Confirmed** (authoritative source), **Likely** (2+ independent sources), or **Speculative** (single source).

**Depth presets:**

| Depth | Tools | Cost | Time | Calls |
|---|---|---|---|---|
| `quick` | theHarvester + subfinder + WHOIS + DNS + crt.sh | $0.05 | 10 min | 8 |
| `standard` | quick + amass + email verification + Wayback + metadata | $0.20 | 30 min | 20 |
| `thorough` | standard + Shodan + cloud enum + social + takeover detection | $0.50 | 60 min | 40 |

---

## `/container-k8s-security`

Comprehensive container and Kubernetes security assessment covering OWASP Kubernetes Top 10 and all 22 Kubernetes Goat attack scenarios.

```
/container-k8s-security kind-cluster type=kubernetes perspective=external depth=thorough
/container-k8s-security docker-host type=docker depth=standard
```

**What it does:**

1. **Service discovery** — K8s infrastructure ports (API server, etcd, kubelet, Docker daemon, registries, NodePorts)
2. **API server & control plane probing** — anonymous auth, etcd direct access, kubelet RCE via /run
3. **NodePort enumeration** — scan 30000-32767, identify exposed services
4. **Pod security audit** — privileged containers, host namespaces, hostPath mounts, dangerous capabilities, missing resource limits
5. **Container escape analysis** — Docker/containerd socket mounts, privileged chroot escape, hostPath abuse
6. **RBAC audit** — cluster-admin bindings, wildcard permissions, SA token API probing, pod creation RBAC
7. **Secrets exposure** — K8s secrets enumeration, env var injection, .git in containers, etcd encryption check
8. **Image supply chain** — Trivy scanning, image layer inspection (crictl/docker history), private registry attacks, crypto miner detection
9. **Network segmentation** — NetworkPolicy presence, cross-namespace connectivity, SSRF to cloud metadata
10. **CIS benchmarks** — kube-bench (deployed as K8s Job), docker-bench-security (containerd-aware)
11. **Defensive controls gap analysis** — admission controllers, PodSecurity, runtime security, audit logging
12. Calls `report_diagram` with attack path map and `complete_scan`

**Depth presets:**

| Depth | Tools | Cost | Time | Calls |
|---|---|---|---|---|
| `quick` | Discovery + API probing + anonymous auth | $0.10 | 15 min | 10 |
| `standard` | quick + pod security + RBAC + secrets + images | $0.50 | 45 min | 30 |
| `thorough` | standard + CIS benchmarks + network + escape exploitation + defense gaps | $2.00 | 120 min | 60 |

---

## `/cloud-security`

Cloud security posture assessment for AWS, Azure, and GCP — IAM privilege escalation, public storage, serverless attack surface, database exposure, logging gaps, and compliance mapping.

```
/cloud-security my-aws-account provider=aws mode=authenticated depth=standard
/cloud-security 10.0.0.5 provider=aws mode=external depth=quick
/cloud-security my-project provider=gcp mode=authenticated depth=thorough
```

**What it does:**

1. **External recon** — public bucket/blob scanning, IMDS probing (AWS/Azure/GCP metadata endpoints), nuclei cloud templates
2. **IAM privilege escalation** — systematic testing of iam:PassRole+Lambda, iam:CreatePolicyVersion, iam:AttachUserPolicy, sts:AssumeRole chains, cross-account trust abuse (10 escalation vectors with severity matrix)
3. **Storage deep-dive** — bucket policies, ACLs, versioning, encryption, cross-account access, pre-signed URL abuse, object-level ACL enumeration
4. **Network security** — security groups/NSGs open to 0.0.0.0/0, critical port exposure
5. **Serverless attack surface** — Lambda/Functions env var secrets, layer inspection, API Gateway auth bypass, Step Functions state injection
6. **Database exposure** — RDS/DynamoDB/ElastiCache/DocumentDB/OpenSearch public access, encryption, snapshot sharing
7. **Logging validation** — CloudTrail, VPC Flow Logs, GuardDuty, Security Hub, Config
8. **Container registry security** — ECR/ACR/Artifact Registry scanning, cross-account pull, immutability
9. **Cloud-specific attacks** — resource policy confusion, SSM/Secrets Manager enumeration, managed identity abuse, service account key audit
10. **Automated scanning** — Prowler + ScoutSuite
11. **Attack path mapping** — chains from public exposure to sensitive data access
12. **Compliance mapping** — SOC 2, PCI DSS 4.0, HIPAA, CIS benchmarks

**Depth presets:**

| Depth | Tools | Cost | Time | Calls |
|---|---|---|---|---|
| `quick` | Public bucket scan + IMDS probe + nuclei cloud templates | $0.10 | 15 min | 10 |
| `standard` | quick + IAM escalation + storage deep-dive + security groups | $0.50 | 45 min | 25 |
| `thorough` | standard + Prowler/ScoutSuite + serverless + databases + logging + container registry + attack paths + compliance | $2.00 | 120 min | 60 |

---

## `/ssl-tls-audit`

Deep TLS/SSL configuration audit with compliance mapping to PCI DSS 4.0, NIST SP 800-52r2, and FedRAMP.

```
/ssl-tls-audit secureby.design depth=thorough
/ssl-tls-audit 10.0.0.1:443 depth=standard
/ssl-tls-audit mail.example.com depth=quick
```

**What it does:**

1. Calls `start_scan` with target and depth
2. **Automated scanning** — testssl.sh, sslscan, sslyze, nuclei SSL templates in parallel
3. **Protocol version analysis** — SSLv2/3, TLS 1.0/1.1/1.2/1.3 support and enforcement
4. **Cipher suite & ordering** — NULL, EXPORT, DES, RC4, 3DES, CBC, DHE strength, server preference
5. **Certificate chain validation** — validity, chain completeness, key size, SAN, CT logs, OCSP stapling
6. **Known vulnerability testing** — Heartbleed, POODLE, BEAST, CRIME, BREACH, ROBOT, DROWN, Lucky13, Ticketbleed, GOLDENDOODLE
7. **ECDHE curve analysis** — P-256, P-384, P-521, X25519, brainpool, preference enforcement
8. **TLS 1.3 specific** — 0-RTT replay, PSK modes, downgrade detection, GREASE, TLS_FALLBACK_SCSV
9. **Session management** — ticket reuse, session ID fixation, resumption, ticket lifetime
10. **Renegotiation** — client-initiated DoS, secure renegotiation (RFC 5746)
11. **HSTS analysis** — max-age, includeSubDomains, preload list, subdomain bypass
12. **Certificate revocation** — CRL distribution points, OCSP responder, stapled response freshness
13. **Multi-port TLS scanning** — 20+ TLS-bearing ports (SMTP, IMAP, LDAPS, RDP, MQTT, etc.)
14. **Compliance mapping** — PCI DSS 4.0 Section 4, NIST SP 800-52r2, FedRAMP controls
15. Calls `report_finding` for every confirmed weakness with compliance impact

**Depth presets:**

| Depth | Tools | Cost | Time | Calls |
|---|---|---|---|---|
| `quick` | testssl quick mode + HSTS check | $0.05 | 5 min | 5 |
| `standard` | testssl full + sslscan + nuclei SSL + HTTP headers + cert chain | $0.20 | 15 min | 12 |
| `thorough` | standard + openssl manual + nmap + multi-port + TLS 1.3 deep + session + renegotiation + revocation + compliance | $0.50 | 30 min | 25 |

---

## `/network-assess`

Internal network assessment — assumes attacker has physical or VPN access to the target network.

```
/network-assess 192.168.1.0/24 depth=standard
/network-assess 10.0.0.0/16 depth=thorough
/network-assess 172.16.0.0/24 depth=quick
```

**What it does:**

1. **Host discovery** — ARP scan, ping sweep, NetBIOS enumeration
2. **Port scanning & service detection** — naabu fast scan, nmap service detection, full port scan at thorough depth
3. **Broadcast protocol analysis** — LLMNR/NBT-NS/mDNS detection (poisoning risk for credential capture)
4. **SNMP enumeration** — community string brute-force, SNMP walk for device info, routing tables, processes
5. **Share enumeration** — SMB shares (null session, anonymous), NFS exports
6. **Network segmentation testing** — inter-VLAN access, firewall rule testing, DNS segmentation
7. **Infrastructure device audit** — router/switch discovery, default credentials, SSH audit
8. Calls `report_diagram` with network topology and `complete_scan`

**Depth presets:**

| Depth | Tools | Cost | Time | Calls |
|---|---|---|---|---|
| `quick` | host discovery + top-100 ports + service ID | $0.10 | 15 min | 10 |
| `standard` | quick + top-1000 ports + SMB/SNMP/NFS enum + broadcast protocols | $0.50 | 45 min | 25 |
| `thorough` | standard + full port scan + segmentation testing + router/switch audit | $2.00 | 120 min | 60 |

## `/ad-assessment`

Active Directory security audit using the MITRE ATT&CK framework — full domain enumeration, ADCS attacks (ESC1-ESC8), delegation abuse, ACL analysis, GPO security, BloodHound attack paths, and forest trust exploitation.

```
/ad-assessment 10.0.0.1 domain=CORP.LOCAL user=auditor pass=P@ssw0rd depth=standard
/ad-assessment dc01.corp.local domain=CORP.LOCAL depth=thorough
/ad-assessment 192.168.1.10 depth=quick
```

**What it does:**

1. **Domain enumeration** — functional level, password policy, privileged groups, Machine Account Quota, Protected Users
2. **Kerberos attacks** — Kerberoasting (SPN enumeration + hash cracking), AS-REP Roasting
3. **Service account security** — SPN accounts with old passwords, gMSA detection, DONT_EXPIRE_PASSWORD
4. **ADCS assessment** — ESC1 through ESC8 (SAN abuse, enrollment agent, template ACL, CA flags, NTLM relay to HTTP enrollment)
5. **Delegation analysis** — unconstrained, constrained (S4U2Proxy), RBCD
6. **Fine-grained password policies** — FGPP precedence, weak policies on service accounts
7. **LAPS deployment** — coverage gaps, v1 vs v2, unauthorized read access
8. **GPO security** — GPP passwords, writable GPOs, security-critical settings (logon scripts, scheduled tasks, restricted groups)
9. **ACL analysis** — dangerous permissions (DCSync, WriteDACL, GenericAll on AdminSDHolder), GUID-decoded rights
10. **BloodHound collection** — shortest path to DA, Kerberoastable with DA path, unconstrained delegation
11. **Forest trust analysis** — SID filtering, selective authentication, trust key extraction
12. **Attack path prioritization** — P0 (immediate DA) through P3 (defense gaps)

**Depth presets:**

| Depth | Tools | Cost | Time | Calls |
|---|---|---|---|---|
| `quick` | Domain enum + password policy + privileged groups + Kerberoasting + AS-REP | $0.10 | 15 min | 10 |
| `standard` | quick + ADCS (ESC1-ESC8) + delegation + GPO + ACL + FGPP + LAPS + service accounts | $0.50 | 45 min | 25 |
| `thorough` | standard + BloodHound + forest trust analysis + attack path prioritization | $2.00 | 120 min | 60 |

---

## `/email-security`

Email infrastructure security audit — SPF, DKIM, DMARC configuration, open relay testing, spoofing resilience, MTA-STS, and SMTP security.

```
/email-security example.com depth=standard
/email-security corp.local depth=thorough
/email-security acme.io depth=quick
```

**What it does:**

1. **DNS record analysis** — SPF record validation (syntax, `+all` vs `-all`, lookup count), DKIM selector discovery, DMARC policy check (`p=none` vs `reject`, reporting)
2. **SMTP service analysis** — STARTTLS support, certificate validation, banner information disclosure
3. **Open relay testing** — swaks relay test to external domain (critical if accepted)
4. **Spoofing resilience** — send spoofed email as internal user, test acceptance
5. **User enumeration** — VRFY, EXPN, RCPT TO response differences
6. **MTA-STS policy** — fetch and verify policy mode (enforce/testing/none), MX alignment
7. **TLS-RPT** — TLSRPT DNS record for failure reporting

**Depth presets:**

| Depth | Tools | Cost | Time | Calls |
|---|---|---|---|---|
| `quick` | SPF + DKIM + DMARC + MX lookup | $0.05 | 5 min | 5 |
| `standard` | quick + STARTTLS + MTA-STS + open relay + spoofing test | $0.15 | 15 min | 12 |
| `thorough` | standard + user enumeration + full SMTP audit + TLS cert analysis | $0.30 | 30 min | 20 |

---

## `/post-exploit`

Post-exploitation workflow — privilege escalation, credential harvesting, persistence assessment, and pivot preparation. Uses LinPEAS/WinPEAS as primary enumeration with dynamic GTFOBins cross-referencing.

```
/post-exploit 10.0.0.5 os=linux access=ssh current-user=www-data depth=standard
/post-exploit 10.0.0.10 os=windows access=winrm current-user=svc_web depth=thorough
/post-exploit 192.168.1.50 os=linux access=shell depth=quick
```

**What it does:**

1. **Local enumeration** — `quick`: minimal checks (id, sudo -l, SUID, whoami /priv); `standard+`: LinPEAS/WinPEAS comprehensive scan with output parsing guidance
2. **Privilege escalation** — decision tree: sudo rules, GTFOBins (40+ binaries with dynamic cross-reference), kernel exploits (DirtyPipe, DirtyCow, PwnKit, OverlayFS), Potato attacks (GodPotato, PrintSpoofer, JuicyPotato), token manipulation, DLL hijacking, container escapes
3. **Credential harvesting** — shadow hashes, SSH keys + agent hijacking, process memory, config files, browser credentials, LSASS/SAM/DPAPI, hash cracking with john
4. **Persistence assessment** — cron, systemd, SSH authorized_keys, init scripts, registry Run keys, scheduled tasks, WMI subscriptions
5. **Pivot preparation** — network mapping from compromised host, credential reuse testing, SSH key reuse

**Depth presets:**

| Depth | Tools | Cost | Time | Calls |
|---|---|---|---|---|
| `quick` | Manual checks only (decision tree inputs) + exploitation + credential search | $0.10 | 15 min | 10 |
| `standard` | LinPEAS/WinPEAS + targeted exploitation + hash extraction + credential harvesting | $0.50 | 45 min | 25 |
| `thorough` | Standard + kernel exploits + container escapes + token manipulation + persistence + pivot | $2.00 | 120 min | 60 |

---

## `/metasploit`

Exploit validation and exploitation using Metasploit Framework. Runs in a **dedicated Docker container** (separate from Kali). Validates CVEs discovered by nuclei, nikto, or other scanners with actual exploit modules.

```
/metasploit 10.0.0.5 cve=CVE-2017-0144 depth=standard
/metasploit 192.168.1.10 service=http cve=CVE-2021-44228 depth=thorough
/metasploit 10.0.0.1 depth=quick
```

**What it does:**

1. **Module discovery** — searches Metasploit module database by CVE or service keyword
2. **Vulnerability validation** — runs auxiliary scanner modules to confirm without exploiting
3. **Exploitation** — runs exploit modules with configurable payloads (safe to reverse shell)
4. **Post-exploitation** — session management, hashdump, sysinfo, pivoting
5. **Payload generation** — msfvenom for custom payloads

**Depth presets:**

| Depth | Tools | Cost | Time | Calls |
|---|---|---|---|---|
| `quick` | Auxiliary scanner modules only — validate without exploitation | $0.10 | 15 min | 10 |
| `standard` | quick + exploit modules with safe payloads (cmd/unix/generic) | $0.50 | 45 min | 25 |
| `thorough` | standard + reverse shells + post-exploitation + pivoting | $2.00 | 120 min | 60 |

**Docker setup:** Requires its own image (based on `metasploitframework/metasploit-framework`):
```bash
docker build -t pentest-agent/metasploit ./tools/metasploit/
```

---

## `/reverse-shell`

Reverse shell payload generation and listener management. Generates platform-specific payloads and sets up listeners in the Kali container.

```
/reverse-shell 10.0.0.5 lhost=10.0.0.1 lport=4444 type=bash
/reverse-shell 10.0.0.10 type=powershell encode=base64
/reverse-shell 10.0.0.5 type=msfvenom
```

**What it does:**

1. **Payload generation** — bash, python, php, perl, ruby, netcat, socat, powershell, awk, msfvenom (ELF, EXE, WAR, JSP, PHP, ASP)
2. **Encoding** — base64, URL-encode, hex for WAF/filter bypass
3. **Listener setup** — ncat, socat, Meterpreter multi/handler, encrypted (OpenSSL)
4. **Shell stabilization** — python pty.spawn, script, socat TTY upgrade
5. **Decision tree** — selects payload based on target OS and available interpreters

No new tools needed — uses ncat, socat, msfvenom, openssl already in Kali.

---

## Chaining skills

Skills are designed to be chained automatically during an engagement:

```
Before a pentest
  ├── /codebase               if source code available — ASVS 5.0 white-box review
  ├── /osint                  passive recon — subdomains, emails, tech stack, cloud storage
  └── /threat-model           identify high-risk areas to focus the scan

During a pentest (/pentester)
  ├── /analyze-cve            if nuclei or semgrep finds a CVE dependency
  ├── /web-exploit            injection point or logic flaw found — deep SQLi, XSS, SSRF, parameter tampering
  ├── /metasploit             if exploitable CVE confirmed — validate with Metasploit modules
  ├── /reverse-shell          exploit needs a callback — payload generation + listener setup
  ├── /ssl-tls-audit          if TLS services are found — PCI DSS/NIST compliance audit
  ├── /network-assess         if internal network scope — segmentation, SNMP, broadcast protocols
  ├── /credential-audit       weak auth found — brute-force, spraying, default credentials
  ├── /post-exploit           initial access obtained — privesc, credential harvesting, pivot
  ├── /container-k8s-security if Docker/K8s infrastructure is discovered
  ├── /cloud-security         if AWS/Azure/GCP infrastructure is discovered
  ├── /ad-assessment          if Active Directory domain is discovered
  ├── /email-security         if SMTP services found (port 25/465/587)
  └── /ai-redteam             if an LLM endpoint is discovered

After initial access (/post-exploit)
  ├── /lateral-movement       credentials + pivot opportunities — pass-the-hash, Kerberoasting
  ├── /ad-assessment          domain environment — ADCS, delegation, ACLs, trust analysis
  └── /credential-audit       harvested hashes — crack and test credentials

During a codebase scan
  └── /analyze-cve            trace CVE reachability in code

For AI/LLM targets (instead of /pentester)
  └── /ai-redteam             OWASP LLM Top 10 assessment

After a pentest
  ├── /threat-model           STRIDE analysis based on discovered architecture
  ├── /remediate              generate specific fixes for every finding
  ├── /aikido-triage          if an Aikido CSV export is available
  └── /gh-export              format findings as GitHub issues (includes remediation)
```

Claude chains these automatically based on context — you can also invoke them manually at any point.
