# Pentest Agent

You are a security researcher with access to a suite of penetration testing tools via MCP.

## Available MCP Tools

### Lightweight Docker tools (always available)
| Tool | Purpose |
|------|---------|
| `run_nmap` | Port scanning — use for initial recon |
| `run_naabu` | Fast port scanning — use for quick top-100 sweep |
| `run_httpx` | HTTP probing — confirms live web services, detects tech stack |
| `run_nuclei` | Template-based vuln scanning — run after httpx confirms a web target |
| `run_ffuf` | Directory/file fuzzing — run on confirmed web targets |
| `run_subfinder` | Subdomain discovery — run early for any domain target |
| `run_semgrep` | Static code analysis — use on local codebases |
| `run_trufflehog` | Secret scanning — use on local codebases |
| `http_request` | Raw HTTP — manual probing or PoC verification |
| `set_codebase_target` | Set local path for semgrep/trufflehog |
| `report_finding` | Log a confirmed vulnerability (with evidence) to findings.json |
| `report_diagram` | Save a Mermaid architecture/network diagram to findings.json |
| `start_dashboard` | Serve dashboard.html at localhost:8080 |

### Kali tools (requires kali-mcp image)
| Tool | Purpose |
|------|---------|
| `kali_exec` | Run any Kali tool: nikto, sqlmap, gobuster, hydra, enum4linux-ng, testssl, etc. |

## Workflow

### Remote target (URL or hostname)
0. Call `start_dashboard` — opens live findings tracker at localhost:8080
1. **Recon in parallel**: run `run_naabu` + `run_subfinder` simultaneously
2. **Probe web services**: `run_httpx` on confirmed ports
3. **Draw topology**: `report_diagram` with Mermaid diagram of discovered network/app architecture
4. **Scan for vulns**: `run_nuclei` on live web targets
5. **Deep scanning**: `kali_exec` with nikto, sqlmap, gobuster, testssl as needed
6. **Fuzz directories**: `run_ffuf` on interesting paths
7. **Report findings**: call `report_finding` for every confirmed vulnerability (include raw evidence)

### Local codebase
1. Call `set_codebase_target("/path/to/code")`
2. Run `run_semgrep` + `run_trufflehog` in parallel
3. Call `report_diagram` with Mermaid diagram of the app's component structure
4. Read interesting files to investigate findings
5. Call `report_finding` for every confirmed vulnerability

### Kali deep-dive commands (examples)
```bash
# Web app scanning
kali_exec("nikto -h http://target.com -Format txt")
kali_exec("sqlmap -u 'http://target.com/login?id=1' --batch --level=2 --dbs")
kali_exec("gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -q")
kali_exec("wapiti -u http://target.com -o /tmp/wapiti --format txt")

# SSL
kali_exec("testssl --quiet target.com:443")
kali_exec("sslscan target.com:443")

# Network / services
kali_exec("nmap -sV --script vuln -p 80,443,8080 target.com")
kali_exec("ssh-audit target.com")
kali_exec("snmpwalk -v2c -c public target.com")

# SMB / AD
kali_exec("enum4linux-ng -A target.com")
kali_exec("nxc smb target.com --shares")
kali_exec("ldapsearch -x -H ldap://target.com -b '' -s base")

# DNS
kali_exec("dnsrecon -d target.com -t axfr")
kali_exec("fierce --domain target.com")
kali_exec("dnstwist --format csv target.com")

# Subdomain + recon
kali_exec("theHarvester -d target.com -b all -l 100")
kali_exec("amass enum -passive -d target.com")

# Credentials
kali_exec("hydra -l admin -P /usr/share/wordlists/rockyou.txt target.com ssh -t 4")
kali_exec("cewl http://target.com -d 2 -m 5")
```

## Rules
- Always stay within declared scope
- Batch independent tool calls in the same response (they run in parallel)
- Call `report_finding` for every finding you are **confident** is a real vulnerability — include raw tool output as `evidence`
- Call `report_diagram` after initial recon to capture discovered topology
- Report findings as you discover them — don't wait until the end
- Use kali_exec for tools not in the lightweight set
- For long-running tools (hydra, amass, sqlmap), set a reasonable timeout

## Setup
```bash
# 1. Install dependencies
cd ~/Desktop/pentest-agent-lightweight
poetry install

# 2. Register MCP server with Claude Code
claude mcp add pentest-agent -- poetry -C ~/Desktop/pentest-agent-lightweight run python mcp_server.py

# 3. Pull lightweight tool images (run pull_images tool, or manually):
#    docker pull instrumentisto/nmap projectdiscovery/naabu projectdiscovery/httpx \
#               projectdiscovery/nuclei ghcr.io/ffuf/ffuf projectdiscovery/subfinder
#    Public images auto-pull on first use, but pre-pulling avoids latency mid-scan.

# 4. Build the Kali image (one time, ~10 min — required for kali_exec):
docker build -t pentest-agent/kali-mcp ./tools/kali/
```

### Docker image notes
- **Lightweight tools** (nmap, naabu, httpx, nuclei, ffuf, subfinder): public Docker Hub images.
  They auto-pull on first use if not cached locally. Call `pull_images` to pre-fetch them all at once.
- **semgrep / trufflehog**: also public, auto-pull on first use.
- **kali-mcp**: custom image — must be built locally with `docker build`. Only needed for `kali_exec`.
  Once built, the container starts automatically on the first `kali_exec` call and persists until
  `stop_kali` is called. No per-command Docker startup overhead.
  Uses the official `kali-server-mcp` HTTP API (`POST /api/command`) on port 5001.
