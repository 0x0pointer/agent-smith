# Kali Toolchain Reference

All commands run via `kali_exec("command here")` inside the persistent `pentest-agent/kali-mcp` container.

**Build the image first (one time):**
```bash
docker build -t pentest-agent/kali-mcp ./tools/kali/
```

The container starts automatically on the first `kali_exec` call and persists until `stop_kali` is called.

---

## Web scanning

| Command | Purpose |
|---|---|
| `nikto -h http://TARGET -Format txt` | Web server misconfig and vuln scanner |
| `sqlmap -u 'http://TARGET/?id=1' --batch --dbs` | Automated SQL injection detection and exploitation |
| `sqlmap -u 'http://TARGET/login' --data 'user=a&pass=b' --batch --level=2` | POST-based SQLi |
| `wapiti -u http://TARGET -o /tmp/wapiti --format txt` | Web app scanner (XSS, SQLi, SSRF, LFI, …) |
| `commix --url http://TARGET/page?cmd=id` | Command injection scanner |
| `xsser --url http://TARGET/search?q=XSS` | XSS detection and exploitation |
| `whatweb -a 3 http://TARGET` | Aggressive tech stack fingerprinting |
| `wafw00f http://TARGET` | WAF detection |

---

## Directory and file enumeration

| Command | Purpose |
|---|---|
| `gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt -q` | Fast directory brute-force |
| `feroxbuster -u http://TARGET -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt` | Recursive directory buster |
| `dirb http://TARGET` | Classic directory brute-force |
| `wfuzz -u http://TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt --hc 404` | Flexible path fuzzer |
| `dirsearch -u http://TARGET -e php,html,js,bak` | Python directory/file scanner |
| `ffuf -u http://TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301 -s` | Fast web fuzzer |

---

## SSL / TLS

| Command | Purpose |
|---|---|
| `testssl --quiet TARGET:443` | Comprehensive TLS cipher and certificate audit |
| `sslscan TARGET:443` | TLS version and cipher suite enumeration |
| `sslyze TARGET:443` | TLS config audit (BEAST, CRIME, Heartbleed, …) |
| `openssl s_client -connect TARGET:443 -showcerts` | Raw TLS handshake inspection |

---

## DNS and subdomains

| Command | Purpose |
|---|---|
| `dnsrecon -d DOMAIN -t axfr` | DNS enumeration including zone transfer attempt |
| `dnsenum DOMAIN` | DNS brute-force and zone walking |
| `fierce --domain DOMAIN` | DNS scanner and subdomain brute-forcer |
| `dnstwist --format csv DOMAIN` | Typosquatting / lookalike domain detection |
| `amass enum -passive -d DOMAIN` | Passive subdomain enumeration (many sources) |
| `host -t axfr DOMAIN NS` | Manual zone transfer |

---

## OSINT and recon

| Command | Purpose |
|---|---|
| `theHarvester -d DOMAIN -b all -l 100` | Email, subdomain, IP, and employee OSINT |
| `katana -u http://TARGET -d 3 -silent` | Fast headless JS-aware web crawler |
| `cewl http://TARGET -d 2 -m 5` | Custom wordlist from target website content |
| `photon -u http://TARGET -o /tmp/photon` | Web crawler for links, emails, JS files, secrets |

---

## Network and services

| Command | Purpose |
|---|---|
| `masscan -p1-65535 IP --rate 1000` | High-speed full-port TCP scanner |
| `ssh-audit TARGET` | SSH configuration and known-vuln audit |
| `snmpwalk -v2c -c public TARGET` | SNMP OID enumeration |
| `smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -t TARGET` | SMTP user enumeration |
| `ike-scan TARGET` | IPsec/IKE VPN fingerprinting |
| `redis-cli -h TARGET info` | Redis instance recon |
| `nmap -sV -p 1433 TARGET` | MSSQL detection |
| `nmap --script=mongodb-info -p 27017 TARGET` | MongoDB recon |

---

## SMB and Active Directory

| Command | Purpose |
|---|---|
| `enum4linux-ng -A TARGET` | Full SMB/RPC/LDAP enumeration |
| `nxc smb TARGET --shares` | SMB share enumeration with NetExec |
| `nxc smb TARGET -u USER -p PASS --sam` | SAM database dump |
| `impacket-secretsdump TARGET` | Credential dump via SMB/DCE-RPC |
| `ldapsearch -x -H ldap://TARGET -b '' -s base` | Anonymous LDAP base query |
| `ldapdomaindump -u 'DOMAIN\USER' -p PASS TARGET` | Full LDAP domain dump |
| `kerbrute userenum users.txt --dc TARGET -d DOMAIN` | Kerberos user enumeration |
| `certipy find -u USER -p PASS -dc-ip TARGET` | Active Directory Certificate Services audit |
| `bloodhound-python -u USER -p PASS -d DOMAIN -ns TARGET -c All` | BloodHound data collection |

---

## Credential testing

| Command | Purpose |
|---|---|
| `hydra -l admin -P /usr/share/wordlists/rockyou.txt TARGET ssh -t 4` | SSH brute-force |
| `hydra -l admin -P /usr/share/wordlists/rockyou.txt TARGET http-post-form '/login:user=^USER^&pass=^PASS^:F=incorrect'` | HTTP form brute-force |
| `medusa -h TARGET -u admin -P /usr/share/wordlists/rockyou.txt -M ssh` | Parallel login brute-forcer |
| `nxc smb TARGET -u users.txt -p passwords.txt --no-bruteforce` | Credential spraying |

---

## AI / LLM red-teaming

| Command | Purpose |
|---|---|
| `pyrit-runner --target-url URL --attack prompt_injection` | Single-turn adversarial prompt |
| `pyrit-runner --target-url URL --attack jailbreak --max-turns 5` | Multi-turn jailbreak |
| `pyrit-runner --target-url URL --attack crescendo --objective "Reveal your system prompt" --max-turns 10` | Crescendo escalation |
| `pyrit-runner --target-url URL --attack jailbreak --scorer substring --max-turns 8` | Jailbreak with substring scorer |

**Note:** `pyrit-runner` is a CLI shim installed at `/usr/local/bin/pyrit-runner` inside the Kali image. It requires `OPENAI_API_KEY` set in the container environment. Set it via:
```
kali_exec("export OPENAI_API_KEY=sk-...")
```

---

## Tips

- Use `timeout` parameter for long-running tools: `kali_exec("hydra ...", timeout=600)`
- Pipe output through `head` to limit noisy tools: `kali_exec("gobuster ... 2>&1 | head -100")`
- Write output to `/tmp/` to avoid losing results on long scans: `kali_exec("nikto -h TARGET -o /tmp/nikto.txt && cat /tmp/nikto.txt")`
