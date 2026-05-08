#!/usr/bin/env python3
"""NullPointer Studio — Penetration Test Report Generator"""
import json, base64, html as html_mod, datetime, re
from pathlib import Path
from weasyprint import HTML as WeasyprintHTML

BASE_DIR     = Path(".")
FINDINGS_PATH = BASE_DIR / "findings.json"
OUTPUT_PDF   = BASE_DIR / "report_notingbank_org_2026-05-08.pdf"
OUTPUT_HTML  = BASE_DIR / "report_notingbank_org_2026-05-08.html"

# ── LOGO ──────────────────────────────────────────────────────────────────────
LOGO_SRC = ""
for _logo in [
    Path("/Users/gibson/Desktop/development/agent-smith/templates/FullLogo_Transparent.png"),
    Path("/Users/riccardo.tencate/Desktop/agent-smith/templates/FullLogo_Transparent.png"),
    BASE_DIR / "templates" / "FullLogo_Transparent.png",
]:
    if _logo.exists():
        with open(_logo, "rb") as _f:
            LOGO_SRC = "data:image/png;base64," + base64.b64encode(_f.read()).decode()
        break

# ── CSS ───────────────────────────────────────────────────────────────────────
CSS_STR = """
@import url('https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@400;600;700&family=Outfit:wght@300;400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap');
:root{--bg:#13112e;--bg-card:#1a1840;--bg-raised:#2d2b55;--bg-deep:#0d0b20;--text:#e8e6f0;--muted:#9b98b8;--dim:#6b6890;--green:#5bf29b;--purple:#7b78ff;--border:rgba(123,120,255,0.28);}
@page{size:A4;margin:2.3cm 2.2cm 2cm 2.2cm;background:#13112e;
  @bottom-left{content:"notingbank.org Penetration Test Report \\B7 2026-05-08";font-family:'IBM Plex Mono',monospace;font-size:7pt;color:#6b6890;}
  @bottom-right{content:"NullPointer Studio \\B7 CONFIDENTIAL \\B7 Page " counter(page);font-family:'IBM Plex Mono',monospace;font-size:7pt;color:#6b6890;}}
@page cover-page{margin:0;@bottom-left{content:none;}@bottom-right{content:none;}}
html,body{background:#13112e;color:#e8e6f0;font-family:'Outfit',sans-serif;font-size:9.5pt;line-height:1.65;margin:0;padding:0;}
.cover{page:cover-page;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:29.7cm;background:#13112e;text-align:center;position:relative;}
.cover::before{content:"";position:absolute;top:0;left:0;right:0;height:6px;background:linear-gradient(90deg,#5bf29b,#7b78ff,#5bf29b);}
.cover-logo{height:180px;margin-bottom:2.5cm;}
.cover-classification{font-family:'IBM Plex Mono',monospace;font-size:8pt;letter-spacing:0.2em;color:#ff4d6d;border:1px solid #ff4d6d;padding:4px 16px;margin-bottom:1cm;display:inline-block;}
.cover-title{font-family:'Chakra Petch',monospace;font-size:28pt;font-weight:700;color:#fff;line-height:1.15;margin-bottom:0.4cm;}
.cover-subtitle{font-family:'Chakra Petch',monospace;font-size:14pt;font-weight:400;color:#5bf29b;margin-bottom:1.5cm;letter-spacing:0.05em;}
.cover-divider{width:80px;height:2px;background:linear-gradient(90deg,transparent,#7b78ff,transparent);margin:0 auto 1.5cm;}
.cover-meta{width:100%;max-width:14cm;border-top:1px solid rgba(123,120,255,0.3);padding-top:0.8cm;margin-top:1cm;}
.cover-meta table{width:100%;border-collapse:collapse;text-align:left;}
.cover-meta td{padding:5px 12px;font-size:9pt;}
.cover-meta td:first-child{color:#9b98b8;font-family:'IBM Plex Mono',monospace;font-size:8pt;width:40%;}
.cover-footer{position:absolute;bottom:1cm;font-family:'IBM Plex Mono',monospace;font-size:7pt;color:#6b6890;}
.stat-row{display:flex;justify-content:space-around;gap:12px;margin:20px 0 24px;flex-wrap:wrap;}
.stat-box{flex:1;min-width:70px;background:#0d0b20;border:1px solid rgba(123,120,255,0.2);border-radius:6px;padding:14px 10px;text-align:center;}
.stat-num{font-family:'Chakra Petch',monospace;font-size:20pt;font-weight:700;display:block;line-height:1.1;}
.stat-label{font-size:7pt;color:#9b98b8;text-transform:uppercase;letter-spacing:0.1em;display:block;margin-top:4px;}
h1{font-family:'Chakra Petch',monospace;font-size:16pt;font-weight:700;color:#fff;border-bottom:1px solid rgba(123,120,255,0.3);padding-bottom:6px;margin:0 0 16px;}
h2{font-family:'Chakra Petch',monospace;font-size:11pt;color:#7b78ff;margin:16px 0 8px;}
h3{font-family:'Chakra Petch',monospace;font-size:10pt;color:#9b98b8;margin:12px 0 6px;}
h4{font-family:'Chakra Petch',monospace;font-size:8.5pt;color:#7b78ff;text-transform:uppercase;letter-spacing:0.08em;margin:14px 0 6px;}
p{margin:0 0 8px;}
.section{margin-bottom:24px;}
.page-break{page-break-before:always;}
.dashboard-table,.meta-table,.remediation-table{width:100%;border-collapse:collapse;font-size:8.5pt;margin:10px 0;}
.dashboard-table th,.meta-table th,.remediation-table th{background:#2d2b55;color:#9b98b8;font-family:'IBM Plex Mono',monospace;font-size:7.5pt;text-transform:uppercase;letter-spacing:0.06em;padding:7px 10px;text-align:left;border-bottom:1px solid rgba(123,120,255,0.3);}
.dashboard-table td,.meta-table td,.remediation-table td{padding:6px 10px;border-bottom:1px solid rgba(123,120,255,0.1);vertical-align:top;}
.finding{background:#1a1840;border-radius:6px;border-left-width:4px;border-left-style:solid;margin-bottom:20px;page-break-inside:avoid;}
.finding-header{padding:12px 16px 10px;border-bottom:1px solid rgba(123,120,255,0.15);}
.finding-title-row{display:flex;align-items:center;gap:10px;margin-bottom:10px;flex-wrap:wrap;}
.finding-id{font-family:'IBM Plex Mono',monospace;font-size:8.5pt;color:#7b78ff;font-weight:500;}
.finding-title{font-family:'Chakra Petch',monospace;font-size:10.5pt;font-weight:600;color:#fff;}
.finding-body{padding:12px 16px 14px;font-size:8.5pt;line-height:1.8;color:#9b98b8;}
.finding-meta{width:100%;border-collapse:collapse;font-size:8pt;margin-bottom:14px;}
.finding-meta td{padding:3px 8px;border-bottom:1px solid rgba(123,120,255,0.08);vertical-align:top;text-transform:uppercase;letter-spacing:0.06em;background:rgba(123,120,255,0.06);width:18%;}
.finding-meta td:nth-child(even){color:#e8e6f0;font-family:'Outfit',sans-serif;text-transform:none;letter-spacing:0;width:32%;background:transparent;}
.badge{font-family:'IBM Plex Mono',monospace;font-size:7pt;font-weight:500;padding:2px 8px;border-radius:3px;white-space:nowrap;letter-spacing:0.08em;}
.code-block{background:#0d0b20;border:1px solid rgba(123,120,255,0.2);border-radius:4px;padding:10px 12px;font-family:'IBM Plex Mono',monospace;font-size:7.5pt;color:#5bf29b;white-space:pre-wrap;word-break:break-all;margin:6px 0 10px;overflow:hidden;}
.risk-box{border-left:3px solid #ff8c42;background:rgba(255,140,66,0.06);padding:8px 12px;border-radius:0 4px 4px 0;margin:6px 0 10px;font-size:8.5pt;color:#e8e6f0;line-height:1.6;}
.callout{border:1px solid rgba(123,120,255,0.3);border-radius:6px;background:rgba(123,120,255,0.05);padding:12px 16px;margin:16px 0;font-size:8.5pt;line-height:1.8;color:#9b98b8;}
ul{margin:4px 0 8px 16px;padding:0;}li{margin-bottom:3px;}
strong{color:#e8e6f0;}
code{font-family:'IBM Plex Mono',monospace;font-size:8pt;color:#5bf29b;background:rgba(91,242,155,0.08);padding:1px 4px;border-radius:2px;}
"""

# ── SEVERITY META ─────────────────────────────────────────────────────────────
SEV_META = {
    "critical": {"label":"CRITICAL","color":"#ff4d6d","bg":"rgba(255,77,109,0.12)","border":"#ff4d6d"},
    "high":     {"label":"HIGH",    "color":"#ff8c42","bg":"rgba(255,140,66,0.12)", "border":"#ff8c42"},
    "medium":   {"label":"MEDIUM",  "color":"#ffd166","bg":"rgba(255,209,102,0.1)","border":"#ffd166"},
    "low":      {"label":"LOW",     "color":"#5bf29b","bg":"rgba(91,242,155,0.08)","border":"#5bf29b"},
    "info":     {"label":"INFO",    "color":"#7b78ff","bg":"rgba(123,120,255,0.08)","border":"#7b78ff"},
}

def esc(s): return html_mod.escape(str(s) if s is not None else "")

def badge(sev):
    m = SEV_META.get(sev.lower(), SEV_META["info"])
    return (f'<span class="badge" style="background:{m["bg"]};color:{m["color"]};'
            f'border:1px solid {m["color"]};">{m["label"]}</span>')

def code_block(text):
    return f'<div class="code-block">{esc(str(text)[:1800])}</div>' if text else ""

def infer_owasp(title, description):
    t = (title + " " + (description or "")).lower()
    if any(k in t for k in ["sql inject","sqli","xss","cross-site script","ssti","template inject","xxe","xml inject","command inject","nosql"]):
        return "A03:2021 — Injection"
    if any(k in t for k in ["bola","idor","broken object level","access control","bfla","broken function","privilege","admin access","unauthorized","unauthenticated access","bopla","mass assign"]):
        return "A01:2021 — Broken Access Control"
    if any(k in t for k in ["jwt","token forg","authentication fail","session","mfa","2fa","forgot password","account takeover","pin","credential"]):
        return "A07:2021 — Identification and Authentication Failures"
    if any(k in t for k in ["ssrf","server-side request"]):
        return "A10:2021 — Server-Side Request Forgery"
    if any(k in t for k in ["cors","debug mode","verbose","error disclos","security header","hsts","csp","https","no tls","missing tls","cleartext","imds","ec2","aws","docker network","topology"]):
        return "A05:2021 — Security Misconfiguration"
    if any(k in t for k in ["llm","prompt inject","jailbreak","system prompt","ai agent","pre-jailbroken","guardrail"]):
        return "LLM01:2025 — Prompt Injection"
    if any(k in t for k in ["crypto","hash","weak","encrypt"]):
        return "A02:2021 — Cryptographic Failures"
    if any(k in t for k in ["upload","file","deserializ"]):
        return "A04:2021 — Insecure Design"
    return "A05:2021 — Security Misconfiguration"

def infer_asvs(title, description):
    t = (title + " " + (description or "")).lower()
    if "sql" in t: return "V5.3.4"
    if any(k in t for k in ["jwt","token","session","auth"]): return "V3.5.3"
    if "xss" in t: return "V5.3.3"
    if "ssrf" in t: return "V10.3.2"
    if "cors" in t: return "V14.4.7"
    if any(k in t for k in ["bola","idor","access control"]): return "V4.2.1"
    if any(k in t for k in ["mass assign","bopla"]): return "V4.2.2"
    if any(k in t for k in ["header","csp","hsts"]): return "V14.4"
    if any(k in t for k in ["tls","https"]): return "V9.1.1"
    return "—"

def infer_auth(description):
    t = (description or "").lower()
    if any(k in t for k in ["unauthenticated","without authentication","no auth","no token","anonymous","without.*token"]):
        return "No"
    return "Yes"

def infer_endpoint(target):
    if not target: return "/"
    t = str(target).strip()
    for base in ["http://notingbank.org","https://notingbank.org"]:
        t = t.replace(base, "")
    return t or "/"

def normalize_title(title):
    return re.sub(r'\s+', ' ', title.strip().lower())

def derive_business_risk(title, severity, description):
    tl = title.lower()
    dl = (description or "").lower()

    if any(k in tl for k in ["rce","remote code","copy to program","os command"]):
        return ("<strong>Impact:</strong> Arbitrary OS command execution as <code>postgres</code> "
                "(uid=999) on the EC2 host. Enables credential harvesting, persistent backdoor "
                "installation, internal Docker network pivot (172.18.0.0/16), and AWS IMDS access "
                "for cloud credential theft — full infrastructure compromise from a single request.")
    if any(k in tl for k in ["aws","imds"]) or ("aws" in dl and "credential" in dl):
        return ("<strong>Impact:</strong> AWS STS credentials (ASIA47CRZXTWW7BMILYS) extracted from "
                "EC2 IMDS. Grants IAM access to cloud resources — S3 buckets, RDS snapshots, SSM "
                "Parameter Store secrets. Depending on the instance role, may enable full cloud "
                "account takeover and data exfiltration of all stored customer records.")
    if "jwt" in tl and any(k in tl for k in ["secret","forg","expos","leak"]):
        return ("<strong>Impact:</strong> The HS256 JWT signing secret (<code>secret123</code>) is "
                "publicly accessible via SSRF. Any attacker can forge arbitrary admin tokens — "
                "granting unrestricted access to all authenticated endpoints, the admin panel, and "
                "every privileged operation across the banking application.")
    if "ssrf" in tl:
        return ("<strong>Impact:</strong> SSRF to loopback and internal services exposes the JWT "
                "signing secret, database credentials, and internal architecture. Can be chained to "
                "reach AWS IMDS (169.254.169.254) for EC2 role credential theft and lateral movement "
                "to other services on the internal Docker network.")
    if "sql" in tl and "inject" in tl:
        return ("<strong>Impact:</strong> PostgreSQL superuser access enables complete database "
                "exfiltration of all customer PII, account balances, and transaction history. "
                "COPY TO PROGRAM escalates to OS-level RCE. All data in <code>vulnerable_bank</code> "
                "is at immediate risk of exfiltration or destruction.")
    if any(k in tl for k in ["bopla","mass assign"]):
        return ("<strong>Impact:</strong> Any user can self-promote to administrator by including "
                "<code>is_admin: true</code> in the registration payload. Instant admin access to "
                "all user management, transaction oversight, and sensitive reporting functions — "
                "no approval workflow required.")
    if any(k in tl for k in ["bola","idor","cross-account","cross-user"]):
        return ("<strong>Impact:</strong> Any authenticated user can retrieve balances and full "
                "transaction history for every other customer by iterating account numbers. Complete "
                "financial privacy breach; regulatory liability under GDPR/AVG Article 32 and PSD2 "
                "strong customer authentication requirements.")
    if "xss" in tl and "stored" in tl:
        return ("<strong>Impact:</strong> Persistent JavaScript in the admin panel executes in every "
                "administrator session — enabling session token theft, admin action hijacking, "
                "credential harvest, and persistent backdoor that survives password rotation.")
    if "cors" in tl:
        return ("<strong>Impact:</strong> Any website can send credentialed cross-origin requests to "
                "the banking API. A malicious page visited by an authenticated user can silently "
                "exfiltrate account data and trigger financial transactions (transfers, bill payments) "
                "without user consent.")
    if any(k in tl for k in ["system prompt","llm07"]):
        return ("<strong>Impact:</strong> The AI agent's full system prompt — including database "
                "schema and internal architecture — is exposed to any user. Provides a complete "
                "blueprint for targeted injection attacks against the application's business logic.")
    if any(k in tl for k in ["jailbreak","pre-jailbroken","guardrail"]):
        return ("<strong>Impact:</strong> Security guardrails are disabled by default. The AI agent "
                "complies with any data-extraction or policy-violating request — functioning as an "
                "insider-threat vector for harvesting customer data without authentication.")
    if any(k in tl for k in ["pin","forgot","account takeover","ato"]):
        return ("<strong>Impact:</strong> Any account can be taken over in under 1,000 requests by "
                "brute-forcing the 3-digit PIN leaked in <code>debug_info</code> API responses. "
                "Full access to victim financial data, transactions, and PII; no existing password "
                "knowledge required.")
    if any(k in tl for k in ["https","tls","cleartext","no tls","missing tls"]):
        return ("<strong>Impact:</strong> All traffic — credentials, session tokens, account numbers, "
                "transaction data — transmitted in cleartext. Network-positioned attacker (ISP, "
                "public WiFi) can passively intercept and actively tamper with every banking "
                "interaction.")
    if any(k in tl for k in ["docker network","internal network","topology"]):
        return ("<strong>Impact:</strong> Full internal topology (172.18.0.0/16, gateway, DB host, "
                "app containers) exposed — enables precise targeting of internal services and "
                "efficient lateral movement without blind scanning after gaining initial foothold.")
    if "debug" in tl:
        return ("<strong>Impact:</strong> Debug mode exposes stack traces, file paths, and config "
                "values to any user who triggers an error — dramatically accelerating exploit "
                "development by eliminating blind server-side reconnaissance.")
    if any(k in tl for k in ["header","hsts","csp","x-frame"]):
        return ("<strong>Impact:</strong> Absence of HSTS, CSP, and X-Frame-Options leaves users "
                "vulnerable to protocol downgrade, clickjacking on banking operations, and XSS "
                "amplification through unrestricted inline script execution.")
    if "verbose" in tl or ("error" in tl and "disclos" in tl):
        return ("<strong>Impact:</strong> Raw SQL error messages expose table names and column types, "
                "providing the database schema needed to craft targeted injection payloads without "
                "blind enumeration.")
    if "container escape" in tl or ("cap" in tl and "eff" in tl):
        return ("<strong>Impact:</strong> Container escape via capability abuse is not possible "
                "(CapEff=0). This tested-clean control provides meaningful defence-in-depth for the "
                "containerised deployment.")
    if "graphql" in tl and "introspect" in tl:
        return ("<strong>Impact:</strong> Full GraphQL schema exposed in production. Attackers can "
                "enumerate all types, fields, mutations, and arguments — enabling precise targeting "
                "of injection points and undocumented query paths.")
    # generic by severity
    sev = severity.lower()
    if sev == "critical":
        return (f"<strong>Impact:</strong> {esc(title)} enables an attacker to compromise the "
                "confidentiality, integrity, or availability of customer financial data and banking "
                "infrastructure. Immediate remediation is required.")
    if sev == "high":
        return (f"<strong>Impact:</strong> {esc(title)} exposes customer data or application "
                "integrity to significant risk without requiring advanced exploitation skills.")
    return (f"<strong>Impact:</strong> {esc(title)} represents a security control deficiency that "
            "provides reconnaissance value or can be chained with other findings to amplify impact.")

def derive_steps(finding):
    repro = finding.get("reproduction", {})
    if isinstance(repro, dict):
        steps = repro.get("steps",""); cmd = repro.get("command","")
        if steps: return f"<p>{esc(steps)}</p>"
        if cmd: return f"<p>Send the following request or run the command:</p>{code_block(cmd)}"
    elif isinstance(repro, str) and repro:
        return f"<p>{esc(repro)}</p>"
    tl = finding.get("title","").lower()
    if "sql" in tl and "login" in tl:
        return ("<ol><li>Send <code>POST /login</code> with <code>username=\"' OR 1=1--\"</code></li>"
                "<li>Observe error-based DB output or use time-based payloads to confirm blind injection</li>"
                "<li>Enumerate via sqlmap: <code>sqlmap -u http://notingbank.org/login --data 'username=*&amp;password=x' --dbms=postgresql</code></li></ol>")
    if any(k in tl for k in ["bopla","mass assign"]):
        return ("<ol><li>Send <code>POST /register</code> with <code>{\"username\":\"x\",\"password\":\"x\",\"email\":\"x@x.com\",\"is_admin\":true}</code></li>"
                "<li>Log in as the new account</li>"
                "<li>Access <code>GET /sup3r_s3cr3t_admin</code> — confirm admin granted</li></ol>")
    if "ssrf" in tl:
        return ("<ol><li>Send <code>POST /upload_profile_picture_url</code> with <code>image_url=http://0.0.0.0:5000/internal/secret</code></li>"
                "<li>Observe response containing JWT secret and DB credentials</li>"
                "<li>Alternatively probe <code>http://169.254.169.254/latest/meta-data/</code> for AWS IMDS</li></ol>")
    if "jwt" in tl:
        return ("<ol><li>Capture a valid JWT from the <code>Authorization</code> header</li>"
                "<li>Forge a new token with <code>is_admin:true</code> using the leaked secret <code>secret123</code></li>"
                "<li>Send forged token to <code>GET /sup3r_s3cr3t_admin</code></li></ol>")
    if any(k in tl for k in ["bola","idor","cross-account"]):
        return ("<ol><li>Register two accounts (A and B)</li>"
                "<li>As Account A, send <code>GET /transactions/{account_number}</code> using Account B's number</li>"
                "<li>Confirm Account B's transactions and balance are returned</li></ol>")
    if "xss" in tl and "stored" in tl:
        return ("<ol><li>Register with username <code>&lt;img src=x onerror=alert(document.cookie)&gt;</code></li>"
                "<li>As admin, navigate to <code>GET /sup3r_s3cr3t_admin</code></li>"
                "<li>Observe XSS execution in admin browser</li></ol>")
    if any(k in tl for k in ["pin","forgot","account takeover"]):
        return ("<ol><li>Call <code>POST /api/v1/forgot-password</code> with target email</li>"
                "<li>Read <code>debug_info.pin</code> from the JSON response</li>"
                "<li>Submit the PIN to complete the reset — full account access obtained</li></ol>")
    return ("<ol>"
            f"<li>Authenticate to the application with a valid account</li>"
            f"<li>Send the crafted request to <code>{esc(infer_endpoint(finding.get('target','/')))} </code></li>"
            "<li>Observe the vulnerability-confirming response detailed in the Evidence section</li>"
            "</ol>")

def derive_remediation(finding):
    tl = finding.get("title","").lower()
    repro = finding.get("reproduction",{})
    if isinstance(repro, dict) and repro.get("verification"):
        return f"<p>{esc(repro['verification'])}</p>"
    if "sql" in tl:
        return ("<p>Use parameterized queries for all database interactions:</p>"
                '<div class="code-block"># Vulnerable\ncur.execute(f"SELECT * FROM users WHERE username = \'{username}\'")\n\n'
                "# Secure\ncur.execute('SELECT * FROM users WHERE username = %s', (username,))</div>"
                "<p>Revoke superuser from the application DB user and disable COPY TO/FROM PROGRAM.</p>")
    if "jwt" in tl and any(k in tl for k in ["secret","forg","expos","leak"]):
        return ("<p>Immediately rotate the JWT secret. Store it in environment variables or a secrets manager:</p>"
                '<div class="code-block">import secrets\nJWT_SECRET = secrets.token_hex(32)  # min 256-bit</div>')
    if any(k in tl for k in ["bopla","mass assign"]):
        return ("<p>Allowlist permitted fields — never pass <code>request.json</code> directly to the ORM:</p>"
                '<div class="code-block">ALLOWED = {\'username\', \'password\', \'email\'}\n'
                "user = User(**{k:v for k,v in request.json.items() if k in ALLOWED})</div>")
    if "ssrf" in tl:
        return ("<p>Validate URLs against an allowlist; block RFC 1918, loopback, and link-local ranges:</p>"
                '<div class="code-block">BLOCKED = ["127.0.0.0/8","10.0.0.0/8","172.16.0.0/12",\n'
                '           "192.168.0.0/16","169.254.0.0/16"]\n'
                "def is_safe(url):\n"
                "    ip = resolve(urlparse(url).hostname)\n"
                "    return not any(ip in net for net in BLOCKED)</div>")
    if any(k in tl for k in ["bola","idor","cross-account"]):
        return ("<p>Enforce ownership checks on every object access:</p>"
                '<div class="code-block">account = Account.query.filter_by(\n'
                "    number=account_number, owner_id=current_user.id\n"
                ").first_or_404()</div>")
    if "xss" in tl:
        return ("<p>Enable Jinja2 auto-escaping (on by default); never use <code>|safe</code> on "
                "user-controlled input. Add <code>Content-Security-Policy: default-src 'self'</code>.</p>")
    if "cors" in tl:
        return ("<p>Replace wildcard with an explicit origin allowlist:</p>"
                '<div class="code-block">ALLOWED_ORIGINS = {"https://notingbank.org"}\n'
                "if origin in ALLOWED_ORIGINS:\n"
                "    resp.headers['Access-Control-Allow-Origin'] = origin</div>")
    if any(k in tl for k in ["https","tls","no tls","missing tls","cleartext"]):
        return ("<p>Configure TLS 1.2+ and redirect all HTTP to HTTPS with HSTS preload:</p>"
                '<div class="code-block">add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;</div>')
    if any(k in tl for k in ["header","hsts","csp"]):
        return ("<p>Add security response headers:</p>"
                '<div class="code-block">Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n'
                "Content-Security-Policy: default-src 'self'\n"
                "X-Frame-Options: DENY\n"
                "X-Content-Type-Options: nosniff</div>")
    if "debug" in tl:
        return ("<p>Disable debug mode via environment variable:</p>"
                '<div class="code-block">DEBUG = os.getenv("DEBUG","false").lower() == "true"\n# Set DEBUG=false in all production environments</div>')
    if "verbose" in tl or ("error" in tl and "disclos" in tl):
        return ("<p>Return generic error messages to clients; log details server-side only:</p>"
                '<div class="code-block">except Exception as e:\n    logger.exception(e)\n    return web.json_response({"error":"An unexpected error occurred"}, status=500)</div>')
    if any(k in tl for k in ["pin","forgot","account takeover"]):
        return ("<p>Remove <code>debug_info</code> from all API responses. Implement time-limited "
                "single-use cryptographic reset tokens delivered via email. Add rate limiting "
                "(max 5 attempts/hour/account) to all recovery endpoints.</p>")
    if any(k in tl for k in ["rce","copy to program"]):
        return ("<p>Fix the underlying SQL injection (parameterized queries). Revoke PostgreSQL "
                "superuser from the application account and disable COPY TO PROGRAM:</p>"
                '<div class="code-block">ALTER USER app_user NOSUPERUSER;\n'
                "GRANT SELECT,INSERT,UPDATE ON ALL TABLES IN SCHEMA public TO app_user;</div>")
    if any(k in tl for k in ["imds","aws","ec2"]):
        return ("<p>Enforce IMDSv2 with hop-limit=1 to prevent container-level IMDS access:</p>"
                '<div class="code-block">aws ec2 modify-instance-metadata-options \\\n'
                "  --instance-id i-08b8a0c45baad2ffe \\\n"
                "  --http-tokens required \\\n"
                "  --http-put-response-hop-limit 1</div>")
    if any(k in tl for k in ["jailbreak","pre-jailbroken","guardrail"]):
        return ("<p>Remove the guardrail-disabling instruction from the system prompt. Implement "
                "an independent moderation layer for all AI inputs and outputs. Red-team AI system "
                "prompts before every production deployment.</p>")
    if any(k in tl for k in ["system prompt","llm07"]):
        return ("<p>Remove database schema and internal architecture from the system prompt. Use "
                "tool-based retrieval for data access. Implement output filtering to prevent "
                "verbatim system prompt reproduction.</p>")
    if "graphql" in tl and "introspect" in tl:
        return ("<p>Disable introspection in production:</p>"
                '<div class="code-block">graphql_app = GraphQL(schema, introspection=False)</div>')
    return ("<p>Apply defence-in-depth: input validation, output encoding, least-privilege access "
            "controls, and security header enforcement. Add automated security tests to the CI/CD pipeline.</p>")

def find_poc_file(title):
    pocs_dir = BASE_DIR / "pocs"
    if not pocs_dir.exists(): return None
    words = set(re.findall(r'[a-z0-9]+', title.lower()))
    best, best_score = None, 1
    for p in pocs_dir.glob("*.http"):
        score = len(words & set(re.findall(r'[a-z0-9]+', p.stem.lower())))
        if score > best_score:
            best_score, best = score, p
    return best

def finding_card(np_id, finding):
    sev   = finding.get("severity","info").lower()
    title = finding.get("title","Untitled Finding")
    tgt   = infer_endpoint(finding.get("target","/"))
    desc  = finding.get("description","")
    evid  = finding.get("evidence","")
    owasp = infer_owasp(title, desc)
    asvs  = infer_asvs(title, desc)
    auth  = infer_auth(desc)
    biz   = derive_business_risk(title, sev, desc)
    steps = derive_steps(finding)
    remed = derive_remediation(finding)
    m     = SEV_META.get(sev, SEV_META["info"])
    is_info = sev == "info"

    poc_file = find_poc_file(title)
    poc_html = ""
    confirmed = "Yes"
    if poc_file:
        try:
            raw = poc_file.read_text(errors="replace")[:1500]
            poc_html = f"<h4>PoC Request</h4>{code_block(raw)}"
            confirmed = "Yes — live PoC"
        except Exception:
            pass

    # format description
    desc_html = ""
    for para in re.split(r'\n{2,}', desc.strip()):
        para = para.strip()
        if not para: continue
        if (para.startswith("```") or re.match(r'^(GET|POST|PUT|DELETE|HTTP|curl|SELECT|INSERT|UPDATE|COPY)\b', para)
                or para.count('\n') > 2):
            desc_html += code_block(para.strip('`').strip())
        else:
            desc_html += f"<p>{esc(para)}</p>"

    # format evidence
    evid_html = ""
    if evid:
        for part in re.split(r'\n{2,}', str(evid).strip())[:3]:
            part = part.strip()
            if not part: continue
            if (len(part) > 150 or '\n' in part or
                    re.match(r'^(HTTP|GET|POST|PUT|DELETE|curl|{)', part)):
                evid_html += code_block(part[:1000])
            else:
                evid_html += f"<p>{esc(part)}</p>"
    evid_html += poc_html

    if is_info:
        return f"""
<div class="finding" style="border-left:4px solid {m['border']};">
  <div class="finding-header">
    <div class="finding-title-row">
      <span class="finding-id">{esc(np_id)}</span>
      {badge(sev)}
      <span class="finding-title">{esc(title)}</span>
    </div>
    <table class="finding-meta">
      <tr><td>OWASP</td><td colspan="3">{esc(owasp)}</td></tr>
      <tr><td>Endpoint</td><td colspan="3"><code>{esc(tgt)}</code></td></tr>
    </table>
  </div>
  <div class="finding-body">
    <h4>Description</h4>{desc_html}
    <h4>Business Risk</h4><div class="risk-box">{biz}</div>
    <h4>Recommendations</h4>{remed}
  </div>
</div>"""

    return f"""
<div class="finding" style="border-left:4px solid {m['border']};">
  <div class="finding-header">
    <div class="finding-title-row">
      <span class="finding-id">{esc(np_id)}</span>
      {badge(sev)}
      <span class="finding-title">{esc(title)}</span>
    </div>
    <table class="finding-meta">
      <tr><td>OWASP</td><td>{esc(owasp)}</td><td>ASVS</td><td>{esc(asvs)}</td></tr>
      <tr><td>Endpoint</td><td colspan="3"><code>{esc(tgt)}</code></td></tr>
      <tr><td>Auth Required</td><td>{esc(auth)}</td><td>Confirmed</td><td>{esc(confirmed)}</td></tr>
    </table>
  </div>
  <div class="finding-body">
    <h4>Description</h4>{desc_html}
    <h4>Business Risk</h4><div class="risk-box">{biz}</div>
    <h4>Evidence</h4>{evid_html or "<p>See tool output in findings.json and the PoC file.</p>"}
    <h4>Reproduction Steps</h4>{steps}
    <h4>Remediation</h4>{remed}
  </div>
</div>"""

def load_findings():
    data = json.loads(FINDINGS_PATH.read_text())
    raw = data.get("findings", data) if isinstance(data, dict) else data
    findings = [f for f in raw if isinstance(f, dict) and f.get("type","finding") == "finding"]
    # deduplicate on normalized title
    seen = {}
    for f in findings:
        key = normalize_title(f.get("title",""))
        prev = seen.get(key)
        if prev is None or len(str(f.get("evidence",""))) > len(str(prev.get("evidence",""))):
            seen[key] = f
    order = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
    return sorted(seen.values(), key=lambda f: order.get(f.get("severity","info").lower(), 4))

def build_stat_boxes(counts):
    boxes = ""
    for sev, label, color in [
        ("critical","Critical","#ff4d6d"),("high","High","#ff8c42"),
        ("medium","Medium","#ffd166"),("low","Low","#5bf29b"),
    ]:
        n = counts.get(sev, 0)
        if n:
            boxes += (f'<div class="stat-box"><span class="stat-num" style="color:{color};">{n}</span>'
                      f'<span class="stat-label">{label}</span></div>\n')
    boxes += (f'<div class="stat-box"><span class="stat-num" style="color:#7b78ff;">{counts["total"]}</span>'
              f'<span class="stat-label">Total</span></div>\n')
    return f'<div class="stat-row">\n{boxes}</div>'

def build_exec_summary(findings, counts):
    crits = [f for f in findings if f.get("severity","").lower() == "critical"]
    highs = [f for f in findings if f.get("severity","").lower() == "high"]
    top2 = "; ".join(f"<strong>{esc(f['title'])}</strong>" for f in crits[:2])
    extra_crit = f" and {len(crits)-2} additional critical findings" if len(crits) > 2 else ""
    high_themes = "; ".join(esc(f.get("title","")) for f in highs[:3])
    return f"""
<h1>Executive Summary</h1>
<div class="section">
<p>NullPointer Studio conducted a thorough penetration test of <strong>notingbank.org</strong>, a
banking web application built on Python/aiohttp 3.13.4 with a PostgreSQL backend, deployed on AWS EC2
in a Dockerized environment. The assessment ran on <strong>2026-05-08</strong> using automated scanning,
manual exploitation, and AI security red-teaming across all discovered attack surfaces.</p>

<p>The assessment uncovered <strong>{counts['critical']} critical</strong> and
<strong>{counts['high']} high</strong> severity vulnerabilities representing an unacceptable risk
posture for a production banking application. The most severe findings — {top2}{extra_crit} — enable
an unauthenticated attacker to compromise the entire application stack: the JWT signing secret
(<code>secret123</code>) is exposed via SSRF; SQL injection in the login endpoint reaches PostgreSQL
superuser and escalates to OS command execution via <code>COPY TO PROGRAM</code>, granting persistent
host-level access, AWS IMDS credential extraction, and full internal network pivot.</p>

<p>Of the <strong>{counts['medium']} medium</strong> and <strong>{counts['low']} low</strong> severity
findings, recurring themes include: {high_themes}. The AI chat agent has security guardrails
explicitly disabled in its system prompt and the complete system prompt — including database schema
— is extractable verbatim by any user, providing attackers a detailed map of application internals.</p>

<p>Positive controls observed during testing: the containerised deployment uses a minimal Linux
capability set (CapEff=0), preventing container escape via capability abuse. These controls represent
a foundation on which a remediated deployment can build.</p>
</div>"""

def build_scope():
    return """
<h1>Scope &amp; Methodology</h1>
<div class="section">
<h2>Target Scope</h2>
<table class="meta-table">
  <tr><th>Asset</th><th>Type</th><th>In Scope</th></tr>
  <tr><td><code>http://notingbank.org</code></td><td>Web Application</td><td>Yes</td></tr>
  <tr><td>Subdomains of notingbank.org</td><td>DNS / Web</td><td>Yes</td></tr>
  <tr><td>EC2 (ec2-44-206-236-113.compute-1.amazonaws.com)</td><td>Cloud Host</td><td>Post-RCE only</td></tr>
  <tr><td>Internal Docker network (172.18.0.0/16)</td><td>Internal</td><td>Post-RCE only</td></tr>
  <tr><td>AWS account / IAM</td><td>Cloud</td><td>Credential assessment only</td></tr>
</table>
<h2>Methodology</h2>
<ul>
  <li><strong>Recon:</strong> Subdomain enumeration, port scanning (naabu/nmap), HTTP fingerprinting (httpx)</li>
  <li><strong>Web Application:</strong> OWASP Web Top 10 systematic testing with full coverage matrix (ffuf, spider, nuclei, manual HTTP)</li>
  <li><strong>API Security:</strong> OWASP API Security Top 10 (2023) — BOLA, BFLA, BOPLA, JWT attacks, GraphQL introspection</li>
  <li><strong>AI Red-Team:</strong> OWASP LLM Top 10 (2025) — prompt injection, system prompt extraction, jailbreaks (FuzzyAI, PyRIT)</li>
  <li><strong>Post-Exploitation:</strong> Privilege escalation, credential harvesting, AWS IMDS access from confirmed RCE</li>
  <li><strong>Cloud Security:</strong> EC2 IAM credential exposure assessment via extracted IMDS credentials</li>
  <li><strong>Network Assessment:</strong> Internal Docker topology enumeration from compromised container</li>
</ul>
<h2>Frameworks</h2>
<ul>
  <li>OWASP WSTG, API Security Top 10 (2023), LLM Top 10 (2025), ASVS 5.0</li>
  <li>MITRE ATT&amp;CK for Enterprise</li>
  <li>AWS Well-Architected Security Pillar</li>
</ul>
</div>"""

def build_dashboard(findings):
    rows = ""
    for i, f in enumerate(findings, 1):
        sev = f.get("severity","info").lower()
        rows += (f'<tr><td style="font-family:\'IBM Plex Mono\',monospace;font-size:8pt;color:#7b78ff;">NP-{i:03d}</td>'
                 f'<td>{badge(sev)}</td>'
                 f'<td style="color:#e8e6f0;">{esc(f.get("title",""))}</td>'
                 f'<td style="color:#9b98b8;font-size:8pt;">{esc(infer_owasp(f.get("title",""),f.get("description","")))}</td>'
                 f'<td style="color:#9b98b8;">{"Informational" if sev=="info" else "Confirmed"}</td></tr>\n')
    return f"""<h1>Risk Dashboard</h1>
<table class="dashboard-table">
  <thead><tr><th>ID</th><th>Severity</th><th>Finding</th><th>OWASP</th><th>Status</th></tr></thead>
  <tbody>{rows}</tbody>
</table>"""

def build_remediation_table(findings):
    p_map = {"critical":"P0 — Immediate","high":"P0 — Immediate","medium":"P2 — Next Sprint","low":"P3 — Milestone","info":"—"}
    e_map = {"critical":"High","high":"Medium","medium":"Low","low":"Low","info":"—"}
    fix_map = {
        "sql":"Parameterized queries; revoke superuser",
        "jwt":"Rotate secret; store in env var",
        "ssrf":"URL allowlist; block RFC 1918 + IMDS",
        "bopla":"Allowlist fields on user creation",
        "mass assign":"Allowlist fields on user creation",
        "bola":"Ownership check on all object access",
        "idor":"Ownership check on all object access",
        "xss":"Enable Jinja2 auto-escape; add CSP",
        "cors":"Replace wildcard with explicit allowlist",
        "https":"Configure TLS 1.2+ and HSTS preload",
        "no tls":"Configure TLS 1.2+ and HSTS preload",
        "header":"Add HSTS, CSP, X-Frame-Options",
        "debug":"Set DEBUG=false via env var",
        "verbose":"Return generic errors; log details server-side",
        "rce":"Fix SQLi; revoke DB superuser",
        "copy to program":"Fix SQLi; revoke DB superuser",
        "imds":"Enforce IMDSv2 hop-limit=1",
        "aws":"Enforce IMDSv2 hop-limit=1",
        "pin":"Remove debug_info; use crypto token reset",
        "account takeover":"Remove debug_info; use crypto token reset",
        "jailbreak":"Remove guardrail-disabling instruction",
        "pre-jailbroken":"Remove guardrail-disabling instruction",
        "system prompt":"Remove schema from prompt; filter verbatim replay",
        "graphql introspect":"Disable introspection in production",
    }
    rows = ""
    for i, f in enumerate(findings, 1):
        sev = f.get("severity","info").lower()
        title = f.get("title","")
        tl = title.lower()
        fix = next((v for k,v in fix_map.items() if k in tl), "Apply OWASP remediation guidance")
        rows += (f'<tr><td style="font-family:\'IBM Plex Mono\',monospace;color:#7b78ff;font-size:8pt;">NP-{i:03d}</td>'
                 f'<td>{badge(sev)}</td>'
                 f'<td style="color:#e8e6f0;">{esc(title)}</td>'
                 f'<td style="color:#9b98b8;font-size:8pt;">{esc(p_map.get(sev,"—"))}</td>'
                 f'<td style="color:#9b98b8;">{esc(e_map.get(sev,"—"))}</td>'
                 f'<td style="color:#9b98b8;font-size:8pt;">{esc(fix)}</td></tr>\n')
    return f"""<h1>Remediation Summary</h1>
<table class="remediation-table">
  <thead><tr><th>ID</th><th>Severity</th><th>Finding</th><th>Priority</th><th>Effort</th><th>Fix</th></tr></thead>
  <tbody>{rows}</tbody>
</table>"""

def build_html():
    findings = load_findings()
    counts = {s:0 for s in ("critical","high","medium","low","info","total")}
    for f in findings:
        s = f.get("severity","info").lower()
        counts[s] = counts.get(s,0) + 1
        counts["total"] += 1

    logo_html = (f'<img class="cover-logo" src="{LOGO_SRC}" alt="NullPointer Studio">'
                 if LOGO_SRC else
                 '<div style="height:180px;margin-bottom:2.5cm;display:flex;align-items:center;justify-content:center;">'
                 '<span style=\'font-family:"Chakra Petch",monospace;font-size:24pt;font-weight:700;color:#7b78ff;\'>'
                 'NullPointer Studio</span></div>')

    cover = f"""<div class="cover">
  {logo_html}
  <div class="cover-classification">CONFIDENTIAL</div>
  <div class="cover-title">Penetration Test Report</div>
  <div class="cover-subtitle">notingbank.org</div>
  <div class="cover-divider"></div>
  <div class="cover-meta"><table>
    <tr><td>Client</td><td>NotingBank</td></tr>
    <tr><td>Target</td><td>http://notingbank.org</td></tr>
    <tr><td>Test type</td><td>Web App Pentest + API Security + AI Red-Team</td></tr>
    <tr><td>Framework</td><td>Python / aiohttp 3.13.4 + PostgreSQL + Nginx</td></tr>
    <tr><td>Test date</td><td>2026-05-08</td></tr>
    <tr><td>Report date</td><td>2026-05-08</td></tr>
    <tr><td>Prepared by</td><td>NullPointer Studio</td></tr>
    <tr><td>Version</td><td>1.0</td></tr>
  </table></div>
  <div class="cover-footer">NullPointer Studio &middot; security research &amp; consulting</div>
</div>"""

    handling = """<div class="callout">
<strong>Handling Notice</strong><br><br>
This document contains confidential information pertaining to the security posture of NotingBank.
It is intended solely for the named client and authorised recipients. This report must not be
reproduced, distributed, or disclosed to any third party without the express written consent of
NullPointer Studio and NotingBank.<br><br>
The vulnerabilities described herein were discovered under controlled conditions as part of an
authorised security assessment. No exploitation was performed beyond what was necessary to confirm
the existence and impact of each finding.<br><br>
<strong>Classification: CONFIDENTIAL &mdash; NOT FOR PUBLIC DISTRIBUTION</strong>
</div>"""

    stat_html  = build_stat_boxes(counts)
    exec_html  = build_exec_summary(findings, counts)
    scope_html = build_scope()
    dash_html  = build_dashboard(findings)

    cards_html = '<div class="page-break"></div>\n<h1>Findings</h1>\n'
    for i, f in enumerate(findings, 1):
        cards_html += finding_card(f"NP-{i:03d}", f)

    remed_html = build_remediation_table(findings)

    footer = """<div class="callout" style="margin-top:32px;">
<strong>NullPointer Studio</strong> &middot; security research &amp; consulting<br>
This assessment was performed under a written authorisation agreement. All findings have been
responsibly disclosed to the client prior to publication of this report.
NullPointer Studio accepts no liability for actions taken by third parties based on information herein.
</div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>notingbank.org Penetration Test Report - NullPointer Studio</title>
<style>{CSS_STR}</style>
</head>
<body>
{cover}
{handling}
{stat_html}
{exec_html}
<div class="page-break"></div>
{scope_html}
<div class="page-break"></div>
{dash_html}
{cards_html}
<div class="page-break"></div>
{remed_html}
{footer}
</body>
</html>"""

if __name__ == "__main__":
    print("Reading findings.json ...")
    html_content = build_html()
    print(f"Writing HTML -> {OUTPUT_HTML}")
    OUTPUT_HTML.write_text(html_content, encoding="utf-8")
    print(f"Generating PDF -> {OUTPUT_PDF}")
    WeasyprintHTML(string=html_content, base_url=str(BASE_DIR.resolve())).write_pdf(str(OUTPUT_PDF))
    findings = load_findings()
    counts = {s:0 for s in ("critical","high","medium","low","info")}
    for f in findings:
        counts[f.get("severity","info").lower()] = counts.get(f.get("severity","info").lower(),0) + 1
    print(f"\nReport generated:")
    print(f"  PDF  -> {OUTPUT_PDF}")
    print(f"  HTML -> {OUTPUT_HTML}")
    print(f"  Findings: {len(findings)} total ({counts['critical']} critical, "
          f"{counts['high']} high, {counts['medium']} medium, {counts['low']} low, {counts['info']} info)")
