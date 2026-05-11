#!/usr/bin/env python3
"""NullPointer Studio — Penetration Test Report Generator"""
import json, base64, html as html_mod, datetime, re
from pathlib import Path
from weasyprint import HTML as WeasyprintHTML

BASE_DIR      = Path(".")
FINDINGS_PATH = BASE_DIR / "findings.json"
SESSION_PATH  = BASE_DIR / "session.json"

# ── SESSION METADATA ──────────────────────────────────────────────────────────

def _load_session_meta() -> dict:
    defaults = {"target": "", "scope": [], "out_of_scope": [], "started": "", "description": ""}
    try:
        data = json.loads(SESSION_PATH.read_text())
        return {**defaults, **{k: data.get(k, defaults[k]) for k in defaults}}
    except Exception:
        return defaults

_SESSION     = _load_session_meta()
_TARGET      = _SESSION["target"].rstrip("/")
_TARGET_HOST = re.sub(r'^https?://', '', _TARGET).split("/")[0] or "target"
_TEST_DATE   = _SESSION["started"][:10] if _SESSION["started"] else datetime.date.today().isoformat()
_SLUG        = re.sub(r'[^a-z0-9]+', '_', _TARGET_HOST.lower()).strip('_') or "target"

OUTPUT_PDF  = BASE_DIR / f"report_{_SLUG}_{_TEST_DATE}.pdf"
OUTPUT_HTML = BASE_DIR / f"report_{_SLUG}_{_TEST_DATE}.html"

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
_CSS_TEMPLATE = """
@import url('https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@400;600;700&family=Outfit:wght@300;400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap');
:root{--bg:#13112e;--bg-card:#1a1840;--bg-raised:#2d2b55;--bg-deep:#0d0b20;--text:#e8e6f0;--muted:#9b98b8;--dim:#6b6890;--green:#5bf29b;--purple:#7b78ff;--border:rgba(123,120,255,0.28);}
@page{size:A4;margin:2.3cm 2.2cm 2cm 2.2cm;background:#13112e;
  @bottom-left{content:"__FOOTER_TARGET__ Penetration Test Report \\B7 __FOOTER_DATE__";font-family:'IBM Plex Mono',monospace;font-size:7pt;color:#6b6890;}
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
CSS_STR = _CSS_TEMPLATE.replace("__FOOTER_TARGET__", _TARGET_HOST).replace("__FOOTER_DATE__", _TEST_DATE)

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


# ── INFERENCE HELPERS ─────────────────────────────────────────────────────────

def infer_owasp(title: str, description: str) -> str:
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
    if any(k in t for k in ["upload","file","deserializ","insecure design"]):
        return "A04:2021 — Insecure Design"
    return "A05:2021 — Security Misconfiguration"

def infer_asvs(title: str, description: str) -> str:
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

def infer_auth(description: str) -> str:
    t = (description or "").lower()
    if any(k in t for k in ["unauthenticated","without authentication","no auth","no token","anonymous"]):
        return "No"
    return "Yes"

def infer_endpoint(target: str) -> str:
    """Strip the session target base URL and return the path component."""
    if not target: return "/"
    t = str(target).strip()
    if _TARGET:
        t = t.replace(_TARGET, "")
    t = re.sub(r'^https?://[^/]+', '', t)
    return t or "/"

def normalize_title(title: str) -> str:
    return re.sub(r'\s+', ' ', title.strip().lower())


# ── SECTION EXTRACTION FROM FREE-TEXT ────────────────────────────────────────

def _extract_section(text: str, *labels: str) -> str:
    """Pull text following a labeled heading from a free-text description.

    Handles common formats: "Impact: ...", "**Impact:**", "## Impact", "### Remediation".
    Returns the first matching label's content, stopping at the next heading or blank line.
    """
    if not text:
        return ""
    for label in labels:
        pat = (
            r'(?:^|\n)\s*'
            r'(?:#{1,4}\s*|\*{1,2})?'
            + re.escape(label) +
            r'[\s*:]{0,4}\s*'
            r'([\s\S]+?)'
            r'(?=\n\s*\n|\n\s*(?:#{1,4}|\*{1,2})\w|\Z)'
        )
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            content = m.group(1).strip()
            if len(content) > 15:
                return content
    return ""


# ── OWASP-KEYED CONTENT TABLES ────────────────────────────────────────────────
# Generic impacts / steps / remediations keyed by OWASP category.
# These are last-resort fallbacks — finding data always takes priority.

_OWASP_IMPACT: dict[str, dict[str, str]] = {
    "A03:2021 — Injection": {
        "critical": ("Injection enables an attacker to read, modify, or delete arbitrary data in the "
                     "backend datastore. Depending on the database configuration, this may escalate to "
                     "OS-level command execution and full host compromise."),
        "high":     ("Injection allows partial or complete read access to backend data. Further "
                     "exploitation depends on database privileges and injection type (error-based, "
                     "blind, or time-based)."),
        "default":  ("Injection enables data extraction or manipulation in the affected component."),
    },
    "A01:2021 — Broken Access Control": {
        "critical": ("Any user can access or modify resources belonging to other users, or perform "
                     "admin-level operations without authorisation — affecting all data in the system."),
        "high":     ("Authenticated users can access objects or invoke functions beyond their "
                     "authorised scope, leading to data exposure or privilege escalation."),
        "default":  ("Access control bypass enables data access or actions beyond the intended permission boundary."),
    },
    "A07:2021 — Identification and Authentication Failures": {
        "critical": ("An attacker can bypass authentication or take over arbitrary accounts, gaining "
                     "full access to victim data and all application functions."),
        "high":     ("Authentication controls are insufficient to prevent account takeover or session "
                     "hijacking under targeted attack conditions."),
        "default":  ("Authentication weakness reduces confidence in user identity and session integrity."),
    },
    "A10:2021 — Server-Side Request Forgery": {
        "critical": ("The server can be directed to reach internal services, cloud metadata endpoints, "
                     "and other backend systems not exposed to the internet — enabling credential theft "
                     "and lateral movement."),
        "high":     ("SSRF allows partial access to internal network resources and may expose "
                     "configuration data or credentials held by internal services."),
        "default":  ("Server-side requests can be directed to unintended internal destinations."),
    },
    "A05:2021 — Security Misconfiguration": {
        "critical": ("The misconfiguration directly exposes credentials, secrets, or full administrative "
                     "access without authentication."),
        "high":     ("The misconfiguration provides a significant attack surface reduction bypass or "
                     "exposes sensitive operational data to unauthenticated requesters."),
        "default":  ("The misconfiguration provides reconnaissance value or can be chained with other "
                     "findings to amplify impact."),
    },
    "LLM01:2025 — Prompt Injection": {
        "critical": ("The AI system can be manipulated to bypass all safety controls, exfiltrate "
                     "sensitive data, or perform unauthorised actions on behalf of the attacker."),
        "high":     ("Prompt injection allows partial bypass of AI safety controls or extraction "
                     "of sensitive system information."),
        "default":  ("AI safety controls can be manipulated through crafted user inputs."),
    },
    "A02:2021 — Cryptographic Failures": {
        "high":     ("Sensitive data is transmitted or stored without adequate cryptographic protection, "
                     "exposing it to passive interception or offline brute-force attack."),
        "default":  ("Weak cryptographic controls reduce data confidentiality and integrity guarantees."),
    },
    "A04:2021 — Insecure Design": {
        "default":  ("The design flaw creates conditions that cannot be fully mitigated by correct "
                     "implementation alone — architectural changes are required."),
    },
}

_OWASP_STEPS: dict[str, str] = {
    "A03:2021 — Injection":
        ("<ol>"
         "<li>Identify the injection point in the request to <code>__EP__</code></li>"
         "<li>Send a crafted payload to trigger an observable effect (error message, time delay, "
         "boolean difference, or reflected data)</li>"
         "<li>Use an automated tool (sqlmap, NoSQLMap, etc.) to confirm and enumerate</li>"
         "</ol>"),
    "A01:2021 — Broken Access Control":
        ("<ol>"
         "<li>Authenticate as a low-privileged user (User A)</li>"
         "<li>Request the resource at <code>__EP__</code> substituting another user's object identifier</li>"
         "<li>Confirm unauthorised data or elevated access is returned</li>"
         "</ol>"),
    "A07:2021 — Identification and Authentication Failures":
        ("<ol>"
         "<li>Interact with the authentication surface at <code>__EP__</code></li>"
         "<li>Apply the attack technique documented in the Evidence section "
         "(token forgery, brute-force, MFA bypass, session fixation, etc.)</li>"
         "<li>Confirm elevated or unauthorised access is obtained</li>"
         "</ol>"),
    "A10:2021 — Server-Side Request Forgery":
        ("<ol>"
         "<li>Submit a request to <code>__EP__</code> with an internal URL as the target parameter "
         "(e.g. <code>http://127.0.0.1/</code> or <code>http://169.254.169.254/latest/meta-data/</code>)</li>"
         "<li>Observe internal content in the response</li>"
         "<li>Enumerate accessible internal services and cloud metadata endpoints</li>"
         "</ol>"),
    "A05:2021 — Security Misconfiguration":
        ("<ol>"
         "<li>Send a request to <code>__EP__</code></li>"
         "<li>Observe the misconfiguration-confirming response or header shown in the Evidence section</li>"
         "<li>Assess downstream impact based on exposed data</li>"
         "</ol>"),
    "LLM01:2025 — Prompt Injection":
        ("<ol>"
         "<li>Interact with the AI endpoint at <code>__EP__</code></li>"
         "<li>Submit the crafted prompt injection payload shown in the Evidence section</li>"
         "<li>Observe bypassed controls or sensitive data in the response</li>"
         "</ol>"),
}

_OWASP_REMEDIATION: dict[str, str] = {
    "A03:2021 — Injection":
        ("<p>Separate code from data using parameterized queries, prepared statements, or an ORM. "
         "Validate and allowlist all input. Apply the principle of least privilege to database "
         "accounts — disable elevated permissions (e.g. superuser, <code>xp_cmdshell</code>, "
         "<code>COPY TO PROGRAM</code>).</p>"
         '<div class="code-block"># Parameterized query example\n'
         "cur.execute('SELECT * FROM users WHERE id = %s', (user_id,))</div>"),
    "A01:2021 — Broken Access Control":
        ("<p>Enforce ownership checks on every object access — never rely on client-supplied "
         "identifiers alone. Verify against the authenticated user's identity server-side. "
         "Apply an allowlist to request fields to prevent mass assignment.</p>"
         '<div class="code-block">record = Model.query.filter_by(\n'
         "    id=object_id, owner_id=current_user.id\n).first_or_404()</div>"),
    "A07:2021 — Identification and Authentication Failures":
        ("<p>Rotate any exposed credentials immediately. Use long random secrets (≥256 bits). "
         "Enforce MFA on privileged accounts. Implement account lockout or exponential backoff. "
         "Use time-limited single-use cryptographic tokens for recovery flows.</p>"
         '<div class="code-block">import secrets\nTOKEN = secrets.token_hex(32)  # 256-bit</div>'),
    "A10:2021 — Server-Side Request Forgery":
        ("<p>Validate all server-side URL inputs against an explicit allowlist. Block RFC 1918 "
         "addresses, loopback, and link-local ranges (including cloud metadata IPs).</p>"
         '<div class="code-block">BLOCKED = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12",\n'
         '           "192.168.0.0/16", "169.254.0.0/16"]\n'
         "def is_safe(url):\n"
         "    ip = resolve(urlparse(url).hostname)\n"
         "    return not any(ip_address(ip) in ip_network(n) for n in BLOCKED)</div>"),
    "A05:2021 — Security Misconfiguration":
        ("<p>Disable debug mode, verbose errors, and directory listing in production. Add security "
         "response headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options). Enforce "
         "token-based access with minimum hop limits for cloud metadata services.</p>"
         '<div class="code-block">Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n'
         "Content-Security-Policy: default-src 'self'\n"
         "X-Frame-Options: DENY\n"
         "X-Content-Type-Options: nosniff</div>"),
    "A02:2021 — Cryptographic Failures":
        ("<p>Enforce TLS 1.2+ for all connections and redirect HTTP to HTTPS with HSTS preload. "
         "Use strong, industry-standard algorithms. Store passwords with an adaptive hashing "
         "algorithm (bcrypt, argon2id).</p>"
         '<div class="code-block">add_header Strict-Transport-Security '
         '"max-age=31536000; includeSubDomains; preload" always;</div>'),
    "LLM01:2025 — Prompt Injection":
        ("<p>Remove sensitive internal information (schema, secrets, architecture) from system "
         "prompts. Implement an independent moderation layer for AI inputs and outputs. Red-team "
         "AI system prompts before every production deployment.</p>"),
    "A04:2021 — Insecure Design":
        ("<p>Review the threat model for the affected component. Apply defence-in-depth: validate "
         "inputs at every layer, enforce least-privilege access controls, and add automated "
         "security tests to the CI/CD pipeline.</p>"),
}


# ── CONTENT DERIVATION — DATA-FIRST, OWASP FALLBACK ──────────────────────────

def derive_business_risk(finding: dict) -> str:
    """Priority: explicit field → labeled section in description → OWASP category → severity."""
    title = finding.get("title", "")
    sev   = finding.get("severity", "info").lower()
    desc  = finding.get("description", "")

    # 1. Explicit impact field on the finding
    for field in ("impact", "business_risk", "business_impact"):
        val = (finding.get(field) or "").strip()
        if val:
            return f"<strong>Impact:</strong> {esc(val)}"

    # 2. Labeled section extracted from the description text
    impact_text = _extract_section(desc, "impact", "business risk", "business impact", "risk")
    if impact_text:
        return f"<strong>Impact:</strong> {esc(impact_text)}"

    # 3. OWASP-category generic impact
    owasp    = infer_owasp(title, desc)
    cat_map  = _OWASP_IMPACT.get(owasp, {})
    fallback = cat_map.get(sev) or cat_map.get("default") or cat_map.get("high") or ""
    if fallback:
        return f"<strong>Impact:</strong> {esc(fallback)}"

    # 4. Severity-only last resort
    if sev == "critical":
        return (f"<strong>Impact:</strong> {esc(title)} enables an attacker to compromise "
                "confidentiality, integrity, or availability of application data. "
                "Immediate remediation required.")
    if sev == "high":
        return (f"<strong>Impact:</strong> {esc(title)} exposes data or functionality to "
                "significant risk that can be exploited without advanced skills.")
    return (f"<strong>Impact:</strong> {esc(title)} represents a security control deficiency "
            "that provides reconnaissance value or amplifies other findings.")


def derive_steps(finding: dict) -> str:
    """Priority: reproduction field → labeled section in description → OWASP steps → generic."""
    repro = finding.get("reproduction", {})
    # 1. Structured reproduction dict
    if isinstance(repro, dict):
        steps = (repro.get("steps") or "").strip()
        cmd   = (repro.get("command") or "").strip()
        if steps: return f"<p>{esc(steps)}</p>"
        if cmd:   return f"<p>Send the following request or run the command:</p>{code_block(cmd)}"
    elif isinstance(repro, str) and repro.strip():
        return f"<p>{esc(repro.strip())}</p>"

    title = finding.get("title", "")
    desc  = finding.get("description", "")
    ep    = esc(infer_endpoint(finding.get("target", "/")))

    # 2. Labeled reproduction section from description
    steps_text = _extract_section(desc, "steps", "reproduction", "how to reproduce",
                                  "proof of concept", "poc", "exploit")
    if steps_text:
        return f"<p>{esc(steps_text)}</p>"

    # 3. OWASP-category generic steps (endpoint substituted in)
    owasp = infer_owasp(title, desc)
    template = _OWASP_STEPS.get(owasp, "")
    if template:
        return template.replace("__EP__", ep)

    # 4. Generic fallback
    return (f"<ol>"
            f"<li>Authenticate to the application if required</li>"
            f"<li>Send the crafted request to <code>{ep}</code> as documented in the Evidence section</li>"
            f"<li>Observe the vulnerability-confirming response</li>"
            f"</ol>")


def derive_remediation(finding: dict) -> str:
    """Priority: remediation field → labeled section in description → OWASP guidance → generic."""
    title = finding.get("title", "")
    desc  = finding.get("description", "")

    # 1. Explicit remediation field
    for field in ("remediation", "fix", "recommendation", "mitigation"):
        val = (finding.get(field) or "").strip()
        if val:
            return f"<p>{esc(val)}</p>"

    # 2. Labeled section from description
    remed_text = _extract_section(desc, "remediation", "fix", "recommendation",
                                  "mitigation", "how to fix")
    if remed_text:
        return f"<p>{esc(remed_text)}</p>"

    # 3. OWASP-category generic guidance
    owasp    = infer_owasp(title, desc)
    guidance = _OWASP_REMEDIATION.get(owasp, "")
    if guidance:
        return guidance

    # 4. Generic fallback
    return ("<p>Apply defence-in-depth: input validation, output encoding, least-privilege access "
            "controls, and security header enforcement. Add automated security tests to the "
            "CI/CD pipeline.</p>")


# ── FINDING CARD ──────────────────────────────────────────────────────────────

def find_poc_file(title: str):
    pocs_dir = BASE_DIR / "pocs"
    if not pocs_dir.exists(): return None
    words = set(re.findall(r'[a-z0-9]+', title.lower()))
    best, best_score = None, 1
    for p in pocs_dir.glob("*.http"):
        score = len(words & set(re.findall(r'[a-z0-9]+', p.stem.lower())))
        if score > best_score:
            best_score, best = score, p
    return best

def _format_text_block(text: str) -> str:
    """Convert free-text paragraphs to HTML, detecting code blocks."""
    out = ""
    for para in re.split(r'\n{2,}', text.strip()):
        para = para.strip()
        if not para: continue
        if (para.startswith("```")
                or re.match(r'^(GET|POST|PUT|DELETE|PATCH|HTTP/|curl |SELECT |INSERT |UPDATE |COPY )\b', para)
                or para.count('\n') > 2):
            out += code_block(para.strip('`').strip())
        else:
            out += f"<p>{esc(para)}</p>"
    return out

def finding_card(np_id: str, finding: dict) -> str:
    sev   = finding.get("severity", "info").lower()
    title = finding.get("title", "Untitled Finding")
    tgt   = infer_endpoint(finding.get("target", "/"))
    desc  = finding.get("description", "")
    evid  = finding.get("evidence", "")
    owasp = infer_owasp(title, desc)
    asvs  = infer_asvs(title, desc)
    auth  = infer_auth(desc)
    biz   = derive_business_risk(finding)
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

    desc_html = _format_text_block(desc)

    evid_html = ""
    if evid:
        for part in re.split(r'\n{2,}', str(evid).strip())[:3]:
            part = part.strip()
            if not part: continue
            if (len(part) > 150 or '\n' in part
                    or re.match(r'^(HTTP|GET|POST|PUT|DELETE|curl|{)', part)):
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


# ── PAGE BUILDERS ─────────────────────────────────────────────────────────────

def load_findings() -> list[dict]:
    data = json.loads(FINDINGS_PATH.read_text())
    raw = data.get("findings", data) if isinstance(data, dict) else data
    findings = [f for f in raw if isinstance(f, dict) and f.get("type", "finding") == "finding"]
    seen: dict[str, dict] = {}
    for f in findings:
        key = normalize_title(f.get("title", ""))
        prev = seen.get(key)
        if prev is None or len(str(f.get("evidence", ""))) > len(str(prev.get("evidence", ""))):
            seen[key] = f
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(seen.values(), key=lambda f: order.get(f.get("severity", "info").lower(), 4))

def build_stat_boxes(counts: dict) -> str:
    boxes = ""
    for sev, label, color in [
        ("critical", "Critical", "#ff4d6d"), ("high", "High", "#ff8c42"),
        ("medium", "Medium", "#ffd166"),     ("low", "Low", "#5bf29b"),
    ]:
        n = counts.get(sev, 0)
        if n:
            boxes += (f'<div class="stat-box"><span class="stat-num" style="color:{color};">{n}</span>'
                      f'<span class="stat-label">{label}</span></div>\n')
    boxes += (f'<div class="stat-box"><span class="stat-num" style="color:#7b78ff;">{counts["total"]}</span>'
              f'<span class="stat-label">Total</span></div>\n')
    return f'<div class="stat-row">\n{boxes}</div>'

def build_exec_summary(findings: list[dict], counts: dict) -> str:
    crits   = [f for f in findings if f.get("severity", "").lower() == "critical"]
    highs   = [f for f in findings if f.get("severity", "").lower() == "high"]
    mediums = [f for f in findings if f.get("severity", "").lower() == "medium"]

    top_titles = "; ".join(
        f"<strong>{esc(f['title'])}</strong>" for f in (crits + highs)[:3]
    )
    medium_themes = "; ".join(esc(f.get("title", "")) for f in mediums[:3])

    critical_sentence = (
        f"The most severe findings — {top_titles} — require immediate remediation."
        if top_titles else ""
    )
    medium_sentence = (
        f"<p>Recurring medium-severity themes include: {medium_themes}.</p>"
        if medium_themes else ""
    )

    # Derive unique OWASP categories from actual findings for the methodology note
    owasp_cats = sorted(set(
        infer_owasp(f.get("title", ""), f.get("description", ""))
        for f in findings
        if f.get("severity", "info").lower() != "info"
    ))
    owasp_note = (
        f"<p>Vulnerabilities span {len(owasp_cats)} OWASP category{'s' if len(owasp_cats) != 1 else ''}: "
        + "; ".join(f"<em>{esc(c)}</em>" for c in owasp_cats[:5])
        + ("..." if len(owasp_cats) > 5 else "") + ".</p>"
        if owasp_cats else ""
    )

    return f"""
<h1>Executive Summary</h1>
<div class="section">
<p>NullPointer Studio conducted a penetration test of <strong>{esc(_TARGET_HOST)}</strong> on
<strong>{_TEST_DATE}</strong> using automated scanning, manual exploitation, and security tooling
across all discovered attack surfaces.</p>

<p>The assessment uncovered <strong>{counts['critical']} critical</strong> and
<strong>{counts['high']} high</strong> severity vulnerabilities. {critical_sentence}</p>

{medium_sentence}
{owasp_note}
<p>A total of <strong>{counts['total']}</strong> findings were identified:
{counts['critical']} critical, {counts['high']} high, {counts['medium']} medium,
{counts['low']} low, and {counts['info']} informational.</p>
</div>"""

def build_scope() -> str:
    scope_items     = _SESSION.get("scope") or [_TARGET_HOST]
    oos_items       = _SESSION.get("out_of_scope") or []

    scope_rows = ""
    for s in scope_items:
        scope_rows += f'  <tr><td><code>{esc(s)}</code></td><td>Web Application</td><td>Yes</td></tr>\n'
    for s in oos_items:
        scope_rows += f'  <tr><td><code>{esc(s)}</code></td><td>—</td><td>No</td></tr>\n'

    return f"""
<h1>Scope &amp; Methodology</h1>
<div class="section">
<h2>Target Scope</h2>
<table class="meta-table">
  <tr><th>Asset</th><th>Type</th><th>In Scope</th></tr>
{scope_rows}</table>
<h2>Methodology</h2>
<ul>
  <li><strong>Recon:</strong> Subdomain enumeration, port scanning (naabu/nmap), HTTP fingerprinting (httpx)</li>
  <li><strong>Web Application:</strong> OWASP Web Top 10 systematic testing with full coverage matrix (ffuf, spider, nuclei, manual HTTP)</li>
  <li><strong>API Security:</strong> OWASP API Security Top 10 (2023) — BOLA, BFLA, BOPLA, JWT attacks, GraphQL introspection</li>
  <li><strong>AI Red-Team:</strong> OWASP LLM Top 10 (2025) — prompt injection, system prompt extraction, jailbreaks (FuzzyAI, PyRIT)</li>
  <li><strong>Post-Exploitation:</strong> Privilege escalation, credential harvesting, lateral movement from confirmed access</li>
  <li><strong>Network Assessment:</strong> Internal topology enumeration from compromised service context</li>
</ul>
<h2>Frameworks</h2>
<ul>
  <li>OWASP WSTG, API Security Top 10 (2023), LLM Top 10 (2025), ASVS 5.0</li>
  <li>MITRE ATT&amp;CK for Enterprise</li>
  <li>AWS Well-Architected Security Pillar</li>
</ul>
</div>"""

def build_dashboard(findings: list[dict]) -> str:
    rows = ""
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "info").lower()
        rows += (
            f'<tr>'
            f'<td style="font-family:\'IBM Plex Mono\',monospace;font-size:8pt;color:#7b78ff;">NP-{i:03d}</td>'
            f'<td>{badge(sev)}</td>'
            f'<td style="color:#e8e6f0;">{esc(f.get("title", ""))}</td>'
            f'<td style="color:#9b98b8;font-size:8pt;">'
            f'{esc(infer_owasp(f.get("title",""), f.get("description","")))}</td>'
            f'<td style="color:#9b98b8;">{"Informational" if sev == "info" else "Confirmed"}</td>'
            f'</tr>\n'
        )
    return f"""<h1>Risk Dashboard</h1>
<table class="dashboard-table">
  <thead><tr><th>ID</th><th>Severity</th><th>Finding</th><th>OWASP</th><th>Status</th></tr></thead>
  <tbody>{rows}</tbody>
</table>"""

def build_remediation_table(findings: list[dict]) -> str:
    p_map = {"critical":"P0 — Immediate","high":"P0 — Immediate","medium":"P2 — Next Sprint",
             "low":"P3 — Milestone","info":"—"}
    e_map = {"critical":"High","high":"Medium","medium":"Low","low":"Low","info":"—"}
    rows = ""
    for i, f in enumerate(findings, 1):
        sev   = f.get("severity", "info").lower()
        title = f.get("title", "")
        owasp = infer_owasp(title, f.get("description", ""))
        # Derive a one-line fix summary from the OWASP category
        fix_line = {
            "A03:2021 — Injection":                               "Parameterized queries; least-privilege DB account",
            "A01:2021 — Broken Access Control":                   "Ownership check on all object access; field allowlisting",
            "A07:2021 — Identification and Authentication Failures": "Rotate secrets; enforce MFA; rate limit auth endpoints",
            "A10:2021 — Server-Side Request Forgery":             "URL allowlist; block RFC 1918 and metadata IPs",
            "A05:2021 — Security Misconfiguration":               "Disable debug; add security headers; restrict metadata access",
            "A02:2021 — Cryptographic Failures":                  "Enforce TLS 1.2+ and HSTS preload; strong algorithms",
            "LLM01:2025 — Prompt Injection":                      "Sanitize AI inputs/outputs; remove secrets from system prompt",
            "A04:2021 — Insecure Design":                         "Architectural review; threat modelling; layered controls",
        }.get(owasp, "Apply OWASP remediation guidance for " + owasp.split(" — ")[-1])
        rows += (
            f'<tr>'
            f'<td style="font-family:\'IBM Plex Mono\',monospace;color:#7b78ff;font-size:8pt;">NP-{i:03d}</td>'
            f'<td>{badge(sev)}</td>'
            f'<td style="color:#e8e6f0;">{esc(title)}</td>'
            f'<td style="color:#9b98b8;font-size:8pt;">{esc(p_map.get(sev,"—"))}</td>'
            f'<td style="color:#9b98b8;">{esc(e_map.get(sev,"—"))}</td>'
            f'<td style="color:#9b98b8;font-size:8pt;">{esc(fix_line)}</td>'
            f'</tr>\n'
        )
    return f"""<h1>Remediation Summary</h1>
<table class="remediation-table">
  <thead><tr><th>ID</th><th>Severity</th><th>Finding</th><th>Priority</th><th>Effort</th><th>Fix</th></tr></thead>
  <tbody>{rows}</tbody>
</table>"""


# ── HTML ASSEMBLY ─────────────────────────────────────────────────────────────

def build_html() -> str:
    findings = load_findings()
    counts: dict[str, int] = {s: 0 for s in ("critical","high","medium","low","info","total")}
    for f in findings:
        s = f.get("severity", "info").lower()
        counts[s] = counts.get(s, 0) + 1
        counts["total"] += 1

    logo_html = (
        f'<img class="cover-logo" src="{LOGO_SRC}" alt="NullPointer Studio">'
        if LOGO_SRC else
        '<div style="height:180px;margin-bottom:2.5cm;display:flex;align-items:center;justify-content:center;">'
        '<span style=\'font-family:"Chakra Petch",monospace;font-size:24pt;font-weight:700;color:#7b78ff;\'>'
        'NullPointer Studio</span></div>'
    )

    cover = f"""<div class="cover">
  {logo_html}
  <div class="cover-classification">CONFIDENTIAL</div>
  <div class="cover-title">Penetration Test Report</div>
  <div class="cover-subtitle">{esc(_TARGET_HOST)}</div>
  <div class="cover-divider"></div>
  <div class="cover-meta"><table>
    <tr><td>Target</td><td>{esc(_TARGET or _TARGET_HOST)}</td></tr>
    <tr><td>Test date</td><td>{esc(_TEST_DATE)}</td></tr>
    <tr><td>Report date</td><td>{esc(datetime.date.today().isoformat())}</td></tr>
    <tr><td>Prepared by</td><td>NullPointer Studio</td></tr>
    <tr><td>Version</td><td>1.0</td></tr>
  </table></div>
  <div class="cover-footer">NullPointer Studio &middot; security research &amp; consulting</div>
</div>"""

    handling = f"""<div class="callout">
<strong>Handling Notice</strong><br><br>
This document contains confidential information pertaining to the security posture of
<strong>{esc(_TARGET_HOST)}</strong>.
It is intended solely for the named client and authorised recipients. This report must not be
reproduced, distributed, or disclosed to any third party without the express written consent of
NullPointer Studio.<br><br>
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
<title>{esc(_TARGET_HOST)} Penetration Test Report - NullPointer Studio</title>
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


# ── ENTRY POINT ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Reading findings.json ...")
    html_content = build_html()
    print(f"Writing HTML -> {OUTPUT_HTML}")
    OUTPUT_HTML.write_text(html_content, encoding="utf-8")
    print(f"Generating PDF -> {OUTPUT_PDF}")
    WeasyprintHTML(string=html_content, base_url=str(BASE_DIR.resolve())).write_pdf(str(OUTPUT_PDF))
    findings = load_findings()
    counts: dict[str, int] = {s: 0 for s in ("critical","high","medium","low","info")}
    for f in findings:
        counts[f.get("severity","info").lower()] = counts.get(f.get("severity","info").lower(), 0) + 1
    print(f"\nReport generated:")
    print(f"  PDF  -> {OUTPUT_PDF}")
    print(f"  HTML -> {OUTPUT_HTML}")
    print(f"  Findings: {len(findings)} total ({counts['critical']} critical, "
          f"{counts['high']} high, {counts['medium']} medium, {counts['low']} low, "
          f"{counts['info']} info)")
