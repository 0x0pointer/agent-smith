  function onLogFileChange() {
    _selectedLogFile = document.getElementById('log-file-select').value;
    pollLogs();
  }

  async function pollLogs() {
    if (scanDone) return;
    try {
      const qs = _selectedLogFile ? `&file=${encodeURIComponent(_selectedLogFile)}` : '';
      const r  = await fetch(`/api/logs?_=${Date.now()}${qs}`);
      if (!r.ok) return;
      const data = await r.json();

      // Populate file selector (preserve current selection)
      const sel   = document.getElementById('log-file-select');
      const files = data.files || [];
      const prev  = sel.value;
      while (sel.options.length > 1) sel.remove(1);
      for (const f of files) {
        const opt = document.createElement('option');
        opt.value = f;
        opt.textContent = f;
        sel.appendChild(opt);
      }
      if (prev) sel.value = prev;

      _logLines = data.lines || [];
      renderLogs();
    } catch { /* ignore */ }
  }

  function classifyLine(line) {
    if (line.includes('TOOL_CALL'))   return 'tool-call';
    if (line.includes('TOOL_RESULT')) return 'tool-result';
    if (line.includes('FINDING'))     return 'finding';
    if (line.includes('NOTE'))        return 'note';
    if (line.includes('DIAGRAM'))     return 'diagram';
    if (line.includes('WARNING'))     return 'warning';
    if (line.includes('ERROR'))       return 'error';
    return '';
  }

  function renderLogs() {
    const q      = document.getElementById('log-filter').value.toLowerCase();
    const out    = document.getElementById('log-output');
    const scroll = document.getElementById('log-autoscroll').checked;
    const lines  = q ? _logLines.filter(l => l.toLowerCase().includes(q)) : _logLines;
    out.innerHTML = lines.map(l => {
      const cls = classifyLine(l);
      return `<div class="log-line ${cls}">${esc(l)}</div>`;
    }).join('');
    if (scroll) out.scrollTop = out.scrollHeight;
  }

  // ── Helpers ───────────────────────────────────────────────────────────────
  function esc(s) {
    return String(s ?? '')
      .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  // ── Skills tab ────────────────────────────────────────────────────────────
  const SKILLS_CATALOG = [
    // Orchestration
    { name: 'pentester',              group: 'Orchestration',  desc: 'Full pentest orchestrator — recon, exploitation, reporting' },
    // Reconnaissance
    { name: 'osint',                  group: 'Recon',          desc: 'OSINT — subdomain enum, email harvest, Shodan, CT logs, Wayback' },
    { name: 'ssl-tls-audit',          group: 'Recon',          desc: 'TLS/SSL audit — protocol versions, ciphers, certificate chain' },
    { name: 'email-security',         group: 'Recon',          desc: 'Email security — SPF/DKIM/DMARC, open relay, spoofing' },
    // Exploitation
    { name: 'web-exploit',            group: 'Exploitation',   desc: 'Web exploitation — SQLi, XSS, SSTI, SSRF, auth bypass, business logic' },
    { name: 'codebase',               group: 'Exploitation',   desc: 'White-box OWASP ASVS 5.0 source code review' },
    { name: 'ai-redteam',             group: 'Exploitation',   desc: 'AI/LLM red-team — OWASP LLM Top 10, prompt injection, jailbreaks' },
    { name: 'credential-audit',       group: 'Exploitation',   desc: 'Credential testing — brute-force, spraying, MFA bypass, JWT attacks' },
    { name: 'analyze-cve',            group: 'Exploitation',   desc: 'CVE exploitability analysis — code path tracing, Burp PoC' },
    { name: 'metasploit',             group: 'Exploitation',   desc: 'Exploit validation and exploitation via Metasploit Framework' },
    { name: 'aikido-triage',          group: 'Exploitation',   desc: 'Triage Aikido security CSV against local codebase' },
    { name: 'param-fuzz',             group: 'Exploitation',   desc: 'Auth stripping, type confusion, boundary values, mass assignment, token entropy analysis' },
    { name: 'business-logic',         group: 'Exploitation',   desc: 'Business logic — value/quantity abuse, workflow bypass, BOLA/BFLA, replay, quota bypass' },
    { name: 'api-security',           group: 'Exploitation',   desc: 'OWASP API Top 10 — BOLA/IDOR, BFLA, mass assignment, GraphQL/gRPC, SSRF' },
    { name: 'oauth-security',         group: 'Exploitation',   desc: 'OAuth 2.0 / OIDC — redirect_uri bypass, PKCE downgrade, state CSRF, token leakage' },
    { name: 'saml-sso',               group: 'Exploitation',   desc: 'SAML SSO — signature wrapping (XSW), assertion forgery, IdP/audience confusion' },
    { name: 'supply-chain',           group: 'Exploitation',   desc: 'Supply chain — dependency confusion, typosquatting, malicious packages, build integrity' },
    { name: 'colang-gen',             group: 'Exploitation',   desc: 'NeMo Guardrails Colang generation — allow-list flows, AI firewall config' },
    // Post-Exploitation
    { name: 'post-exploit',           group: 'Post-Exploit',   desc: 'Privesc (Linux/Windows), persistence, credential harvesting, pivot' },
    { name: 'reverse-shell',          group: 'Post-Exploit',   desc: 'Reverse shell payload generation and listener management' },
    { name: 'lateral-movement',       group: 'Post-Exploit',   desc: 'Pass-the-hash, Kerberoasting, NTLM relay, WMI/WinRM abuse' },
    { name: 'container-k8s-security', group: 'Post-Exploit',   desc: 'Container escape, K8s RBAC, pod security, etcd, secret enumeration' },
    { name: 'cloud-security',         group: 'Post-Exploit',   desc: 'AWS/Azure/GCP — IAM escalation, public storage, serverless, IMDS' },
    { name: 'cloud-identity-federation', group: 'Post-Exploit', desc: 'Cloud identity federation — OIDC CI/CD trust abuse, workload identity, SSRF→IMDS→creds' },
    { name: 'ad-assessment',          group: 'Post-Exploit',   desc: 'Active Directory — GPO, ADCS (ESC1-8), BloodHound paths, trusts' },
    { name: 'network-assess',         group: 'Post-Exploit',   desc: 'VLAN hopping, ARP spoofing, LLMNR/NBT-NS, SNMP, NFS, segmentation' },
    // Mobile
    { name: 'mobile-pentest-plan',    group: 'Mobile',         desc: 'Mobile pentest orchestrator — fingerprint APK/IPA, scope MASVS baseline, dispatch' },
    { name: 'android-security',       group: 'Mobile',         desc: 'Android OWASP MASVS/MASTG — APK static/dynamic, storage, crypto, IPC, WebView' },
    { name: 'ios-security',           group: 'Mobile',         desc: 'iOS OWASP MASVS/MASTG — IPA static/dynamic, Keychain, ATS, URL schemes, pinning' },
    { name: 'masvs-checklist',        group: 'Mobile',         desc: 'OWASP MASVS 2.0 compliance matrix mapped to MASTG test IDs' },
    // Reporting
    { name: 'threat-modeling',        group: 'Reporting',      desc: 'PASTA framework + 4-question threat model with STRIDE analysis' },
    { name: 'compliance',             group: 'Reporting',      desc: 'OWASP ASVS 5.0 compliance matrix — 346 controls, per-control evidence, HTML report' },
    { name: 'remediate',              group: 'Reporting',      desc: 'Fix vulnerabilities in source code with patch generation' },
    { name: 'report',                 group: 'Reporting',      desc: 'Generate a styled PDF penetration-test report from findings.json' },
    { name: 'request-cves',           group: 'Reporting',      desc: 'Generate MITRE CVE request packages and GitHub Security Advisory drafts' },
    { name: 'gh-export',              group: 'Reporting',      desc: 'Format all confirmed findings as GitHub issue markdown blocks' },
  ];

  let _skillsSession = null;
