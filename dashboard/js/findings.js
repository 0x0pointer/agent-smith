  async function pollFindings() {
    try {
      const r = await fetch(`/api/findings?_=${Date.now()}`);
      if (!r.ok) throw new Error('not found');
      const data = await r.json();
      freshIds = new Set();
      (data.findings || []).forEach(f => {
        if (!seenIds.has(f.id)) freshIds.add(f.id);
        seenIds.add(f.id);
      });
      allData = data;
      lastOk  = new Date();
      renderFindings();
    } catch {
      document.getElementById('status').innerHTML =
        '<span class="dot" style="background:#f85149"></span>Waiting for data…';
    }
  }

  function renderFindings() {
    const findings = allData.findings || [];
    const target   = allData.meta?.target || '';
    const ago = lastOk ? Math.round((Date.now() - lastOk) / 1000) + 's ago' : '';
    document.getElementById('status').innerHTML =
      `<span class="dot"></span>Live · refreshes every 5 s · last updated ${ago}` +
      (target ? ` · <strong style="color:#c9d1d9">${target}</strong>` : '');
    renderStats(findings);
    renderFindingsTable(findings);
    if (_activeTab === 'topology')   renderTopology(allData.diagrams || []);
    if (_activeTab === 'components') renderComponentMap(findings);
  }

  const VS_ORDER = {
    confirmed_dynamic:       0,
    new_dynamic_finding:     1,
    code_confirmed:          2,
    not_accessible_external: 3,
    not_confirmed:           4,
    unverified:              5,
  };
  const VS_LABELS = {
    confirmed_dynamic:       '✓ CONFIRMED',
    new_dynamic_finding:     '+ NEW DISCOVERY',
    code_confirmed:          '◉ CODE CONFIRMED',
    not_accessible_external: '⊘ INTERNAL ONLY',
    not_confirmed:           '? NOT CONFIRMED',
    unverified:              '· UNVERIFIED',
  };

  function renderStats(findings) {
    const c = { all: findings.length, critical:0, high:0, medium:0, low:0, info:0 };
    findings.forEach(f => { if (c[f.severity] !== undefined) c[f.severity]++; });
    document.getElementById('stats').innerHTML =
      ['all','critical','high','medium','low','info'].map(s =>
        `<span class="stat stat-${s}${filter===s?' active':''}" onclick="setFilter('${s}')">
          ${s==='all'?'ALL':s.toUpperCase()} ${c[s]}
        </span>`
      ).join('');

    // Verification filter bar
    const vc = {};
    const vsKeys = Object.keys(VS_ORDER);
    vsKeys.forEach(k => { vc[k] = 0; });
    findings.forEach(f => { if (vc[f.verification_status] !== undefined) vc[f.verification_status]++; });
    document.getElementById('vstats').innerHTML =
      `<span class="vstat-label">verify:</span>` +
      [['all', 'ALL ' + findings.length]].concat(vsKeys.filter(k => vc[k] > 0).map(k => [k, VS_LABELS[k] + ' ' + vc[k]])).map(([k, label]) =>
        `<span class="stat vstat-${k}${vfilter===k?' active':''}" onclick="setVFilter('${k}')">${label}</span>`
      ).join('');
  }

  function renderFindingsTable(findings) {
    let filtered = filter === 'all' ? findings : findings.filter(f => f.severity === filter);
    if (vfilter !== 'all') filtered = filtered.filter(f => f.verification_status === vfilter);
    filtered.sort((a, b) => {
      const vd = (VS_ORDER[a.verification_status]??9) - (VS_ORDER[b.verification_status]??9);
      if (vd !== 0) return vd;
      const d = (SEV_ORDER[a.severity]??5) - (SEV_ORDER[b.severity]??5);
      return d !== 0 ? d : new Date(b.timestamp) - new Date(a.timestamp);
    });
    const wrap = document.getElementById('findings-wrap');
    if (!filtered.length) {
      wrap.innerHTML = '<div class="empty-placeholder">No findings' +
        (filter !== 'all' || vfilter !== 'all' ? ` matching current filters` : ' yet — run a scan.') + '</div>';
      return;
    }
    const openIds = new Set();
    wrap.querySelectorAll('details[open]').forEach(el => openIds.add(el.dataset.id));
    wrap.innerHTML = `<div class="finding-cards">${filtered.map(f => cardHTML(f, openIds)).join('')}</div>`;
    // Restore open fix panels after DOM rebuild
    _openFixPanels.forEach(id => {
      const el = document.getElementById('fix-' + id);
      if (el) el.style.display = 'block';
    });
  }

  const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

  function _adjudicationBlock(adj) {
    if (!adj?.rationale) return '';
    const repro     = adj.reproducible === true || adj.reproducible === 'true';
    const reproHTML = repro
      ? '<span style="color:var(--green)">✓ Reproducible</span>'
      : '<span style="color:#f87171">✗ Not reproducible</span>';
    const orig = (adj.original_severity || '').toLowerCase();
    const rev  = (adj.revised_severity  || '').toLowerCase();
    let sevHTML = '';
    if (orig && rev && orig !== rev) {
      const up = (SEV_RANK[rev] ?? 9) < (SEV_RANK[orig] ?? 9);
      sevHTML =
        `<span class="fadj-sev-old">${esc(orig)}</span>` +
        `<span class="fadj-sev-arrow">→</span>` +
        `<span class="${up ? 'fadj-sev-new-up' : 'fadj-sev-new-down'}">${esc(rev)}</span>`;
    } else {
      sevHTML = `<span class="fadj-sev-same">${esc(orig || rev || '—')} (unchanged)</span>`;
    }
    return `
      <div class="finding-adjudication">
        <div class="finding-adjudication-header">⚖ Senior review</div>
        <div class="finding-adjudication-grid">
          <span class="fadj-label">Reproducible</span><span class="fadj-value">${reproHTML}</span>
          <span class="fadj-label">Severity</span><span class="fadj-value">${sevHTML}</span>
          <span class="fadj-label">Rationale</span><span class="fadj-value">${esc(adj.rationale)}</span>
        </div>
      </div>`;
  }

  function cardHTML(f, openIds) {
    const isNew    = freshIds.has(f.id);
    const isOpen   = openIds.has(f.id);
    const ts       = new Date(f.timestamp).toLocaleTimeString();
    const newBadge = isNew ? '<span class="new-badge">NEW</span>' : '';
    const cve      = f.cve ? `<span class="cve">CVE: ${esc(f.cve)}</span>` : '';
    const statusBadge = f.status === 'false_positive'
      ? `<span class="badge" style="background:rgba(107,104,144,.2);color:var(--text-dim);margin-left:.4rem">false positive</span>`
      : '';
    const triagedBadge = f.adjudication?.rationale
      ? `<span class="triaged-badge" title="Senior-reviewed: ${esc(f.adjudication.rationale)}">⚖ Triaged</span>`
      : '';
    const vs = f.verification_status || 'unverified';
    const vsBadge = `<span class="vbadge vbadge-${vs}" title="Verification status: ${vs.replace(/_/g,' ')}">${VS_LABELS[vs] || vs}</span>`;
    const ghBtn = f.gh_issue
      ? `<button class="copy-gh-btn" data-id="${esc(f.id)}" onclick="copyGhIssue(this,this.dataset.id)" title="Copy GitHub issue">
           <svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor">
             <path d="M0 6.75C0 5.784.784 5 1.75 5h1.5a.75.75 0 0 1 0 1.5h-1.5a.25.25 0 0 0-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 0 0 .25-.25v-1.5a.75.75 0 0 1 1.5 0v1.5A1.75 1.75 0 0 1 9.25 16h-7.5A1.75 1.75 0 0 1 0 14.25Z"/><path d="M5 1.75C5 .784 5.784 0 6.75 0h7.5C15.216 0 16 .784 16 1.75v7.5A1.75 1.75 0 0 1 14.25 11h-7.5A1.75 1.75 0 0 1 5 9.25Zm1.75-.25a.25.25 0 0 0-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 0 0 .25-.25v-7.5a.25.25 0 0 0-.25-.25Z"/>
           </svg>
           GH Issue
         </button>`
      : '';
    const replayBtn = f.reproduction?.command
      ? `<button class="replay-btn" data-id="${esc(f.id)}" onclick="copyReplay(this,this.dataset.id)" title="Copy reproduction command">&#9654; Replay</button>`
      : '';
    const fixBtn = f.remediation
      ? `<button class="fix-btn" data-id="${esc(f.id)}" onclick="toggleFix(this.dataset.id)" title="Show remediation">&#128295; Fix</button>`
      : '';
    const fixDetail  = f.remediation ? buildFixDetail(f) : '';
    const adjBlock   = _adjudicationBlock(f.adjudication);
    const impactHtml = f.business_impact
      ? `<div class="finding-impact">
           <span class="finding-impact-icon">&#9888;</span>
           <span class="finding-impact-label">Business impact&nbsp;&nbsp;</span>
           <span class="finding-impact-text">${esc(f.business_impact)}</span>
         </div>`
      : '';
    return `<div class="finding-card sev-${f.severity}">
      <div class="finding-header">
        <span class="badge badge-${f.severity}">${f.severity}</span>${statusBadge}${triagedBadge}${vsBadge}
        <div class="finding-title-group">
          <div class="finding-title">${esc(f.title)}${newBadge}</div>
          <div class="finding-meta-row">
            <span class="target">${esc(f.target)}</span>
            ${f.tool_used ? `<span class="tool">${esc(f.tool_used)}</span>` : ''}
            ${cve}
            <span class="finding-ts-meta">${ts}</span>
          </div>
        </div>
      </div>
      ${impactHtml}
      ${adjBlock}
      ${f.description ? `<div class="finding-desc">${esc(f.description)}</div>` : ''}
      ${fixDetail}
      <div class="finding-footer">
        ${replayBtn}${fixBtn}${ghBtn}
        ${f.evidence ? `<details ${isOpen?'open':''} data-id="${f.id}" style="width:100%;margin-top:${(replayBtn||fixBtn||ghBtn)?'0.4rem':'0'}">
          <summary></summary>
          <pre class="evidence">${esc(f.evidence)}</pre>
        </details>` : ''}
      </div>
    </div>`;
  }

  // ── GH Issue clipboard copy ────────────────────────────────────────────────
  function copyGhIssue(btn, findingId) {
    const f = (allData.findings || []).find(x => x.id === findingId);
    if (!f?.gh_issue) return;
    navigator.clipboard.writeText(f.gh_issue).then(() => {
      btn.classList.add('copied');
      btn.innerHTML = btn.innerHTML.replace('GH Issue', 'Copied!');
      setTimeout(() => {
        btn.classList.remove('copied');
        btn.innerHTML = btn.innerHTML.replace('Copied!', 'GH Issue');
      }, 2000);
    });
  }

  // ── Replay button — copy reproduction command ──────────────────────────────
  function copyReplay(btn, findingId) {
    const f = (allData.findings || []).find(x => x.id === findingId);
    if (!f?.reproduction?.command) return;
    navigator.clipboard.writeText(f.reproduction.command).then(() => {
      btn.classList.add('copied');
      btn.textContent = 'Copied!';
      setTimeout(() => { btn.classList.remove('copied'); btn.innerHTML = '&#9654; Replay'; }, 2000);
    });
  }

  // ── Fix button — toggle remediation detail ─────────────────────────────────
  const _openFixPanels = new Set();
  function toggleFix(findingId) {
    const el = document.getElementById('fix-' + findingId);
    if (!el) return;
    if (_openFixPanels.has(findingId)) {
      _openFixPanels.delete(findingId);
      el.style.display = 'none';
    } else {
      _openFixPanels.add(findingId);
      el.style.display = 'block';
    }
  }

  function buildFixDetail(f) {
    const r = f.remediation;
    if (!r) return '';
    const effortClass = r.effort === 'low' ? 'effort-low' : r.effort === 'high' ? 'effort-high' : 'effort-medium';
    const breaking = r.breaking_change ? '<span style="color:#da3633;margin-left:.5rem">&#9888; Breaking change</span>' : '';
    const diffBlock = r.diff ? `<div style="margin-top:.5rem"><strong>Diff:</strong><pre>${esc(r.diff)}</pre></div>` : '';
    const beforeAfter = (r.before && r.after) ? `
      <div style="margin-top:.5rem"><strong>Before:</strong><pre style="color:#da3633">${esc(r.before)}</pre></div>
      <div><strong>After:</strong><pre style="color:#3fb950">${esc(r.after)}</pre></div>` : '';
    const refs = r.references?.length ? `<div style="margin-top:.5rem"><strong>References:</strong><ul>${r.references.map(u => '<li><a href="'+esc(u)+'" target="_blank" style="color:#58a6ff">'+esc(u)+'</a></li>').join('')}</ul></div>` : '';
    const verify = r.verification ? `<div style="margin-top:.5rem"><strong>Verification:</strong> ${esc(r.verification)}</div>` : '';
    const file = r.file ? `<div style="margin-top:.3rem;color:#8b949e">${esc(r.file)}${r.line ? ':'+r.line : ''} (${esc(r.language||'')})</div>` : '';
    return `<div id="fix-${f.id}" class="remediation-detail" style="display:none">
      <div><strong>${esc(r.summary)}</strong></div>
      <div style="margin-top:.3rem"><span class="effort-badge ${effortClass}">${esc(r.effort||'unknown')} effort</span>${breaking}</div>
      ${file}${diffBlock}${beforeAfter}${verify}${refs}
    </div>`;
  }

  function setFilter(sev) {
    filter = sev;
    renderStats(allData.findings || []);
    renderFindingsTable(allData.findings || []);
  }

  function setVFilter(vs) {
    vfilter = vs;
    renderStats(allData.findings || []);
    renderFindingsTable(allData.findings || []);
  }

  // ── Tunnel cleanup ─────────────────────────────────────────────────────
  function cleanupTunnels() {
    if (!confirm('Kill chisel tunnels and Meterpreter sessions? You will lose access to internal services.')) return;
    const btn = document.querySelector('.tunnel-btn');
    btn.textContent = 'Cleaning up…';
    btn.disabled = true;
    fetch('/api/tunnels', { method: 'DELETE' })
      .then(r => r.json())
      .then(d => {
        btn.textContent = d.message || 'Done';
        setTimeout(() => { btn.textContent = 'Cleanup Tunnels'; btn.disabled = false; }, 3000);
      })
      .catch(() => { btn.textContent = 'Failed'; setTimeout(() => { btn.textContent = 'Cleanup Tunnels'; btn.disabled = false; }, 3000); });
  }

  // ── Clear all findings ──────────────────────────────────────────────────
  function clearFindings() {
    if (!confirm('Clear ALL scan data? This wipes findings, session, coverage, skills, logs, QA state, and kills any active tunnels. This cannot be undone.')) return;
    fetch('/api/clear', { method: 'DELETE' })
      .then(r => r.json())
      .then(d => {
        if (!d.ok) return;

        // ── In-memory state ──────────────────────────────────────────────
        allData  = { findings: [], diagrams: [] };
        scanDone = false;
        seenIds  = new Set();
        freshIds = new Set();
        filter   = 'all';
        _logLines = [];

        // ── Status bar ───────────────────────────────────────────────────
        document.getElementById('status').innerHTML =
          '<span class="dot"></span>Live · refreshes every 5 s';

        // ── Command Center reset ───────────────────────────────────────────
        const cmdTarget = document.getElementById('cmd-target');
        if (cmdTarget) cmdTarget.textContent = '—';
        const cmdStatus = document.getElementById('cmd-scan-status');
        if (cmdStatus) { cmdStatus.textContent = '—'; cmdStatus.className = 'cmd-scan-status'; }
        const cmdPhase = document.getElementById('cmd-phase-pill');
        if (cmdPhase) cmdPhase.style.display = 'none';
        const cmdCov = document.getElementById('cmd-cov-group');
        if (cmdCov) cmdCov.style.display = 'none';
        const cmdCost = document.getElementById('cmd-cost-group');
        if (cmdCost) cmdCost.style.display = 'none';

        // ── Findings tab ──────────────────────────────────────────────────
        renderStats([]);
        document.getElementById('findings-wrap').innerHTML =
          '<div class="empty-placeholder">No findings yet — run a scan.</div>';

        // ── Topology tab ──────────────────────────────────────────────────
        document.getElementById('diagrams-wrap').innerHTML =
          '<div class="empty-placeholder">No diagrams yet — Claude calls report_diagram during a scan.</div>';

        // ── Components tab ────────────────────────────────────────────────
        document.getElementById('components-wrap').innerHTML = '';

        // ── Coverage tab ──────────────────────────────────────────────────
        document.getElementById('coverage-summary').innerHTML = '';
        document.getElementById('coverage-wrap').innerHTML =
          '<div class="empty-placeholder">No coverage data yet — run a scan with web-exploit.</div>';

        // ── Skills tab ────────────────────────────────────────────────────
        document.getElementById('skills-summary').innerHTML = '';
        document.getElementById('skills-wrap').innerHTML =
          '<div class="empty-placeholder">No active scan session — start a scan to track skill usage.</div>';

        // ── Activity tab ──────────────────────────────────────────────────
        document.getElementById('qa-last-check').textContent = '';
        document.getElementById('qa-alerts-wrap').innerHTML =
          '<div class="empty-placeholder">Waiting for first QA cycle (runs every 2 min during an active scan).</div>';
        document.getElementById('quicklog-wrap').innerHTML =
          '<div class="empty-placeholder">No tool activity yet — start a scan.</div>';
        document.getElementById('steering-active-wrap').innerHTML =
          '<div class="empty-placeholder">No active steering directives.</div>';
        document.getElementById('steering-history-wrap').innerHTML =
          '<div class="empty-placeholder">No steering history yet.</div>';
        _qaData = null;
        _steeringData = null;
        _sessionData = null;
        _cycleRenderedCount = 0;
        _adjudicationRenderedCount = 0;
        const stuckWrap = document.getElementById('stuck-log-wrap');
        if (stuckWrap) stuckWrap.innerHTML = '<div class="empty-placeholder">No stuck events yet — Smith is running smoothly.</div>';
        document.getElementById('cycle-history-wrap').innerHTML =
          '<div class="empty-placeholder">No cycles yet — QA starts 2 min after scan begins.</div>';
        const adjWrap = document.getElementById('adjudication-log-wrap');
        if (adjWrap) adjWrap.innerHTML = '<div class="empty-placeholder">No adjudication pass recorded yet.</div>';
        const adjSection = document.getElementById('adjudication-section');
        if (adjSection) adjSection.style.display = 'none';

        // ── Logs tab ──────────────────────────────────────────────────────
        document.getElementById('log-output').innerHTML = '';

        // ── Threat model tab ──────────────────────────────────────────────
        const tmWrap = document.getElementById('threat-model-wrap');
        if (tmWrap) {
          tmWrap.className = 'empty';
          tmWrap.innerHTML = 'No threat model yet — run the threat-modeling in <code>/pentester</code>';
        }
      })
      .catch(() => alert('Failed to clear — is the dashboard API running?'));
  }

  // ── Topology tab ──────────────────────────────────────────────────────────