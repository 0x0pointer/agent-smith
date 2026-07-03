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
    // Detail view takes over the pane when a finding is open (progressive disclosure).
    if (_openFindingId) {
      const wrapEl = document.getElementById('findings-wrap');
      const f = (findings || []).find(x => x.id === _openFindingId);
      if (f && wrapEl) { wrapEl.innerHTML = renderFindingDetail(f); return; }
      _openFindingId = null;  // finding vanished (cleared) → fall back to the grid
    }
    let filtered = filter === 'all' ? findings : findings.filter(f => f.severity === filter);
    if (vfilter !== 'all') filtered = filtered.filter(f => f.verification_status === vfilter);
    const wrap = document.getElementById('findings-wrap');
    if (!filtered.length) {
      wrap.innerHTML = '<div class="empty-placeholder">No findings' +
        (filter !== 'all' || vfilter !== 'all' ? ` matching current filters` : ' yet — run a scan.') + '</div>';
      return;
    }
    // Group into severity SECTIONS (critical → info); within a section, order by
    // verification (unverified first — needs attention) then newest first. Each
    // section is a responsive grid of uniform, scannable cards.
    const SEVS = ['critical', 'high', 'medium', 'low', 'info'];
    const bySev = {};
    filtered.forEach(f => { (bySev[f.severity] = bySev[f.severity] || []).push(f); });
    wrap.innerHTML = SEVS.filter(s => bySev[s] && bySev[s].length).map(s => {
      const cards = bySev[s].sort((a, b) =>
        ((VS_ORDER[a.verification_status] ?? 9) - (VS_ORDER[b.verification_status] ?? 9))
        || (new Date(b.timestamp) - new Date(a.timestamp))
      ).map(f => cardHTML(f)).join('');
      return `<div class="finding-section">
        <div class="finding-section-head sev-${s}"><span class="fs-dot"></span>${s.toUpperCase()}<span class="fs-count">${bySev[s].length}</span></div>
        <div class="finding-cards">${cards}</div>
      </div>`;
    }).join('');
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

  // ── Full finding detail view (progressive disclosure: card → click → detail) ──
  let _openFindingId = null;

  function openFinding(id) {
    _openFindingId = id;
    renderFindingsTable(allData.findings || []);
    window.scrollTo(0, 0);
  }
  function closeFinding() {
    _openFindingId = null;
    renderFindingsTable(allData.findings || []);
  }
  function copyEvidence(btn, findingId) {
    const f = (allData.findings || []).find(x => x.id === findingId);
    if (!f?.evidence) return;
    navigator.clipboard.writeText(f.evidence).then(() => {
      const t = btn.textContent; btn.textContent = 'Copied!';
      setTimeout(() => { btn.textContent = t; }, 1500);
    });
  }

  function _rail(label, val) {
    return `<div class="fd-rail-k">${esc(label)}</div><div class="fd-rail-v">${val}</div>`;
  }

  function renderFindingDetail(f) {
    const vs = f.verification_status || 'unverified';
    const ts = f.timestamp ? new Date(f.timestamp).toLocaleString() : '—';
    const triaged = f.adjudication?.rationale ? `<span class="triaged-badge">⚖ Triaged</span>` : '';
    const sevVal  = `<span class="badge badge-${esc(f.severity)}">${esc(f.severity)}</span>`;
    const idCopy  = `<span class="fd-id">${esc(f.id)}</span>` +
                    `<button class="fd-copy" onclick="copyFindingId(this,'${esc(f.id)}')">copy</button>`;
    const evidence = f.evidence ? `
      <div class="fd-sec-head">Evidence <button class="fd-copy" onclick="copyEvidence(this,'${esc(f.id)}')">Copy evidence</button></div>
      <pre class="evidence">${esc(f.evidence)}</pre>` : '';
    const repro = f.reproduction?.command ? `
      <div class="fd-sec-head">Reproduction <button class="fd-copy" onclick="copyReplay(this,'${esc(f.id)}')">▸ Copy command</button></div>
      <pre class="evidence">${esc(f.reproduction.command)}</pre>
      ${f.reproduction.expected ? `<div class="fd-expected">expected: ${esc(f.reproduction.expected)}</div>` : ''}` : '';
    const seniorReview = f.adjudication?.rationale ? _adjudicationBlock(f.adjudication) : '';
    const pocs = (f.poc_files && f.poc_files.length)
      ? `<div class="fd-rail-box"><div class="fd-rail-title">PoC files</div>${
          f.poc_files.map(p => `<div class="fd-poc">${esc(p)}</div>`).join('')}</div>` : '';
    const remediation = f.remediation ? `<div class="fd-block">${buildFixDetail(f).replace('display:none', 'display:block')}</div>` : '';
    const impact = f.business_impact ? `
      <div class="finding-impact"><span class="finding-impact-icon">&#9888;</span>
      <span class="finding-impact-label">Business impact&nbsp;&nbsp;</span>
      <span class="finding-impact-text">${esc(f.business_impact)}</span></div>` : '';

    return `<div class="fd-view">
      <button class="fd-back" onclick="closeFinding()">← All findings</button>
      <div class="fd-hero sev-${esc(f.severity)}">
        <div class="fd-hero-badges">${sevVal}<span class="vbadge vbadge-${vs}">${VS_LABELS[vs] || vs}</span>${triaged}</div>
        <h2 class="fd-title">${esc(f.title)}</h2>
        <div class="fd-hero-meta"><span class="target">${esc(f.target)}</span>
          ${f.tool_used ? `<span class="tool">${esc(f.tool_used)}</span>` : ''}
          <span class="finding-ts-meta">first seen ${ts}</span></div>
      </div>
      <div class="fd-body">
        <div class="fd-main">
          ${f.description ? `<div class="fd-sec-head">Description</div><div class="finding-desc">${esc(f.description)}</div>` : ''}
          ${impact}
          ${evidence}
          ${repro}
          ${remediation}
        </div>
        <aside class="fd-rail">
          <div class="fd-rail-box fd-rail-grid">
            ${_rail('Severity', sevVal)}
            ${_rail('Verification', `<span class="vbadge vbadge-${vs}">${VS_LABELS[vs] || vs}</span>`)}
            ${_rail('Target', esc(f.target))}
            ${_rail('Tool', esc(f.tool_used || '—'))}
            ${_rail('Status', esc(f.status || 'confirmed'))}
            ${_rail('First seen', esc(ts))}
            ${_rail('Finding ID', idCopy)}
            ${f.cve ? _rail('CVE', esc(f.cve)) : ''}
          </div>
          ${seniorReview}
          ${pocs}
        </aside>
      </div>
    </div>`;
  }

  function copyFindingId(btn, id) {
    navigator.clipboard.writeText(id).then(() => {
      const t = btn.textContent; btn.textContent = 'copied'; setTimeout(() => { btn.textContent = t; }, 1500);
    });
  }

  function cardHTML(f) {
    const isNew    = freshIds.has(f.id);
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
    // Clean, uniform card — a scannable summary. Evidence, reproduction, senior
    // review and PoC all live in the click-through detail view (openFinding).
    return `<div class="finding-card sev-${f.severity}" onclick="openFinding('${esc(f.id)}')" title="Open full detail">
      <div class="finding-card-top">
        <span class="badge badge-${f.severity}">${f.severity}</span>${statusBadge}${triagedBadge}
        <span class="finding-vs-right">${vsBadge}</span>
      </div>
      <div class="finding-title">${esc(f.title)}${newBadge}</div>
      ${f.description ? `<div class="finding-desc">${esc(f.description)}</div>` : ''}
      <div class="finding-card-foot">
        <span class="target">${esc(f.target)}</span>
        ${f.tool_used ? `<span class="tool">${esc(f.tool_used)}</span>` : ''}
        ${cve}
        <span class="finding-ts-meta">${ts}</span>
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