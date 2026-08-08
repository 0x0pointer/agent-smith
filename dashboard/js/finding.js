// ============================================================================
//  finding.js — renders the standalone finding "dossier" page (/finding/<id>).
//  Depends on shared.js for the auth shim + esc() + mermaid setup.
//  Wrapped in an IIFE; copy buttons use event delegation (no globals needed).
// ============================================================================
(function () {
  const POLL_MS = 5000;
  const shell    = document.querySelector('.dossier-shell');
  const fid      = shell ? shell.getAttribute('data-finding-id') : '';
  const root     = document.getElementById('dossier-root');
  const statusEl = document.getElementById('dossier-status');

  const SEV_RANK  = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const VS_LABELS = {
    confirmed_dynamic:       '✓ CONFIRMED',
    new_dynamic_finding:     '+ NEW DISCOVERY',
    code_confirmed:          '◉ CODE CONFIRMED',
    not_accessible_external: '⊘ INTERNAL ONLY',
    not_confirmed:           '? NOT CONFIRMED',
    unverified:              '· UNVERIFIED',
  };

  let _lastKey = '';

  // ── helpers ────────────────────────────────────────────────────────────────
  function fmtTime(ts) {
    if (!ts) return '';
    const d = new Date(ts);
    return isNaN(d) ? String(ts) : d.toLocaleString();
  }
  function section(title, bodyHtml, extraClass) {
    if (!bodyHtml) return '';
    return `<section class="dossier-section ${extraClass || ''}">
      <h2 class="dossier-section-title">${esc(title)}</h2>
      ${bodyHtml}
    </section>`;
  }
  function railRow(label, valueHtml) {
    if (!valueHtml && valueHtml !== 0) return '';
    return `<div class="drail-label">${esc(label)}</div><div class="drail-value">${valueHtml}</div>`;
  }
  function copyBtn(text, label) {
    // data-copy is base64 so arbitrary payloads survive the attribute intact.
    const enc = btoa(unescape(encodeURIComponent(text)));
    return `<button class="dossier-copy" data-copy="${enc}">${esc(label || 'Copy')}</button>`;
  }

  // ── data-flow trace → vertical stepped timeline ──────────────────────────────
  function traceHtml(trace) {
    if (!Array.isArray(trace) || !trace.length) return '';
    const kindLabel = { entrypoint: 'ENTRY', propagation: 'FLOW', sink: 'SINK' };
    const steps = trace.map((s, i) => {
      const kind = (s.kind || '').toLowerCase();
      const loc  = s.file ? `${esc(s.file)}${s.line ? ':' + esc(s.line) : ''}` : '';
      return `<li class="trace-step trace-${esc(kind)}">
        <span class="trace-node"></span>
        <div class="trace-body">
          <div class="trace-head">
            <span class="trace-kind">${esc(kindLabel[kind] || kind || 'STEP')}</span>
            ${loc ? `<span class="trace-loc">${loc}</span>` : ''}
            ${s.scope ? `<span class="trace-scope">${esc(s.scope)}</span>` : ''}
          </div>
          ${s.description ? `<div class="trace-desc">${esc(s.description)}</div>` : ''}
        </div>
      </li>`;
    }).join('');
    return `<ol class="trace-timeline">${steps}</ol>`;
  }

  // ── adjudication (senior review) ─────────────────────────────────────────────
  function adjudicationHtml(adj) {
    if (!adj || !adj.rationale) return '';
    const repro = adj.reproducible === true || adj.reproducible === 'true';
    const reproHtml = repro
      ? '<span class="adj-ok">✓ Reproducible</span>'
      : '<span class="adj-no">✗ Not reproducible</span>';
    const orig = (adj.original_severity || '').toLowerCase();
    const rev  = (adj.revised_severity  || '').toLowerCase();
    let sevHtml;
    if (orig && rev && orig !== rev) {
      const up = (SEV_RANK[rev] ?? 9) < (SEV_RANK[orig] ?? 9);
      sevHtml = `<span class="fadj-sev-old">${esc(orig)}</span>` +
                `<span class="fadj-sev-arrow">→</span>` +
                `<span class="${up ? 'fadj-sev-new-up' : 'fadj-sev-new-down'}">${esc(rev)}</span>`;
    } else {
      sevHtml = `<span class="fadj-sev-same">${esc(orig || rev || '—')} (unchanged)</span>`;
    }
    return `<div class="finding-adjudication">
      <div class="finding-adjudication-header">⚖ Senior review</div>
      <div class="finding-adjudication-grid">
        <span class="fadj-label">Reproducible</span><span class="fadj-value">${reproHtml}</span>
        <span class="fadj-label">Severity</span><span class="fadj-value">${sevHtml}</span>
        ${adj.artifact_id ? `<span class="fadj-label">Artifact</span><span class="fadj-value"><code>${esc(adj.artifact_id)}</code></span>` : ''}
        <span class="fadj-label">Rationale</span><span class="fadj-value">${esc(adj.rationale)}</span>
      </div>
    </div>`;
  }

  // ── remediation ──────────────────────────────────────────────────────────────
  function remediationHtml(r) {
    if (!r) return '';
    const effortClass = r.effort === 'low' ? 'effort-low' : r.effort === 'high' ? 'effort-high' : 'effort-medium';
    const breaking = r.breaking_change ? '<span class="rem-breaking">⚠ Breaking change</span>' : '';
    const file = r.file ? `<div class="rem-file">${esc(r.file)}${r.line ? ':' + esc(r.line) : ''}${r.language ? ' (' + esc(r.language) + ')' : ''}</div>` : '';
    const diff = r.diff ? `<div class="rem-block"><strong>Diff</strong><pre class="evidence">${esc(r.diff)}</pre></div>` : '';
    const ba = (r.before && r.after)
      ? `<div class="rem-block"><strong>Before</strong><pre class="evidence rem-before">${esc(r.before)}</pre></div>
         <div class="rem-block"><strong>After</strong><pre class="evidence rem-after">${esc(r.after)}</pre></div>`
      : '';
    const verify = r.verification ? `<div class="rem-block"><strong>Verification</strong><div class="rem-verify">${esc(r.verification)}</div></div>` : '';
    const refs = Array.isArray(r.references) && r.references.length
      ? `<div class="rem-block"><strong>References</strong><ul class="rem-refs">${r.references.map(u => `<li><a href="${esc(u)}" target="_blank" rel="noopener">${esc(u)}</a></li>`).join('')}</ul></div>`
      : '';
    return `<div class="remediation-detail">
      <div><strong>${esc(r.summary || 'Remediation')}</strong></div>
      <div class="rem-meta"><span class="effort-badge ${effortClass}">${esc(r.effort || 'unknown')} effort</span>${breaking}</div>
      ${file}${diff}${ba}${verify}${refs}
    </div>`;
  }

  // ── escalation leads (may be a string or a list of {lead,status,result}) ─────
  function escalationHtml(leads) {
    if (!leads) return '';
    if (typeof leads === 'string') return `<div class="dossier-text">${esc(leads)}</div>`;
    if (!Array.isArray(leads) || !leads.length) return '';
    return `<ul class="esc-leads">${leads.map(l => {
      if (typeof l === 'string') return `<li>${esc(l)}</li>`;
      const st = l.status ? `<span class="esc-status esc-${esc(l.status)}">${esc(l.status)}</span>` : '';
      return `<li>${st}${esc(l.lead || '')}${l.result ? ` — ${esc(l.result)}` : ''}</li>`;
    }).join('')}</ul>`;
  }

  function chainsHtml(chains) {
    if (!Array.isArray(chains) || !chains.length) return '';
    return chains.map(c => `
      <div class="dossier-chain">
        <div class="dossier-chain-head">
          <span class="dossier-chain-name">${esc(c.name || 'Exploit chain')}</span>
          ${c.combined_severity ? `<span class="badge badge-${esc(c.combined_severity)}">${esc(c.combined_severity)}</span>` : ''}
        </div>
        ${c.terminal_impact ? `<div class="dossier-text">${esc(c.terminal_impact)}</div>` : ''}
        <div class="tm-mermaid-wrap">${c.svg || `<pre class="mermaid">${esc(c.mermaid || '')}</pre>`}</div>
      </div>`).join('');
  }

  // ── main render ──────────────────────────────────────────────────────────────
  function render(data) {
    const f = data.finding || {};
    const sev = (f.severity || 'info').toLowerCase();
    const vs  = f.verification_status || 'unverified';

    document.title = `${f.title ? f.title.slice(0, 60) : 'Finding'} · Pentest Dashboard`;
    if (statusEl) {
      statusEl.innerHTML = `<span class="dot"></span>Live · refreshes every 5 s`
        + (data.archived ? ' · <strong style="color:#faad14">archived</strong>' : '');
    }

    const badges = [
      `<span class="badge badge-${esc(sev)}">${esc(sev)}</span>`,
      `<span class="vbadge vbadge-${esc(vs)}">${esc(VS_LABELS[vs] || vs)}</span>`,
      f.adjudication?.rationale ? '<span class="triaged-badge">⚖ Triaged</span>' : '',
      f.status === 'false_positive' ? '<span class="badge" style="background:rgba(107,104,144,.2);color:var(--text-dim)">false positive</span>' : '',
    ].join('');

    const metaLine = [
      f.target ? `<span class="target">${esc(f.target)}</span>` : '',
      f.tool_used ? `<span class="tool">${esc(f.tool_used)}</span>` : '',
      f.cve ? `<span class="cve">CVE: ${esc(f.cve)}</span>` : '',
      f.timestamp ? `<span class="finding-ts-meta">first seen ${esc(fmtTime(f.timestamp))}</span>` : '',
    ].filter(Boolean).join('');

    // ── main (narrative) column ──
    const impact = f.business_impact
      ? `<div class="finding-impact">
           <span class="finding-impact-icon">⚠</span>
           <span class="finding-impact-label">Business impact&nbsp;&nbsp;</span>
           <span class="finding-impact-text">${esc(f.business_impact)}</span>
         </div>`
      : '';
    const desc = f.description ? `<div class="dossier-text">${esc(f.description)}</div>` : '';
    const evidence = f.evidence
      ? `<div class="dossier-copy-row">${copyBtn(f.evidence, '⧉ Copy evidence')}</div><pre class="evidence dossier-evidence">${esc(f.evidence)}</pre>`
      : '';
    const repro = f.reproduction?.command
      ? `<div class="dossier-copy-row">${copyBtn(f.reproduction.command, '▶ Copy command')}</div><pre class="evidence dossier-evidence">${esc(f.reproduction.command)}</pre>`
      : '';
    const poc = Array.isArray(f.poc_files) && f.poc_files.length
      ? `<ul class="poc-list">${f.poc_files.map(p => `<li><code>${esc(typeof p === 'string' ? p : (p.path || JSON.stringify(p)))}</code></li>`).join('')}</ul>`
      : '';

    const mainCol = `<div class="dossier-main">
      ${impact}
      ${section('Description', desc)}
      ${section('Data flow', traceHtml(f.trace))}
      ${section('Evidence', evidence)}
      ${section('Reproduction', repro)}
      ${section('Remediation', remediationHtml(f.remediation))}
      ${section('Escalation leads', escalationHtml(f.escalation_leads))}
      ${section('Exploit chain', chainsHtml(data.chains))}
    </div>`;

    // ── metadata rail ──
    const railRows = [
      railRow('Severity', `<span class="drail-sev drail-sev-${esc(sev)}">${esc(sev)}</span>`),
      railRow('Verification', `<span class="vbadge vbadge-${esc(vs)}">${esc(VS_LABELS[vs] || vs)}</span>`),
      railRow('Target', f.target ? `<span class="mono-wrap">${esc(f.target)}</span>` : ''),
      railRow('Tool', f.tool_used ? esc(f.tool_used) : ''),
      railRow('CVE', f.cve ? esc(f.cve) : ''),
      railRow('Status', f.status ? esc(f.status) : ''),
      railRow('First seen', f.timestamp ? esc(fmtTime(f.timestamp)) : ''),
      railRow('Finding ID', `<span class="mono-wrap">${esc(f.id || '')}</span> ${copyBtn(f.id || '', 'copy')}`),
    ].join('');

    const railCol = `<aside class="dossier-rail">
      <div class="dossier-rail-card">
        <div class="drail-grid">${railRows}</div>
      </div>
      ${adjudicationHtml(f.adjudication)}
      ${poc ? `<div class="dossier-rail-card"><div class="drail-heading">PoC files</div>${poc}</div>` : ''}
    </aside>`;

    root.innerHTML = `
      <div class="dossier-masthead dossier-sev-${esc(sev)}">
        <div class="dossier-badges">${badges}</div>
        <h1 class="dossier-title">${esc(f.title || 'Untitled finding')}</h1>
        <div class="dossier-meta">${metaLine}</div>
      </div>
      <div class="dossier-grid">
        ${mainCol}
        ${railCol}
      </div>`;
  }

  function renderMissing() {
    if (statusEl) statusEl.innerHTML = '<span class="dot" style="background:#f85149;box-shadow:0 0 6px #f85149"></span>Not found';
    root.innerHTML = `<div class="empty-placeholder">This finding was not found — it may have been cleared or archived.
      <div style="margin-top:1rem"><a class="detail-link" href="/"
        onclick="if (window.history.length > 1) { window.history.back(); return false; }">&#8592; Back to all findings</a></div></div>`;
    document.title = 'Finding not found · Pentest Dashboard';
  }

  async function poll() {
    if (!fid) { renderMissing(); return; }
    try {
      const r = await fetch('/api/findings/' + encodeURIComponent(fid) + '?_=' + Date.now());
      if (r.status === 404) { renderMissing(); return; }
      if (!r.ok) throw new Error('bad');
      const data = await r.json();
      const key = JSON.stringify(data);
      if (key === _lastKey) return;      // nothing changed — skip re-render
      _lastKey = key;
      render(data);
    } catch (e) {
      if (statusEl && !root.innerHTML) statusEl.textContent = 'Waiting for the dashboard API…';
    }
  }

  // Copy-button delegation.
  document.addEventListener('click', (ev) => {
    const btn = ev.target.closest('.dossier-copy');
    if (!btn) return;
    let text = '';
    try { text = decodeURIComponent(escape(atob(btn.getAttribute('data-copy') || ''))); } catch (_) {}
    navigator.clipboard.writeText(text).then(() => {
      const orig = btn.textContent;
      btn.classList.add('copied');
      btn.textContent = 'Copied!';
      setTimeout(() => { btn.classList.remove('copied'); btn.textContent = orig; }, 1600);
    }).catch(() => {});
  });

  poll();
  setInterval(poll, POLL_MS);
})();
