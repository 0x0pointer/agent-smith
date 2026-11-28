  const _FINDINGS_CACHE_KEY = 'smith_findings_cache';

  async function pollFindings() {
    // On (re)load — e.g. returning from a /finding/<id> detail page — paint the
    // last findings from sessionStorage IMMEDIATELY so the list isn't blank for a
    // whole poll cycle (~5s) while the fetch below is in flight. The live fetch
    // refreshes it (and the NEW badges) a moment later.
    if (!(allData.findings || []).length) {
      try {
        const cached = sessionStorage.getItem(_FINDINGS_CACHE_KEY);
        if (cached) { allData = JSON.parse(cached); renderFindings(); }
      } catch { /* ignore malformed/absent cache */ }
    }
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
      try { sessionStorage.setItem(_FINDINGS_CACHE_KEY, JSON.stringify(data)); } catch { /* quota */ }
      renderFindings();
    } catch {
      document.getElementById('status').innerHTML =
        '<span class="dot" style="background:var(--danger)"></span>Waiting for data…';
    }
  }

  // Returning via the browser's back/forward cache doesn't re-run init, so the
  // next interval poll can be up to 5s away — refresh findings right on restore.
  window.addEventListener('pageshow', (e) => { if (e.persisted) pollFindings(); });

  // The "last updated Ns ago" freshness line. Lives in the shared #status header
  // (above every tab panel), so it must tick on ALL tabs — not just findings.
  // Skipped while an HIR is active so it doesn't overwrite the "Scan paused" banner.
  function updateFreshness() {
    if (_hirActive) return;
    const el = document.getElementById('status');
    if (!el) return;
    const target = allData.meta?.target || '';
    const ago = lastOk ? Math.round((Date.now() - lastOk) / 1000) + 's ago' : '';
    el.innerHTML =
      `<span class="dot"></span>Live · refreshes every 5 s · last updated ${ago}` +
      (target ? ` · <strong style="color:var(--text)">${target}</strong>` : '');
  }

  function renderFindings() {
    const findings = allData.findings || [];
    updateFreshness();
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
    unverified:              '· NOT YET RE-TESTED',
  };
  // Plain-language meaning of each label — shown in the legend and on hover.
  const VS_HELP = {
    confirmed_dynamic:       'Smith exploited it against the running target and kept the evidence.',
    new_dynamic_finding:     'Found while testing live; it was not predicted by any earlier analysis.',
    code_confirmed:          'Proven by reading the source code, not by a live request.',
    not_accessible_external: 'Real, but only reachable from inside the network.',
    not_confirmed:           'A re-test could not reproduce it. Treat as a lead, not a fact.',
    unverified:              'Reported with evidence, but not yet independently re-tested. Run triage after the scan to review these.',
  };
  // Counts as "confirmed" in the summary line.
  const VS_CONFIRMED = new Set(['confirmed_dynamic', 'new_dynamic_finding', 'code_confirmed']);
  window.VS_LABELS = VS_LABELS; window.VS_HELP = VS_HELP; window.VS_CONFIRMED = VS_CONFIRMED;

  function renderStats(findings) {
    const c = { all: findings.length, critical:0, high:0, medium:0, low:0, info:0 };
    findings.forEach(f => { if (c[f.severity] !== undefined) c[f.severity]++; });

    // Overview: a slim severity-distribution bar — the risk profile at a glance.
    const ov = document.getElementById('findings-overview');
    if (ov) {
      const total = c.all || 0;
      const segs = ['critical','high','medium','low','info']
        .filter(s => c[s] > 0)
        .map(s => `<span class="sevbar-seg sevbar-${s}" style="flex:${c[s]}" title="${s}: ${c[s]}"></span>`)
        .join('');
      ov.innerHTML = total
        ? `<div class="fx-overview">
             <div class="sevbar">${segs}</div>
           </div>`
        : '';
    }

    document.getElementById('stats').innerHTML =
      ['all','critical','high','medium','low','info'].map(s =>
        `<button type="button" class="stat stat-${s}${filter===s?' active':''}" aria-pressed="${filter===s}" onclick="setFilter('${s}')">
          ${s==='all'?'ALL':s.toUpperCase()} ${c[s]}
        </button>`
      ).join('');

    // Verification filter bar
    const vc = {};
    const vsKeys = Object.keys(VS_ORDER);
    vsKeys.forEach(k => { vc[k] = 0; });
    findings.forEach(f => { if (vc[f.verification_status] !== undefined) vc[f.verification_status]++; });
    document.getElementById('vstats').innerHTML =
      `<span class="vstat-label" title="How sure are we? See the legend below.">Verification</span>` +
      [['all', 'ALL ' + findings.length]].concat(vsKeys.filter(k => vc[k] > 0).map(k => [k, VS_LABELS[k] + ' ' + vc[k]])).map(([k, label]) =>
        `<button type="button" class="stat vstat-${k}${vfilter===k?' active':''}" aria-pressed="${vfilter===k}" title="${esc(VS_HELP[k] || '')}" onclick="setVFilter('${k}')">${label}</button>`
      ).join('');

    const has = findings.length > 0;
    for (const id of ['findings-toolbar', 'findings-legend']) {
      const el = document.getElementById(id); if (el) el.hidden = !has;
    }
    const vstatsEl = document.getElementById('vstats'); if (vstatsEl) vstatsEl.hidden = !has;
    const legend = document.getElementById('findings-legend-list');
    if (legend && !legend.childElementCount) {
      legend.innerHTML = vsKeys.map(k => `<div><dt><span class="vbadge vbadge-${k}">${VS_LABELS[k]}</span></dt><dd>${esc(VS_HELP[k])}</dd></div>`).join('');
    }
    renderFindingsSummary(findings);
  }

  const SEV_GROUPS = ['critical', 'high', 'medium', 'low', 'info'];
  const _SEV_IDX = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

  // The part of the target that identifies WHERE the problem is: the path, with
  // IDs and query strings folded so /users/12 and /users/97 group together.
  function findingEndpoint(f) {
    const raw = String(f.target || '').trim();
    if (!raw) return '(no endpoint recorded)';
    let path = raw;
    try { const u = new URL(raw); path = u.pathname || '/'; } catch (_) { path = raw.split('?')[0]; }
    try { path = decodeURIComponent(path); } catch (_) { /* keep the raw path */ }
    path = path.replace(/\{[^}]*\}/g, '{id}').replace(/\/\d+(?=\/|$)/g, '/{id}')
               .replace(/\/[0-9a-f]{8}-[0-9a-f-]{27,}(?=\/|$)/gi, '/{id}');
    return path.length > 1 ? path.replace(/\/$/, '') : path;
  }
  window.findingEndpoint = findingEndpoint;

  // Summary: how many findings there are, in total and per severity.
  function renderFindingsSummary(findings) {
    const box = document.getElementById('findings-summary');
    if (!box) return;
    if (!findings.length) { box.hidden = true; box.innerHTML = ''; return; }
    const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(f => { if (c[f.severity] !== undefined) c[f.severity]++; });
    // Each tile is also the severity filter (the old chip row repeated these numbers).
    const tile = (key, cls, n, label) => `<button type="button" class="fx-sum-item ${cls}${filter === key ? ' active' : ''}"
        aria-pressed="${filter === key}" onclick="setFilter('${key}')" title="Show ${key === 'all' ? 'all findings' : 'only ' + key + ' findings'}">
        <span class="fx-sum-num">${n}</span>
        <span class="fx-sum-label">${label}</span>
      </button>`;
    box.innerHTML = tile('all', 'fx-sum-total', findings.length, findings.length === 1 ? 'Finding' : 'Findings') +
      SEV_GROUPS.map(s => tile(s, 'fx-sum-' + s + (c[s] ? '' : ' is-zero'), c[s], s)).join('');
    box.hidden = false;
  }

  // Grouping + ordering are the operator's choice and persist across reloads.
  const _FX_VIEW_KEY = 'smith_findings_view';
  let _fxView = { group: 'severity', sort: 'confirmed' };
  try {
    const saved = JSON.parse(localStorage.getItem(_FX_VIEW_KEY) || '{}') || {};
    if (saved.group === 'endpoint' || saved.group === 'severity') _fxView.group = saved.group;
    if (['confirmed', 'severity', 'newest'].includes(saved.sort)) _fxView.sort = saved.sort;
  } catch (_) { /* defaults */ }
  function setFindingsView(key, value) {
    _fxView[key] = value;
    const ctl = document.getElementById(key === 'group' ? 'findings-group' : 'findings-sort');
    if (ctl && ctl.value !== value) ctl.value = value;
    try { localStorage.setItem(_FX_VIEW_KEY, JSON.stringify(_fxView)); } catch (_) { /* ignore */ }
    renderFindingsTable(allData.findings || []);
  }
  window.setFindingsView = setFindingsView;
  (function _wireFindingsView() {
    const g = document.getElementById('findings-group'), o = document.getElementById('findings-sort');
    if (g) { g.value = _fxView.group; g.addEventListener('change', () => setFindingsView('group', g.value)); }
    if (o) { o.value = _fxView.sort;  o.addEventListener('change', () => setFindingsView('sort', o.value)); }
  })();

  function _fxCompare(a, b) {
    const sev = (_SEV_IDX[a.severity] ?? 9) - (_SEV_IDX[b.severity] ?? 9);
    const ver = (VS_ORDER[a.verification_status] ?? 9) - (VS_ORDER[b.verification_status] ?? 9);
    const age = new Date(b.timestamp) - new Date(a.timestamp);
    if (_fxView.sort === 'newest')   return age || sev;
    if (_fxView.sort === 'severity') return sev || ver || age;
    return ver || sev || age;                      // confirmed first
  }

  function renderFindingsTable(findings) {
    let filtered = filter === 'all' ? findings : findings.filter(f => f.severity === filter);
    if (vfilter !== 'all') filtered = filtered.filter(f => f.verification_status === vfilter);

    const wrap = document.getElementById('findings-wrap');
    if (!filtered.length) {
      const filtering = filter !== 'all' || vfilter !== 'all';
      wrap.innerHTML = filtering
        ? '<div class="empty-placeholder">No findings match these filters. <button type="button" class="runs-clear-btn" onclick="setFilter(\'all\');setVFilter(\'all\')">Show all</button></div>'
        : '<div class="empty-placeholder">No findings yet. They appear here as soon as Smith confirms one.</div>';
      return;
    }

    if (_fxView.group === 'endpoint') {
      // One section per endpoint: ten criticals on one route read as one problem.
      const groups = {};
      filtered.forEach(f => { const e = findingEndpoint(f); (groups[e] = groups[e] || []).push(f); });
      const worstOf = items => Math.min(...items.map(f => _SEV_IDX[f.severity] ?? 9));
      const names = Object.keys(groups).sort((a, b) =>
        worstOf(groups[a]) - worstOf(groups[b]) || groups[b].length - groups[a].length || a.localeCompare(b));
      wrap.innerHTML = names.map(name => {
        const items = groups[name].sort(_fxCompare);
        const sev = SEV_GROUPS[worstOf(items)] || 'info';
        const mix = SEV_GROUPS.filter(s => items.some(f => f.severity === s))
          .map(s => `${items.filter(f => f.severity === s).length} ${s}`).join(' · ');
        return `<section class="fx-section">
          <div class="fx-section-head fx-head-${sev} fx-head-endpoint">
            <span class="fx-head-dot"></span>
            <span class="fx-head-name">${esc(name)}</span>
            <span class="fx-head-count">${items.length}</span>
            <span class="fx-head-mix">${esc(mix)}</span>
          </div>
          <div class="fx-grid">${items.map(tileHTML).join('')}</div>
        </section>`;
      }).join('');
      return;
    }

    // Default: group by severity, most severe first.
    const groups = {};
    filtered.forEach(f => { (groups[f.severity] = groups[f.severity] || []).push(f); });
    const html = SEV_GROUPS.filter(s => groups[s] && groups[s].length).map(s => {
      const items = groups[s].sort(_fxCompare);
      return `<section class="fx-section">
        <div class="fx-section-head fx-head-${s}">
          <span class="fx-head-dot"></span>
          <span class="fx-head-name">${s}</span>
          <span class="fx-head-count">${items.length}</span>
        </div>
        <div class="fx-grid">${items.map(tileHTML).join('')}</div>
      </section>`;
    }).join('');
    wrap.innerHTML = html;
  }

  // Compact finding tile — the whole tile is a same-tab link to the dossier.
  function tileHTML(f) {
    const isNew = freshIds.has(f.id);
    const vs    = f.verification_status || 'unverified';
    const ts    = new Date(f.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const newBadge = isNew ? '<span class="new-badge">NEW</span>' : '';
    const fpBadge  = f.status === 'false_positive'
      ? '<span class="badge" style="background:rgba(107,104,144,.2);color:var(--text-dim)">FP</span>' : '';
    const line = f.business_impact || f.description || '';
    const foot = [
      f.target    ? `<span class="meta-chip chip-target">${esc(f.target)}</span>` : '',
      f.tool_used ? `<span class="meta-chip chip-tool">${esc(f.tool_used)}</span>` : '',
      f.cve       ? `<span class="meta-chip chip-cve">${esc(f.cve)}</span>` : '',
      f.adjudication?.rationale ? '<span class="fx-triaged" title="Senior-reviewed">⚖</span>' : '',
    ].filter(Boolean).join('');
    return `<a class="fx-tile sev-${f.severity}" href="/finding/${encodeURIComponent(f.id)}">
      <div class="fx-tile-top">
        <span class="badge badge-${f.severity}"><span class="sev-dot"></span>${f.severity}</span>${fpBadge}
        <span class="fx-grow"></span>
        <span class="vbadge vbadge-${vs}" title="${esc(VS_HELP[vs] || vs.replace(/_/g,' '))}">${VS_LABELS[vs] || vs}</span>
      </div>
      <div class="fx-tile-title">${esc(f.title)}${newBadge}</div>
      ${line ? `<div class="fx-tile-line">${esc(line)}</div>` : ''}
      <div class="fx-tile-foot">${foot}<span class="fx-grow"></span><span class="fx-time">${ts}</span></div>
    </a>`;
  }

  const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

  function _adjudicationBlock(adj) {
    if (!adj?.rationale) return '';
    const repro     = adj.reproducible === true || adj.reproducible === 'true';
    const reproHTML = repro
      ? '<span style="color:var(--green)">✓ Reproducible</span>'
      : '<span style="color:var(--danger)">✗ Not reproducible</span>';
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

  // Open a finding's detail page in the SAME tab. Bound to the whole card;
  // bail out when the click landed on an interactive child (button / link) so
  // those keep their own behaviour and we don't navigate twice.
  function openFinding(ev, id) {
    if (ev && ev.target && ev.target.closest('button, a')) return;
    window.location.assign('/finding/' + encodeURIComponent(id));
  }

  function cardHTML(f, openIds) {
    const isNew    = freshIds.has(f.id);
    const ts       = new Date(f.timestamp).toLocaleTimeString();
    const newBadge = isNew ? '<span class="new-badge">NEW</span>' : '';
    const statusBadge = f.status === 'false_positive'
      ? `<span class="badge" style="background:rgba(107,104,144,.2);color:var(--text-dim);margin-left:.4rem">false positive</span>`
      : '';
    const triagedBadge = f.adjudication?.rationale
      ? `<span class="triaged-badge" title="Senior-reviewed: ${esc(f.adjudication.rationale)}">⚖ Triaged</span>`
      : '';
    const vs = f.verification_status || 'unverified';
    const vsBadge = `<span class="vbadge vbadge-${vs}" title="${esc(VS_HELP[vs] || vs.replace(/_/g,' '))}">${VS_LABELS[vs] || vs}</span>`;
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
    const detailHref = '/finding/' + encodeURIComponent(f.id);
    const metaChips = [
      f.target    ? `<span class="meta-chip chip-target">${esc(f.target)}</span>` : '',
      f.tool_used ? `<span class="meta-chip chip-tool">${esc(f.tool_used)}</span>` : '',
      f.cve       ? `<span class="meta-chip chip-cve">${esc(f.cve)}</span>` : '',
    ].filter(Boolean).join('');
    // One body line, scannable: lead with the "so what" (business impact) when we
    // have it, else the technical description. Both live in full on the dossier.
    const body = f.business_impact
      ? `<div class="fc-body fc-body-impact"><span class="fc-impact-tag">&#9888; Impact</span>${esc(f.business_impact)}</div>`
      : (f.description ? `<div class="fc-body">${esc(f.description)}</div>` : '');
    return `<div class="finding-card sev-${f.severity}" onclick="openFinding(event,'${esc(f.id)}')" title="Open finding detail">
      <div class="fc-top">
        <div class="fc-top-left">
          <span class="badge badge-${f.severity}"><span class="sev-dot"></span>${f.severity}</span>${statusBadge}
        </div>
        <div class="fc-top-right">
          ${triagedBadge}${vsBadge}
          <span class="finding-ts-meta">${ts}</span>
          <span class="finding-open-cue" aria-hidden="true">&#8594;</span>
        </div>
      </div>
      <a class="finding-title-link" href="${detailHref}">
        <h3 class="finding-title">${esc(f.title)}${newBadge}</h3>
      </a>
      ${metaChips ? `<div class="finding-meta-row">${metaChips}</div>` : ''}
      ${body}
      <div class="finding-footer">
        ${replayBtn}${ghBtn}
        <a class="detail-link" href="${detailHref}">View detail &#8594;</a>
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
    const breaking = r.breaking_change ? '<span style="color:var(--danger);margin-left:.5rem">&#9888; Breaking change</span>' : '';
    const diffBlock = r.diff ? `<div style="margin-top:.5rem"><strong>Diff:</strong><pre>${esc(r.diff)}</pre></div>` : '';
    const beforeAfter = (r.before && r.after) ? `
      <div style="margin-top:.5rem"><strong>Before:</strong><pre style="color:var(--danger)">${esc(r.before)}</pre></div>
      <div><strong>After:</strong><pre style="color:var(--green)">${esc(r.after)}</pre></div>` : '';
    const refs = r.references?.length ? `<div style="margin-top:.5rem"><strong>References:</strong><ul>${r.references.map(u => '<li><a href="'+esc(u)+'" target="_blank" style="color:var(--purple)">'+esc(u)+'</a></li>').join('')}</ul></div>` : '';
    const verify = r.verification ? `<div style="margin-top:.5rem"><strong>Verification:</strong> ${esc(r.verification)}</div>` : '';
    const file = r.file ? `<div style="margin-top:.3rem;color:var(--text-muted)">${esc(r.file)}${r.line ? ':'+r.line : ''} (${esc(r.language||'')})</div>` : '';
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
  async function clearFindings() {
    const ok = await confirmAction({
      title: 'Clear all data for this scan?',
      body: 'This wipes the findings, coverage, skills, logs and QA state of ' + scanDisplayName() +
            ', and kills any active tunnels. It cannot be undone.',
      confirmLabel: 'Clear all data',
    });
    if (!ok) return;
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
        try { sessionStorage.removeItem(_FINDINGS_CACHE_KEY); } catch { /* ignore */ }

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
          '<div class="empty-placeholder">No findings yet. They appear here as soon as Smith confirms one.</div>';

        // ── Topology tab ──────────────────────────────────────────────────
        document.getElementById('diagrams-wrap').innerHTML =
          '<div class="empty-placeholder">No diagrams yet. Smith draws the attack surface as it learns it. <button type="button" class="empty-action" onclick="askSmith(\'Draw a diagram of what you have mapped so far\')">Ask for one now</button></div>';

        // ── Components tab ────────────────────────────────────────────────
        document.getElementById('components-wrap').innerHTML = '';

        // ── Coverage tab ──────────────────────────────────────────────────
        document.getElementById('coverage-summary').innerHTML = '';
        document.getElementById('coverage-wrap').innerHTML =
          '<div class="empty-placeholder">Nothing mapped yet. The matrix fills in once Smith has discovered the first endpoints, usually within a few minutes.</div>';

        // ── Skills tab ────────────────────────────────────────────────────
        document.getElementById('skills-summary').innerHTML = '';
        document.getElementById('skills-wrap').innerHTML =
          '<div class="empty-placeholder">No skills used yet. Each testing playbook Smith runs shows up here.</div>';

        // ── Activity tab ──────────────────────────────────────────────────
        _qaData = null;
        _steeringData = null;
        _sessionData = null;
        if (typeof resetActivityFeed === 'function') resetActivityFeed();
        if (typeof resetToolResults === 'function') resetToolResults();

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