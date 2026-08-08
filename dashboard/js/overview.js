// Overview tab — the at-a-glance landing view. Summary-first (inverted pyramid):
// KPI tiles + "needs attention" + proposed chains + top findings, all drilling
// into the detail tabs. Reuses existing endpoints; no new backend.

function ovEsc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

async function pollOverview() {
  const [findings, coverage, session, graph] = await Promise.all([
    fetch(`/api/findings?_=${Date.now()}`).then(r => r.ok ? r.json() : {}).catch(() => ({})),
    fetch(`/api/coverage?_=${Date.now()}`).then(r => r.ok ? r.json() : {}).catch(() => ({})),
    fetch(`/api/session?_=${Date.now()}`).then(r => r.ok ? r.json() : {}).catch(() => ({})),
    fetch(`/api/graph?_=${Date.now()}`).then(r => r.ok ? r.json() : {}).catch(() => ({})),
  ]);
  ovRenderKpis(findings.findings || [], coverage.meta || {}, session);
  ovRenderAttention(session, findings.findings || []);
  ovRenderChains(graph.candidate_chains || []);
  ovRenderTopFindings(findings.findings || []);
  ovRenderNext(graph);
}

function _sevCounts(findings) {
  const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach(f => { if (c[f.severity] !== undefined) c[f.severity]++; });
  return c;
}

function ovRenderKpis(findings, covMeta, session) {
  const el = document.getElementById('ov-kpis'); if (!el) return;
  const c = _sevCounts(findings);
  const total = covMeta.total_cells || 0, tested = covMeta.tested || 0;
  const vuln = covMeta.vulnerable || 0;
  const pct = total ? Math.round((tested / total) * 100) : 0;
  const status = session.status || '—';
  const tile = (label, val, cls) =>
    `<div class="ov-kpi ${cls || ''}"><div class="ov-kpi-val">${val}</div><div class="ov-kpi-label">${label}</div></div>`;
  el.innerHTML =
    tile('Critical', c.critical, c.critical ? 'ov-kpi-crit' : '') +
    tile('High', c.high, c.high ? 'ov-kpi-high' : '') +
    tile('Medium', c.medium) +
    tile('Vulnerable cells', vuln, vuln ? 'ov-kpi-crit' : '') +
    `<div class="ov-kpi"><div class="ov-kpi-val">${pct}%<span class="ov-kpi-frac"> ${tested}/${total}</span></div>
       <div class="ov-kpi-label">Coverage</div>
       <div class="ov-kpi-bar"><div class="ov-kpi-bar-fill" style="width:${pct}%"></div></div></div>` +
    tile('Scan', ovEsc(status), 'ov-kpi-status');
}

function ovRenderAttention(session, findings) {
  const el = document.getElementById('ov-attention'); if (!el) return;
  const items = [];
  const gates = session.pending_gates || [];
  gates.forEach(g => items.push({ icon: '⛔', text: `Gate: ${ovEsc(g.id || g)} — ${ovEsc((g.required_skills || []).join(', '))}`, cls: 'ov-att-gate' }));
  if (session.intervention_required) items.push({ icon: '⏸', text: 'Human intervention required — see the banner above', cls: 'ov-att-hir' });
  const leads = findings.filter(f => (f.escalation_leads || []).some(l => l.status === 'pending')).length;
  if (leads) items.push({ icon: '↗', text: `${leads} finding(s) with unproven escalation leads`, cls: 'ov-att-lead' });
  el.innerHTML = items.length
    ? items.map(i => `<div class="ov-att ${i.cls}"><span class="ov-att-icon">${i.icon}</span>${i.text}</div>`).join('')
    : `<div class="ov-empty">Nothing needs action right now.</div>`;
}

function ovRenderChains(chains) {
  const el = document.getElementById('ov-chains'); if (!el) return;
  el.innerHTML = chains.length
    ? chains.slice(0, 4).map(c =>
        `<div class="ov-chain"><span class="wm-sev wm-sev-${ovEsc(c.combined_severity || 'medium')}">${ovEsc(c.combined_severity || '?')}</span>
         <span class="ov-chain-steps">${(c.steps || []).map(ovEsc).join(' <span class="wm-arrow">→</span> ')}</span></div>`
      ).join('')
    : `<div class="ov-empty">No chains proposed yet.</div>`;
}

function ovRenderTopFindings(findings) {
  const el = document.getElementById('ov-findings'); if (!el) return;
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const top = [...findings].sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5)).slice(0, 6);
  el.innerHTML = top.length
    ? top.map(f => `<div class="ov-row" onclick="switchTab('findings')">
        <span class="wm-sev wm-sev-${ovEsc(f.severity || 'info')}">${ovEsc(f.severity || '?')}</span>
        <span class="ov-row-label">${ovEsc(f.title || '')}</span></div>`).join('')
    : `<div class="ov-empty">No findings yet.</div>`;
}

function ovRenderNext(graph) {
  const el = document.getElementById('ov-next'); if (!el) return;
  const rf = (graph.ranked_findings || []).slice(0, 3);
  const nt = (graph.next_targets || []).slice(0, 4);
  let html = rf.map(f => `<div class="ov-row" onclick="switchTab('world-model')">
      <span class="wm-sev wm-sev-${ovEsc(f.severity || 'info')}">${ovEsc(f.severity || '?')}</span>
      <span class="ov-row-label">${ovEsc(f.label)}</span></div>`).join('');
  html += nt.map(t => `<div class="ov-row" onclick="switchTab('world-model')">
      <span class="ov-pending">${t.pending_cells}</span>
      <span class="ov-row-label">${ovEsc(t.path || t.endpoint)}</span></div>`).join('');
  el.innerHTML = html || `<div class="ov-empty">Nothing ranked yet.</div>`;
}
