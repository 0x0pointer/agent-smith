// World Model tab — renders the Phase-2 knowledge graph: graph-derived kill-chain
// proposals, finding/target rankings, and a dependency-free SVG of the world model
// (hosts · endpoints · params · findings · principals). No CDN libs (CSP-safe).

let _wmData = null;

function wmEsc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

async function pollWorldModel() {
  try {
    const r = await fetch(`/api/graph?_=${Date.now()}`);
    if (!r.ok) return;
    _wmData = await r.json();
  } catch (e) { return; }
  wmRenderStats();
  wmRenderChains();
  wmRenderRankings();
  wmRenderGraph();
}

function wmRenderStats() {
  const el = document.getElementById('wm-stats');
  if (!el) return;
  const s = (_wmData && _wmData.stats) || { nodes: 0, edges: 0, by_kind: {} };
  const chips = Object.entries(s.by_kind || {})
    .sort((a, b) => b[1] - a[1])
    .map(([k, n]) => `<span class="wm-stat-chip wm-k-${wmEsc(k)}">${wmEsc(k)} ${n}</span>`)
    .join('');
  el.innerHTML =
    `<span class="wm-stat-total">${s.nodes} nodes · ${s.edges} edges</span>${chips}` +
    ((_wmData && _wmData.error) ? `<span class="wm-err">graph unavailable</span>` : '');
}

function wmRenderChains() {
  const el = document.getElementById('wm-chains');
  if (!el) return;
  const chains = (_wmData && _wmData.candidate_chains) || [];
  if (!chains.length) {
    el.innerHTML = `<div class="wm-empty">No chains proposable yet — need ≥2 related findings, an escalation lead, or a credential leak.</div>`;
    return;
  }
  el.innerHTML = chains.map(c => {
    const steps = (c.steps || []).map((s, i) =>
      `<span class="wm-step">${wmEsc(s)}</span>${i < c.steps.length - 1 ? '<span class="wm-arrow">→</span>' : ''}`
    ).join('');
    return `<div class="wm-chain">
      <span class="wm-sev wm-sev-${wmEsc(c.combined_severity || 'medium')}">${wmEsc(c.combined_severity || '?')}</span>
      <div class="wm-chain-body"><div class="wm-steps">${steps}</div>
      <div class="wm-terminal">terminal: ${wmEsc(c.terminal || '')}</div>
      <div class="wm-rationale">${wmEsc(c.rationale || '')}</div></div></div>`;
  }).join('');
}

function wmRenderRankings() {
  const fEl = document.getElementById('wm-findings');
  const tEl = document.getElementById('wm-targets');
  if (fEl) {
    const fs = (_wmData && _wmData.ranked_findings) || [];
    fEl.innerHTML = fs.length ? fs.map(f =>
      `<div class="wm-row"><span class="wm-sev wm-sev-${wmEsc(f.severity || 'info')}">${wmEsc(f.severity || '?')}</span>
       <span class="wm-row-label">${wmEsc(f.label)}</span><span class="wm-why">${wmEsc(f.why || '')}</span></div>`
    ).join('') : `<div class="wm-empty">No findings yet.</div>`;
  }
  if (tEl) {
    const ts = (_wmData && _wmData.next_targets) || [];
    tEl.innerHTML = ts.length ? ts.map(t =>
      `<div class="wm-row"><span class="wm-pending">${t.pending_cells}</span>
       <span class="wm-row-label">${wmEsc(t.path || t.endpoint)}</span></div>`
    ).join('') : `<div class="wm-empty">No untested endpoints.</div>`;
  }
}

// ── SVG world-model graph (columnar, dependency-free) ───────────────────────
const _WM_COLS = [
  { kinds: ['host', 'tech'], title: 'host / tech' },
  { kinds: ['endpoint'], title: 'endpoints' },
  { kinds: ['param'], title: 'params' },
  { kinds: ['finding'], title: 'findings' },
  { kinds: ['credential', 'token'], title: 'principals' },
];
const _WM_CAP = 18;

function wmRenderGraph() {
  const el = document.getElementById('wm-graph');
  if (!el) return;
  const nodes = (_wmData && _wmData.nodes) || [];
  const edges = (_wmData && _wmData.edges) || [];
  if (!nodes.length) { el.innerHTML = `<div class="wm-empty">World model is empty — it fills in as the scan discovers surface and files findings.</div>`; return; }

  const colOf = k => _WM_COLS.findIndex(c => c.kinds.includes(k));
  const byCol = _WM_COLS.map(() => []);
  for (const n of nodes) { const c = colOf(n.kind); if (c >= 0) byCol[c].push(n); }

  const COLW = 210, ROWH = 26, PADX = 12, PADY = 34, BOXW = 180, BOXH = 20;
  const pos = {};                 // node id -> {x, y}
  const rows = Math.max(1, ...byCol.map(c => Math.min(c.length, _WM_CAP)));
  const height = PADY + rows * ROWH + 20;
  const width = _WM_COLS.length * COLW;

  let svg = `<svg viewBox="0 0 ${width} ${height}" width="100%" preserveAspectRatio="xMinYMin meet" class="wm-svg">`;
  // column headers
  _WM_COLS.forEach((c, i) => {
    svg += `<text x="${i * COLW + PADX}" y="18" class="wm-col-title">${wmEsc(c.title)}</text>`;
  });
  // place + draw nodes
  byCol.forEach((list, ci) => {
    list.slice(0, _WM_CAP).forEach((n, ri) => {
      const x = ci * COLW + PADX, y = PADY + ri * ROWH;
      pos[n.id] = { x: x + BOXW, y: y + BOXH / 2, xl: x, yc: y + BOXH / 2 };
    });
  });
  // edges first (under nodes) — only between placed nodes, skip self-loops
  edges.forEach(e => {
    const a = pos[e.src], b = pos[e.dst];
    if (!a || !b || e.src === e.dst) return;
    svg += `<line x1="${a.x}" y1="${a.yc}" x2="${b.xl}" y2="${b.yc}" class="wm-edge wm-edge-${wmEsc(e.kind)}"/>`;
  });
  // nodes
  byCol.forEach((list, ci) => {
    list.slice(0, _WM_CAP).forEach((n, ri) => {
      const x = ci * COLW + PADX, y = PADY + ri * ROWH;
      const cls = n.kind === 'finding' ? `wm-node wm-node-finding wm-sevfill-${wmEsc(n.severity || 'info')}` : `wm-node wm-node-${wmEsc(n.kind)}`;
      const label = (n.label || n.id).slice(0, 26);
      svg += `<g class="${cls}"><rect x="${x}" y="${y}" width="${BOXW}" height="${BOXH}" rx="3"/>` +
        `<text x="${x + 6}" y="${y + 14}"><title>${wmEsc(n.label || n.id)}</title>${wmEsc(label)}</text></g>`;
    });
    if (list.length > _WM_CAP) {
      const x = ci * COLW + PADX, y = PADY + _WM_CAP * ROWH;
      svg += `<text x="${x + 6}" y="${y + 12}" class="wm-more">+${list.length - _WM_CAP} more</text>`;
    }
  });
  svg += `</svg>`;
  el.innerHTML = svg;
}
