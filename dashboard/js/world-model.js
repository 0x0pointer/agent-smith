// World Model tab — an interactive Labeled-Property-Graph (LPG) of the knowledge
// graph (Neo4j-style: Nodes = entities, Relationships = typed edges, Properties =
// key/value attrs), plus graph-derived kill-chains and finding/target rankings.
// Rendered with cytoscape.js (force layout + a graph stylesheet); degrades to a
// dependency-free columnar SVG if the CDN library is unavailable.

let _wmData = null;
let _wmCy = null;               // cytoscape instance
let _wmSig = null;              // element-set signature — rebuild only on change
let _wmHiddenKinds = new Set(); // legend toggles
let _wmBridges = false;         // "◆ Bridges" highlight mode
let _wmLayout = 'tree';         // 'tree' | 'radial' | 'force'

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
    el.innerHTML = `<div class="wm-empty">No chains proposable yet — need ≥2 related findings, an escalation lead, a credential leak, or a capability bridge.</div>`;
    return;
  }
  el.innerHTML = chains.map(c => {
    const steps = (c.steps || []).map((s, i) =>
      `<span class="wm-step">${wmEsc(s)}</span>${i < c.steps.length - 1 ? '<span class="wm-arrow">→</span>' : ''}`
    ).join('');
    const bridge = c.kind === 'primitive_unblock' ? `<span class="wm-bridge-tag" title="Compositional capability bridge">◆ ${wmEsc(c.primitive || 'bridge')}</span>` : '';
    return `<div class="wm-chain">
      <span class="wm-sev wm-sev-${wmEsc(c.combined_severity || 'medium')}">${wmEsc(c.combined_severity || '?')}</span>
      <div class="wm-chain-body"><div class="wm-steps">${steps}${bridge}</div>
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

// ── Interactive LPG (cytoscape) ──────────────────────────────────────────────
const WM_KIND_COLOR = {
  host: '#a371f7', endpoint: '#4f8cff', param: '#6b7681', credential: '#e3b341',
  token: '#d29922', tech: '#3fb950', primitive: '#ff5ccd', finding: '#7b78ff',
};
const WM_SEV_COLOR = {
  critical: '#f85149', high: '#fa8c16', medium: '#d29922', low: '#5bf29b', info: '#7b78ff',
};
const WM_EDGE = {
  // Structural skeleton (faint) — target -> component -> param.
  hosts:        { color: '#30363d', style: 'solid',  width: 1 },
  has_param:    { color: '#30363d', style: 'solid',  width: 1 },
  runs:         { color: '#30363d', style: 'solid',  width: 1 },
  // Auth/token DATAFLOW (blue) — how a session/JWT moves between components.
  issues:       { color: '#4f8cff', style: 'solid',  width: 3 },
  grants:       { color: '#4f8cff', style: 'dashed', width: 2 },
  authenticates:{ color: '#4f8cff', style: 'dashed', width: 2 },
  // Exploit / escalation overlay (red/amber/green).
  provides:     { color: '#3fb950', style: 'solid',  width: 3 },
  requires:     { color: '#ff7b3d', style: 'dashed', width: 3 },
  leaks:        { color: '#e3b341', style: 'solid',  width: 2 },
  escalates_to: { color: '#f85149', style: 'solid',  width: 2 },
  found_on:     { color: '#3d444d', style: 'solid',  width: 1 },
  // Pivot / discovery (magenta) — a finding on host A reached/discovered host B (SSRF,
  // XXE/file-leak, lateral cred-reuse, config leak). This is the edge that LINKS two
  // otherwise-separate host circles.
  reaches:      { color: '#ff5ccd', style: 'solid',  width: 3 },
};
function wmEdgeStyle(k) { return WM_EDGE[k] || { color: '#30363d', style: 'solid', width: 1 }; }
function wmNodeColor(n) {
  return n.kind === 'finding' ? (WM_SEV_COLOR[n.severity] || WM_SEV_COLOR.info)
                              : (WM_KIND_COLOR[n.kind] || '#8b98a5');
}

function wmElements(data) {
  const nodes = (data.nodes || []).filter(n => !_wmHiddenKinds.has(n.kind)).map(n => ({
    data: {
      id: n.id, label: (n.label || n.id), kind: n.kind, color: wmNodeColor(n),
      props: n.properties || (n.severity ? { severity: n.severity } : {}),
      disc: n.properties?.discovered ? 1 : 0,   // pivot-discovered host
    },
  }));
  const ids = new Set(nodes.map(n => n.data.id));
  const edges = (data.edges || [])
    .map((e, i) => ({ e, i, s: e.source || e.src, t: e.target || e.dst }))
    .filter(x => ids.has(x.s) && ids.has(x.t) && x.s !== x.t)   // skip dangling + self-loops
    .map(x => {
      const st = wmEdgeStyle(x.e.kind);
      return {
        data: {
          id: x.e.id || ('e' + x.i), source: x.s, target: x.t, kind: x.e.kind,
          ecolor: st.color, estyle: st.style, ewidth: st.width, props: x.e.properties || {},
        },
      };
    });
  return [...nodes, ...edges];
}

function wmStyle() {
  return [
    { selector: 'node', style: {
      'background-color': 'data(color)', 'label': 'data(label)', 'color': '#c9d1d9',
      'font-size': '9px', 'font-family': 'ui-monospace, SFMono-Regular, monospace',
      'text-valign': 'bottom', 'text-halign': 'center', 'text-margin-y': 3,
      'text-wrap': 'ellipsis', 'text-max-width': '96px',
      'width': 20, 'height': 20, 'border-width': 1.5, 'border-color': '#0d1117',
      'text-outline-width': 2, 'text-outline-color': '#0d1117',
    } },
    { selector: 'node[kind="finding"]',   style: { 'shape': 'ellipse', 'width': 30, 'height': 30, 'font-size': '10px' } },
    { selector: 'node[kind="primitive"]', style: { 'shape': 'diamond', 'width': 32, 'height': 32, 'color': '#ff9ee6', 'font-weight': 'bold' } },
    { selector: 'node[kind="host"]',      style: { 'shape': 'round-rectangle', 'width': 36, 'height': 24 } },
    { selector: 'node[kind="host"][disc = 1]', style: { 'border-color': '#ff5ccd', 'border-width': 2.5, 'border-style': 'dashed' } },
    { selector: 'node[kind="credential"], node[kind="token"]', style: { 'shape': 'hexagon' } },
    { selector: 'node[kind="param"]',     style: { 'width': 14, 'height': 14 } },
    { selector: 'edge', style: {
      'width': 'data(ewidth)', 'line-color': 'data(ecolor)', 'line-style': 'data(estyle)',
      'target-arrow-color': 'data(ecolor)', 'target-arrow-shape': 'triangle',
      'curve-style': 'bezier', 'arrow-scale': 0.85, 'opacity': 0.7,
      'label': 'data(kind)', 'font-size': '7px', 'color': '#8b949e',
      'text-rotation': 'autorotate', 'text-opacity': 0, 'text-background-color': '#0d1117',
      'text-background-opacity': 0.85, 'text-background-padding': 1,
    } },
    { selector: '.wm-dim',   style: { 'opacity': 0.1, 'text-opacity': 0 } },
    { selector: '.wm-hi',    style: { 'opacity': 1, 'text-opacity': 1, 'z-index': 20 } },
    { selector: '.wm-bridge', style: { 'opacity': 1, 'text-opacity': 1, 'width': 4, 'z-index': 25 } },
    { selector: 'node:selected', style: { 'border-width': 3, 'border-color': '#58a6ff', 'z-index': 30 } },
    { selector: 'edge:selected', style: { 'line-color': '#58a6ff', 'target-arrow-color': '#58a6ff', 'opacity': 1, 'text-opacity': 1, 'width': 4 } },
  ];
}

// ── Layout modes: Tree (horizontal fanned hierarchy), Radial (per-host circles),
//    Force (physics). Returns a cytoscape layout object (not yet run). ──────────
function wmRunLayout(animate) {
  if (!_wmCy) return null;
  if (_wmLayout === 'force') {
    return _wmCy.layout({
      name: 'cose', animate: !!animate, animationDuration: 500, randomize: false,
      nodeRepulsion: 9000, idealEdgeLength: 78, edgeElasticity: 120, gravity: 0.6,
      padding: 24, nodeDimensionsIncludeLabels: true,
    });
  }
  if (_wmLayout === 'radial') {
    return _wmCy.layout({
      name: 'preset', positions: wmRadialPositions(_wmCy),
      animate: !!animate, animationDuration: 450, fit: true, padding: 30,
    });
  }
  // 'tree' — breadthfirst rooted at host(s), laid out HORIZONTALLY (host on the left
  // → endpoints → params → findings fanning right). Undirected BFS so the semantic
  // arrow direction (finding --found_on--> endpoint) doesn't invert the tiers; the
  // x/y-swap transform turns cytoscape's top-down tree into a left-to-right fan.
  const roots = _wmCy.nodes('[kind="host"]');
  const opts = {
    name: 'breadthfirst', directed: false, animate: !!animate, animationDuration: 450,
    spacingFactor: 1.1, padding: 26, avoidOverlap: true, circle: false, grid: false,
    nodeDimensionsIncludeLabels: true,
    transform: (node, pos) => ({ x: pos.y, y: pos.x }),
  };
  if (roots && roots.length) opts.roots = roots;
  return _wmCy.layout(opts);
}

// Multi-source undirected BFS: assign every node to its NEAREST host (for per-host
// radial clustering). Returns { nodeId: hostId }.
function wmAssignToHosts(cy, hosts) {
  const owner = {};
  const queue = [];
  hosts.forEach(h => { owner[h.id()] = h.id(); queue.push(h); });
  for (let qi = 0; qi < queue.length; qi++) {
    const oid = owner[queue[qi].id()];
    queue[qi].connectedEdges().connectedNodes().forEach(nb => {
      if (owner[nb.id()] === undefined) { owner[nb.id()] = oid; queue.push(nb); }
    });
  }
  return owner;
}

// Preset positions for the Radial view. Hosts are separate circles by default; a pivot
// (a finding --reaches--> host) links two hosts into ONE connected component. So we lay
// out per connected COMPONENT: each gets its own region — disconnected targets sit in
// clearly separate areas, while pivot-linked hosts share a region with the REACHES link
// drawn short between them. Within a region each host is a circle with its owned nodes in
// concentric rings (endpoints inner, params/principals mid, findings/primitives outer).
const WM_RING_OF = { endpoint: 1, tech: 1, param: 2, credential: 2, token: 2, finding: 3, primitive: 3 };

function wmRadialPositions(cy) {
  const W = cy.width() || 900, H = cy.height() || 560;
  const comps = cy.elements().components();     // connected components = separate circles
  const nC = Math.max(1, comps.length);
  const cols = Math.ceil(Math.sqrt(nC)), rows = Math.ceil(nC / cols);
  const cellW = W / cols, cellH = H / rows;
  const regionR = Math.min(cellW, cellH) * 0.42;
  const pos = {};
  comps.forEach((comp, ci) => {
    const col = ci % cols, row = Math.floor(ci / cols);
    wmLayoutComponent(comp, (col + 0.5) * cellW, (row + 0.5) * cellH, regionR, pos);
  });
  return pos;
}

// Lay one connected component inside a circular region centred at (rx, ry).
function wmLayoutComponent(comp, rx, ry, R, pos) {
  const hosts = comp.filter('[kind="host"]');
  const nH = hosts.length;
  if (nH === 0) {                        // hostless island — ring its nodes round the centre
    const ns = comp.nodes();
    ns.forEach((n, i) => {
      const a = (2 * Math.PI * i) / (ns.length || 1);
      pos[n.id()] = { x: rx + R * 0.5 * Math.cos(a), y: ry + R * 0.5 * Math.sin(a) };
    });
    return;
  }
  // One host sits at the region centre; several pivot-linked hosts share a small inner
  // ring so their REACHES links stay short and the linkage reads at a glance.
  const hostR = nH > 1 ? R * 0.36 : 0;
  const ringGap = nH > 1 ? R * 0.16 : R / 3.2;
  const center = {};
  hosts.forEach((h, i) => {
    const a = (2 * Math.PI * i) / nH - Math.PI / 2;
    const c = { x: rx + hostR * Math.cos(a), y: ry + hostR * Math.sin(a), a };
    center[h.id()] = c;
    pos[h.id()] = { x: c.x, y: c.y };
  });
  const owner = wmAssignToHosts(comp, hosts);   // each node → nearest host in this component
  const byHostRing = {};
  comp.nodes().forEach(n => {
    if (n.data('kind') === 'host') return;
    const hid = owner[n.id()];
    if (!hid) return;
    const r = WM_RING_OF[n.data('kind')] ?? 3;
    if (!byHostRing[hid]) byHostRing[hid] = {};
    if (!byHostRing[hid][r]) byHostRing[hid][r] = [];
    byHostRing[hid][r].push(n.id());
  });
  Object.keys(byHostRing).forEach(hid => {
    const hc = center[hid];
    if (!hc) return;
    Object.keys(byHostRing[hid]).forEach(r => {
      const ids = byHostRing[hid][r], radius = Number(r) * ringGap;
      ids.forEach((id, i) => {
        const ang = (2 * Math.PI * i) / ids.length + hc.a;
        pos[id] = { x: hc.x + radius * Math.cos(ang), y: hc.y + radius * Math.sin(ang) };
      });
    });
  });
  comp.nodes().forEach(n => { if (!pos[n.id()]) pos[n.id()] = { x: rx, y: ry }; }); // safety
}

function wmSetLayout(mode) {
  _wmLayout = mode;
  ['tree', 'radial', 'force'].forEach(mo => {
    const b = document.getElementById('wm-layout-' + mo);
    if (b) b.classList.toggle('wm-btn-on', mo === mode);
  });
  if (!_wmCy) return;
  const lay = wmRunLayout(true);
  if (lay) { lay.one('layoutstop', () => { _wmCy.fit(undefined, 30); if (_wmBridges) wmApplyBridges(); }); lay.run(); }
}

function wmRenderGraph() {
  const host = document.getElementById('wm-graph');
  if (!host) return;
  if (typeof cytoscape === 'undefined') { wmRenderGraphSvgFallback(); return; }
  const data = _wmData || {};
  if (!(data.nodes || []).length) {
    if (_wmCy) { _wmCy.destroy(); _wmCy = null; _wmSig = null; }
    host.innerHTML = '<div class="wm-empty">World model is empty — it fills in as the scan discovers surface and files findings.</div>';
    return;
  }
  const els = wmElements(data);
  const sig = els.map(e => e.data.id).sort().join('|') + '#' + [..._wmHiddenKinds].sort().join(',');
  if (_wmCy && sig === _wmSig) return;   // structure unchanged — preserve the user's view
  _wmSig = sig;

  if (!_wmCy) {
    host.innerHTML = '';
    _wmCy = cytoscape({
      container: host, elements: els, style: wmStyle(),
      wheelSensitivity: 0.2, minZoom: 0.12, maxZoom: 3.5,
    });
    wmBindGraphEvents();
    const lay = wmRunLayout(false);      // cose is async → fit on stop
    lay.one('layoutstop', () => { _wmCy.fit(undefined, 30); if (_wmBridges) wmApplyBridges(); });
    lay.run();
  } else {
    const pan = _wmCy.pan(), zoom = _wmCy.zoom();       // preserve the user's viewport
    _wmCy.batch(() => { _wmCy.elements().remove(); _wmCy.add(els); });
    const lay = wmRunLayout(false);
    lay.one('layoutstop', () => { _wmCy.pan(pan); _wmCy.zoom(zoom); if (_wmBridges) wmApplyBridges(); });
    lay.run();
  }
  wmRenderLegend();
}

function wmBindGraphEvents() {
  _wmCy.on('tap', 'node', ev => wmInspect(ev.target));
  _wmCy.on('tap', 'edge', ev => wmInspect(ev.target));
  _wmCy.on('tap', ev => {
    if (ev.target !== _wmCy) return;                 // background tap only
    if (!_wmBridges) _wmCy.elements().removeClass('wm-dim wm-hi');
    wmInspectClear();
  });
  _wmCy.on('mouseover', 'node', ev => wmHighlight(ev.target));
  _wmCy.on('mouseout', 'node', () => { _wmBridges ? wmApplyBridges() : _wmCy.elements().removeClass('wm-dim wm-hi'); });
}

function wmHighlight(node) {
  const nb = node.closedNeighborhood();
  _wmCy.elements().addClass('wm-dim').removeClass('wm-hi');
  nb.removeClass('wm-dim').addClass('wm-hi');
}

function wmInspect(ele) {
  const el = document.getElementById('wm-inspector');
  if (!el) return;
  el.classList.remove('wm-inspector-empty');
  const isNode = ele.isNode();
  const d = ele.data();
  const kindColor = isNode ? (WM_KIND_COLOR[d.kind] || '#8b98a5') : ((WM_EDGE[d.kind] || {}).color || '#8b98a5');
  const props = d.props || {};
  const rows = Object.entries(props)
    .filter(([, v]) => v !== '' && v != null)
    .map(([k, v]) => `<tr><td class="wm-pk">${wmEsc(k)}</td><td class="wm-pv">${wmEsc(typeof v === 'object' ? JSON.stringify(v) : v)}</td></tr>`)
    .join('');
  const title = isNode ? wmEsc(d.label)
    : `${wmEsc(_wmCy.getElementById(d.source).data('label') || d.source)} <span class="wm-arrow">→</span> ${wmEsc(_wmCy.getElementById(d.target).data('label') || d.target)}`;
  el.innerHTML =
    `<div class="wm-insp-head">
       <span class="wm-insp-kind" style="background:${kindColor}22;color:${kindColor};border-color:${kindColor}66">${wmEsc(d.kind)}</span>
       <span class="wm-insp-title">${title}</span>
     </div>` +
    (rows ? `<table class="wm-props"><tbody>${rows}</tbody></table>` : `<div class="wm-empty">no properties</div>`);
}

function wmInspectClear() {
  const el = document.getElementById('wm-inspector');
  if (el) { el.classList.add('wm-inspector-empty'); el.innerHTML = 'Click a node or relationship to inspect its properties.'; }
}

function wmRenderLegend() {
  const el = document.getElementById('wm-legend');
  if (!el) return;
  const counts = {};
  (_wmData.nodes || []).forEach(n => { counts[n.kind] = (counts[n.kind] || 0) + 1; });
  const order = ['finding', 'primitive', 'host', 'endpoint', 'param', 'credential', 'token', 'tech'];
  el.innerHTML = order.filter(k => counts[k]).map(k => {
    const off = _wmHiddenKinds.has(k);
    const c = WM_KIND_COLOR[k] || '#8b98a5';
    return `<span class="wm-lg${off ? ' wm-lg-off' : ''}" onclick="wmToggleKind('${k}')" title="Show/hide ${k} nodes">
      <span class="wm-lg-dot" style="background:${c}"></span>${wmEsc(k)} <b>${counts[k]}</b></span>`;
  }).join('');
}

function wmToggleKind(k) {
  if (_wmHiddenKinds.has(k)) _wmHiddenKinds.delete(k); else _wmHiddenKinds.add(k);
  _wmSig = null;              // force a rebuild with the new filter
  wmRenderGraph();
}

function wmToggleBridges() {
  _wmBridges = !_wmBridges;
  const btn = document.getElementById('wm-bridges-btn');
  if (btn) btn.classList.toggle('wm-btn-on', _wmBridges);
  if (!_wmCy) return;
  if (_wmBridges) wmApplyBridges();
  else _wmCy.elements().removeClass('wm-dim wm-hi wm-bridge');
}

function wmApplyBridges() {
  if (!_wmCy) return;
  const bridges = _wmCy.edges('[kind="provides"], [kind="requires"]');
  const prims = _wmCy.nodes('[kind="primitive"]');
  const keep = bridges.union(bridges.connectedNodes()).union(prims);
  _wmCy.elements().addClass('wm-dim').removeClass('wm-hi wm-bridge');
  keep.removeClass('wm-dim');
  bridges.addClass('wm-bridge');
}

function wmRelayout() { if (_wmCy) { const l = wmRunLayout(true); if (l) l.run(); } }
function wmFit() { if (_wmCy) _wmCy.fit(undefined, 30); }

// ── Dependency-free SVG fallback (used only if cytoscape didn't load) ────────
const _WM_COLS = [
  { kinds: ['host', 'tech'], title: 'host / tech' },
  { kinds: ['endpoint'], title: 'endpoints' },
  { kinds: ['param'], title: 'params' },
  { kinds: ['finding'], title: 'findings' },
  { kinds: ['primitive'], title: 'capabilities' },
  { kinds: ['credential', 'token'], title: 'principals' },
];
const _WM_CAP = 18;

function wmRenderGraphSvgFallback() {
  const el = document.getElementById('wm-graph');
  if (!el) return;
  const nodes = (_wmData && _wmData.nodes) || [];
  const edges = (_wmData && _wmData.edges) || [];
  if (!nodes.length) { el.innerHTML = `<div class="wm-empty">World model is empty — it fills in as the scan runs.</div>`; return; }
  const colOf = k => _WM_COLS.findIndex(c => c.kinds.includes(k));
  const byCol = _WM_COLS.map(() => []);
  for (const n of nodes) { const c = colOf(n.kind); if (c >= 0) byCol[c].push(n); }
  const COLW = 200, ROWH = 26, PADX = 12, PADY = 34, BOXW = 172, BOXH = 20;
  const pos = {};
  const rows = Math.max(1, ...byCol.map(c => Math.min(c.length, _WM_CAP)));
  const height = PADY + rows * ROWH + 20, width = _WM_COLS.length * COLW;
  let svg = `<svg viewBox="0 0 ${width} ${height}" width="100%" preserveAspectRatio="xMinYMin meet" class="wm-svg">`;
  _WM_COLS.forEach((c, i) => { svg += `<text x="${i * COLW + PADX}" y="18" class="wm-col-title">${wmEsc(c.title)}</text>`; });
  byCol.forEach((list, ci) => list.slice(0, _WM_CAP).forEach((n, ri) => {
    const x = ci * COLW + PADX, y = PADY + ri * ROWH;
    pos[n.id] = { x: x + BOXW, xl: x, yc: y + BOXH / 2 };
  }));
  edges.forEach(e => {
    const a = pos[e.source || e.src], b = pos[e.target || e.dst];
    if (!a || !b || (e.source || e.src) === (e.target || e.dst)) return;
    svg += `<line x1="${a.x}" y1="${a.yc}" x2="${b.xl}" y2="${b.yc}" class="wm-edge wm-edge-${wmEsc(e.kind)}"/>`;
  });
  byCol.forEach((list, ci) => {
    list.slice(0, _WM_CAP).forEach((n, ri) => {
      const x = ci * COLW + PADX, y = PADY + ri * ROWH;
      const cls = n.kind === 'finding' ? `wm-node wm-node-finding wm-sevfill-${wmEsc(n.severity || 'info')}` : `wm-node wm-node-${wmEsc(n.kind)}`;
      svg += `<g class="${cls}"><rect x="${x}" y="${y}" width="${BOXW}" height="${BOXH}" rx="3"/>` +
        `<text x="${x + 6}" y="${y + 14}"><title>${wmEsc(n.label || n.id)}</title>${wmEsc((n.label || n.id).slice(0, 24))}</text></g>`;
    });
    if (list.length > _WM_CAP) {
      const x = ci * COLW + PADX, y = PADY + _WM_CAP * ROWH;
      svg += `<text x="${x + 6}" y="${y + 12}" class="wm-more">+${list.length - _WM_CAP} more</text>`;
    }
  });
  el.innerHTML = svg + `</svg>`;
}
