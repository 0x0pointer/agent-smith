// ── Knowledge page: the notes vault as a workspace ──────────────────────────
//   left    notes tree            (GET /api/knowledge/{name}/notes)
//   centre  reader + related notes, search results, or the Map (graph view)
//   right   the Brain: questions answered from the vault, each answer citing
//           the notes it used  (POST /api/knowledge/{name}/ask)
//
// Loaded after platform.js and reuses its operator-token helpers (_pfGet,
// _pfHeaders). Everything from a vault or from the AI is untrusted: it goes
// through esc(), or through _kbMd() (Markdown, sanitized) below. Paths travel in
// data-* attributes and clicks are delegated — nothing is put in a handler.

const _KB_SOURCE_KEY = 'smith_kb_source';
const _KB_RECENT_KEY = 'smith_kb_recent';
const _KB_STARTERS = [
  'How do we test a web application, step by step?',
  'What did earlier scans find, and where?',
  'What do we check on login and session handling?',
  'Which findings were critical?',
];
// Folder colours on the Map: the dashboard palette, in a fixed order.
const _KB_FOLDER_COLORS = ['#7b78ff', '#5bf29b', '#faad14', '#fa8c16', '#ff5ccd', '#58c4dc', '#9b98b8'];

let _kb = {
  sources: null, current: '', loadedFor: '',
  notes: [], filter: '', open: '', openTitle: '',
  view: 'read', graph: null, graphFor: '', cy: null,
  chat: [], asking: false,
};

function _kbApi(suffix) {
  return '/api/knowledge/' + encodeURIComponent(_kb.current) + suffix;
}

async function _kbPost(path, body) {
  try {
    const r = await fetch(path, {
      method: 'POST',
      headers: Object.assign({ 'Content-Type': 'application/json' }, _pfHeaders()),
      body: JSON.stringify(body),
    });
    const data = await r.json().catch(() => ({}));
    return { ok: r.ok, status: r.status, data: data };
  } catch (e) {
    return { ok: false, status: 0, data: {} };
  }
}

function _kbMd(text) {
  return (typeof marked !== 'undefined' && typeof sanitizeHtml === 'function')
    ? sanitizeHtml(marked.parse(String(text || '')))
    : `<pre>${esc(text)}</pre>`;
}

function _kbStem(path) {
  return String(path || '').slice(String(path || '').lastIndexOf('/') + 1).replace(/\.(md|txt)$/i, '');
}

// ── Vaults ───────────────────────────────────────────────────────────────────
async function kbRefresh() {
  const setup = document.getElementById('kb-setup');
  const main = document.getElementById('kb-main');
  if (!setup || !main) return;
  const loading = document.getElementById('kb-loading');
  if (loading) loading.hidden = _kb.sources !== null;      // only on the first visit
  const res = await _pfGet('/api/knowledge');
  if (loading) loading.hidden = true;
  _kb.sources = (res.ok && Array.isArray(res.data.sources)) ? res.data.sources : [];
  setup.hidden = _kb.sources.length > 0;
  main.hidden = _kb.sources.length === 0;
  if (!_kb.sources.length) { _kbRenderSources(); return; }

  let wanted = _kb.current;
  if (!wanted) { try { wanted = localStorage.getItem(_KB_SOURCE_KEY) || ''; } catch (e) { wanted = ''; } }
  if (!_kb.sources.some(s => s.name === wanted)) {
    wanted = (_kb.sources.find(s => s.ready) || _kb.sources[0]).name;
  }
  _kb.current = wanted;
  _kbRenderSources();
  if (_kb.loadedFor !== _kb.current) await _kbLoadNotes();
  else _kbRenderChat();
}

function _kbRenderSources() {
  const box = document.getElementById('kb-sources');
  if (!box) return;
  box.innerHTML = (_kb.sources || []).map(s => {
    const state = s.ready ? 'ready' : (s.reachable ? 'indexing' : 'offline');
    const detail = s.ready ? `${s.notes == null ? '—' : s.notes} notes` : (s.reachable ? 'building its index' : 'not running');
    return `<button type="button" role="tab" class="kb-source${s.name === _kb.current ? ' active' : ''}"
        aria-selected="${s.name === _kb.current}" data-kb-source="${esc(s.name)}">
      <span class="kb-dot kb-dot-${state}" aria-hidden="true"></span>
      <span class="kb-source-name">${esc(s.name)}</span>
      <span class="kb-source-detail">${esc(detail)}</span>
    </button>`;
  }).join('');
}

function _kbSelectSource(name) {
  if (!name || name === _kb.current) return;
  _kb.current = name;
  try { localStorage.setItem(_KB_SOURCE_KEY, name); } catch (e) { /* ignore */ }
  _kb.chat = [];
  _kb.graph = null;
  _kbRenderSources();
  _kbLoadNotes();
}

// ── Notes tree ───────────────────────────────────────────────────────────────
async function _kbLoadNotes() {
  const tree = document.getElementById('kb-tree');
  if (!tree) return;
  tree.innerHTML = '<div class="empty-placeholder">Loading…</div>';
  const forSource = _kb.current;
  const res = await _pfGet(_kbApi('/notes'));
  if (forSource !== _kb.current) return;            // the operator switched vaults meanwhile
  _kb.loadedFor = forSource;
  _kb.open = '';
  _kb.openTitle = '';
  _kb.notes = res.ok ? (res.data.notes || []) : [];
  _kbSyncAskScope();
  _kbRenderChat();
  if (!res.ok) {
    tree.innerHTML = `<div class="pf-empty"><p>${esc(res.data.error || 'This vault could not be reached.')}</p></div>`;
    const view = document.getElementById('kb-view');
    if (view) view.innerHTML = '<div class="pf-empty"><p>Start the Source service for this vault, then choose it again.</p></div>';
    const count = document.getElementById('kb-tree-count');
    if (count) count.textContent = 'Notes';
    return;
  }
  _kbRenderTree();
  _kbSetView('read');
  _kbShowWelcome();
}

function _kbFolders(notes) {
  const folders = new Map();
  for (const n of notes) {
    const cut = n.path.lastIndexOf('/');
    const dir = cut === -1 ? '' : n.path.slice(0, cut);
    if (!folders.has(dir)) folders.set(dir, []);
    folders.get(dir).push(n);
  }
  return folders;
}

function _kbRenderTree() {
  const tree = document.getElementById('kb-tree');
  if (!tree) return;
  const q = _kb.filter.trim().toLowerCase();
  const notes = _kb.notes.filter(n => !q || n.path.toLowerCase().includes(q));
  const count = document.getElementById('kb-tree-count');
  if (count) count.textContent = q ? `${notes.length} of ${_kb.notes.length} notes` : `${_kb.notes.length} notes`;
  if (!_kb.notes.length) { tree.innerHTML = '<div class="pf-empty"><p>This vault has no notes yet.</p></div>'; return; }
  if (!notes.length) { tree.innerHTML = '<div class="pf-empty"><p>No note matches that filter.</p></div>'; return; }
  const folders = _kbFolders(notes);
  const item = n => `<button type="button" class="kb-note${n.path === _kb.open ? ' active' : ''}"
      data-kb-note="${esc(n.path)}" title="${esc(n.path)}">${esc(_kbStem(n.path))}</button>`;
  tree.innerHTML = [...folders.keys()].sort().map(dir => {
    const items = folders.get(dir).map(item).join('');
    if (!dir) return `<div class="kb-folder-root">${items}</div>`;
    return `<details class="kb-folder" open><summary>${esc(dir)} <span class="pf-count">${folders.get(dir).length}</span></summary>${items}</details>`;
  }).join('');
}

// ── Recently opened (per vault, this browser) ────────────────────────────────
function _kbRecent() {
  let all = {};
  try { all = JSON.parse(localStorage.getItem(_KB_RECENT_KEY) || '{}') || {}; } catch (e) { all = {}; }
  const known = new Set(_kb.notes.map(n => n.path));
  return (Array.isArray(all[_kb.current]) ? all[_kb.current] : []).filter(p => known.has(p));
}

function _kbRememberRecent(path) {
  let all = {};
  try { all = JSON.parse(localStorage.getItem(_KB_RECENT_KEY) || '{}') || {}; } catch (e) { all = {}; }
  const list = (Array.isArray(all[_kb.current]) ? all[_kb.current] : []).filter(p => p !== path);
  list.unshift(path);
  all[_kb.current] = list.slice(0, 6);
  try { localStorage.setItem(_KB_RECENT_KEY, JSON.stringify(all)); } catch (e) { /* ignore */ }
}

// ── Centre: welcome, reader, search ──────────────────────────────────────────
function _kbShowWelcome() {
  const view = document.getElementById('kb-view');
  if (!view) return;
  const folders = _kbFolders(_kb.notes);
  const named = [...folders.keys()].filter(Boolean).sort();
  const recent = _kbRecent();
  view.innerHTML = `<div class="kb-welcome">
    <h3>${esc(_kb.current)}</h3>
    <p class="kb-welcome-sub">${_kb.notes.length} note${_kb.notes.length === 1 ? '' : 's'}${named.length ? ` in ${named.length} folder${named.length === 1 ? '' : 's'}` : ''}.
      Pick a note on the left, search above, or ask the brain on the right.</p>
    <div class="kb-welcome-grid">
      <section>
        <h4>Recently opened</h4>
        ${recent.length
          ? recent.map(p => `<button type="button" class="kb-row" data-kb-note="${esc(p)}"><span>${esc(_kbStem(p))}</span><small>${esc(p)}</small></button>`).join('')
          : '<p class="pf-muted">Notes you open show up here.</p>'}
      </section>
      <section>
        <h4>Folders</h4>
        ${named.length
          ? named.map(d => `<button type="button" class="kb-row" data-kb-folder="${esc(d)}"><span>${esc(d)}</span><small>${folders.get(d).length} note${folders.get(d).length === 1 ? '' : 's'}</small></button>`).join('')
          : '<p class="pf-muted">This vault keeps its notes in one folder.</p>'}
      </section>
    </div>
  </div>`;
}

// "---\ntags: [a, b]\n---\n# Title…" → { tags: ['a','b'], body: '# Title…' }
function _kbSplitFrontmatter(text) {
  const m = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?/.exec(text || '');
  if (!m) return { tags: [], body: text || '' };
  const tagLine = /^tags:\s*\[?([^\]\n]*)\]?/m.exec(m[1]);
  const tags = tagLine ? tagLine[1].split(/[,\s]+/).map(t => t.trim()).filter(Boolean) : [];
  return { tags: tags, body: text.slice(m[0].length) };
}

function _kbTags(tags) {
  return (tags || []).length ? `<span class="kb-tags">${tags.map(t => `<span class="pf-tag">${esc(t)}</span>`).join('')}</span>` : '';
}

async function _kbOpenNote(path) {
  const view = document.getElementById('kb-view');
  if (!view || !path) return;
  _kbSetView('read');
  _kb.open = path;
  _kb.openTitle = _kbStem(path);
  _kbRenderTree();
  _kbSyncAskScope();
  view.innerHTML = '<div class="empty-placeholder">Loading…</div>';
  const res = await _pfGet(_kbApi('/note?path=' + encodeURIComponent(path)));
  if (_kb.open !== path) return;
  if (!res.ok) {
    view.innerHTML = `<div class="pf-empty"><p>${esc(res.data.error || 'This note could not be opened.')}</p></div>`;
    return;
  }
  const parts = _kbSplitFrontmatter(res.data.content || '');
  const heading = /^#\s+(.+)$/m.exec(parts.body);
  _kb.openTitle = heading ? heading[1].trim() : _kbStem(path);
  _kbRememberRecent(path);
  _kbSyncAskScope();
  const crumbs = path.split('/').map(esc).join('<span class="kb-crumb-sep">›</span>');
  view.innerHTML = `<header class="kb-view-head">
      <span class="kb-path">${crumbs}</span>${_kbTags(parts.tags)}
      <button type="button" class="btn btn-secondary btn-sm kb-view-ask" data-kb-action="ask-note">Ask about this note</button>
    </header>
    ${res.data.truncated ? '<p class="kb-truncated">This note is long; only the first part is shown.</p>' : ''}
    <div class="kb-note-body">${_kbMd(parts.body)}</div>
    <section class="kb-related" id="kb-related" hidden></section>`;
  _kbLinkNotes(view.querySelector('.kb-note-body'), path);
  view.scrollTop = 0;
  _kbLoadRelated(path, _kb.openTitle);
}

// Find the note a link points at: relative to the open note, then from the
// vault root, then by file name alone (how [[wikilinks]] work).
function _kbResolveLink(target, fromPath) {
  const raw = String(target || '').split('#')[0].split('|')[0].trim().replace(/\\/g, '/');
  if (!raw || /^[a-z][a-z0-9+.-]*:/i.test(raw)) return '';
  const base = fromPath.includes('/') ? fromPath.slice(0, fromPath.lastIndexOf('/')) : '';
  const norm = p => {
    const out = [];
    for (const seg of p.split('/')) {
      if (!seg || seg === '.') continue;
      if (seg === '..') { out.pop(); continue; }
      out.push(seg);
    }
    return out.join('/').toLowerCase();
  };
  const byPath = new Map(_kb.notes.map(n => [n.path.toLowerCase(), n.path]));
  for (const cand of [base ? base + '/' + raw : raw, raw]) {
    const key = norm(cand);
    for (const k of [key, key + '.md', key + '.txt']) if (byPath.has(k)) return byPath.get(k);
  }
  const stem = _kbStem(raw).toLowerCase();
  const hit = _kb.notes.find(n => _kbStem(n.path).toLowerCase() === stem);
  return hit ? hit.path : '';
}

// Make links between notes work inside the reader: [[wikilinks]] become
// buttons, and Markdown links to another note open it instead of navigating.
function _kbLinkNotes(root, fromPath) {
  if (!root) return;
  const noteButton = (path, label) => {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'kb-wikilink';
    btn.textContent = label;
    btn.title = path;
    btn.setAttribute('data-kb-note', path);
    return btn;
  };
  root.querySelectorAll('a[href]').forEach(a => {
    let href = a.getAttribute('href') || '';
    try { href = decodeURIComponent(href); } catch (e) { /* keep the raw href */ }
    const path = _kbResolveLink(href, fromPath);
    if (path) a.replaceWith(noteButton(path, a.textContent));
    else { a.target = '_blank'; a.rel = 'noopener noreferrer'; }
  });
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  const texts = [];
  while (walker.nextNode()) texts.push(walker.currentNode);
  for (const node of texts) {
    if (node.parentElement && node.parentElement.closest('code, pre')) continue;
    if (!node.nodeValue.includes('[[')) continue;
    const frag = document.createDocumentFragment();
    node.nodeValue.split(/(\[\[[^\]\n]+\]\])/).forEach(part => {
      const m = /^\[\[([^\]\n]+)\]\]$/.exec(part);
      const path = m ? _kbResolveLink(m[1], fromPath) : '';
      if (!path) { frag.appendChild(document.createTextNode(part)); return; }
      const alias = m[1].includes('|') ? m[1].split('|')[1].trim() : m[1].split('#')[0].trim();
      frag.appendChild(noteButton(path, alias));
    });
    node.parentNode.replaceChild(frag, node);
  }
}

// Notes that are close in meaning to the open one (the Source's vector search).
async function _kbLoadRelated(path, title) {
  const res = await _pfGet(_kbApi('/search?k=8&mode=vector&q=' + encodeURIComponent(title)));
  const box = document.getElementById('kb-related');
  if (!box || _kb.open !== path || !res.ok) return;
  const seen = new Set([path]);
  const related = (res.data.results || []).filter(h => h.path && !seen.has(h.path) && seen.add(h.path)).slice(0, 5);
  if (!related.length) return;
  box.hidden = false;
  box.innerHTML = '<h4>Related notes</h4>' + related.map(h =>
    `<button type="button" class="kb-row" data-kb-note="${esc(h.path)}">
       <span>${esc(h.heading || _kbStem(h.path))}</span><small>${esc(h.path)}</small>
     </button>`).join('');
}

async function _kbSearch() {
  const view = document.getElementById('kb-view');
  const q = ((document.getElementById('kb-q') || {}).value || '').trim();
  const mode = (document.getElementById('kb-mode') || {}).value || 'hybrid';
  if (!view) return;
  _kbSetView('read');
  if (!q) { _kbShowWelcome(); return; }
  _kb.open = '';
  _kb.openTitle = '';
  _kbRenderTree();
  _kbSyncAskScope();
  view.innerHTML = '<div class="empty-placeholder">Searching…</div>';
  const res = await _pfGet(_kbApi('/search?k=10&mode=' + encodeURIComponent(mode) + '&q=' + encodeURIComponent(q)));
  if (!res.ok) {
    view.innerHTML = `<div class="pf-empty"><p>${esc(res.data.error || 'The search did not work.')}</p></div>`;
    return;
  }
  const hits = res.data.results || [];
  const askBtn = `<button type="button" class="btn btn-secondary btn-sm kb-view-ask" data-kb-ask="${esc(q)}">Ask the brain this</button>`;
  if (!hits.length) {
    view.innerHTML = `<div class="pf-empty"><p>Nothing in this vault matches “${esc(q)}”. Try other words, or switch the match to “By meaning”.</p>${askBtn}</div>`;
    return;
  }
  view.innerHTML = `<header class="kb-view-head"><span class="kb-path">${hits.length} result${hits.length === 1 ? '' : 's'} for “${esc(q)}”</span>${askBtn}</header>` +
    hits.map(h => `<article class="kb-hit">
      <header>
        <button type="button" class="kb-hit-open" data-kb-note="${esc(h.path)}">${esc(h.heading || _kbStem(h.path))}</button>
        <span class="kb-hit-path">${esc(h.path)}</span>
        ${_kbTags(h.tags)}
      </header>
      <p class="kb-hit-text">${esc(h.text.length > 600 ? h.text.slice(0, 600) + '…' : h.text)}</p>
    </article>`).join('');
  view.scrollTop = 0;
}

// ── Map (graph view) ─────────────────────────────────────────────────────────
function _kbSetView(view) {
  _kb.view = view === 'map' ? 'map' : 'read';
  const read = document.getElementById('kb-view');
  const map = document.getElementById('kb-map');
  if (read) read.hidden = _kb.view !== 'read';
  if (map) map.hidden = _kb.view !== 'map';
  document.querySelectorAll('.kb-view-btn').forEach(btn => {
    const on = btn.getAttribute('data-kb-view') === _kb.view;
    btn.classList.toggle('active', on);
    btn.setAttribute('aria-selected', on ? 'true' : 'false');
  });
  if (_kb.view === 'map') _kbLoadGraph();
}

async function _kbLoadGraph() {
  const hint = document.getElementById('kb-map-hint');
  if (!_kb.graph || _kb.graphFor !== _kb.current) {
    if (hint) hint.textContent = 'Drawing the map…';
    const forSource = _kb.current;
    const res = await _pfGet(_kbApi('/graph'));
    if (forSource !== _kb.current) return;
    if (!res.ok) { if (hint) hint.textContent = res.data.error || 'The map could not be drawn.'; return; }
    _kb.graph = res.data;
    _kb.graphFor = forSource;
  }
  if (_kb.view === 'map') _kbRenderGraph();
}

function _kbRenderGraph() {
  const canvas = document.getElementById('kb-map-canvas');
  const legend = document.getElementById('kb-map-legend');
  const hint = document.getElementById('kb-map-hint');
  if (!canvas || !_kb.graph) return;
  if (typeof cytoscape !== 'function') { if (hint) hint.textContent = 'The map needs the graph library, which did not load.'; return; }
  const notes = _kb.graph.nodes.filter(n => n.kind === 'note');
  const folders = [...new Set(notes.map(n => n.folder || ''))].sort();
  const colorOf = folder => _KB_FOLDER_COLORS[Math.max(0, folders.indexOf(folder || '')) % _KB_FOLDER_COLORS.length];
  const degree = {};
  for (const e of _kb.graph.edges) {
    degree[e.source] = (degree[e.source] || 0) + 1;
    degree[e.target] = (degree[e.target] || 0) + 1;
  }
  const elements = _kb.graph.nodes.map(n => ({
    data: {
      id: n.id, label: n.label, kind: n.kind,
      color: n.kind === 'tag' ? '#8683ad' : colorOf(n.folder),
      size: n.kind === 'tag' ? 12 : Math.min(46, 20 + 4 * (degree[n.id] || 0)),
    },
  })).concat(_kb.graph.edges.map((e, i) => ({
    data: { id: 'e' + i, source: e.source, target: e.target, kind: e.kind },
  })));

  if (_kb.cy) { try { _kb.cy.destroy(); } catch (e) { /* ignore */ } }
  _kb.cy = cytoscape({
    container: canvas,
    elements: elements,
    minZoom: 0.3, maxZoom: 2.5, wheelSensitivity: 0.25,
    style: [
      { selector: 'node', style: {
          'background-color': 'data(color)', 'width': 'data(size)', 'height': 'data(size)',
          'label': 'data(label)', 'color': '#e8e6f0', 'font-size': 10, 'text-wrap': 'ellipsis', 'text-max-width': 130,
          'text-valign': 'bottom', 'text-margin-y': 5, 'text-outline-color': '#13112e', 'text-outline-width': 2,
          'border-width': 0 } },
      { selector: 'node[kind = "tag"]', style: { 'shape': 'diamond', 'color': '#9b98b8', 'font-size': 9 } },
      { selector: 'edge', style: { 'width': 1.4, 'line-color': 'rgba(123,120,255,0.55)', 'curve-style': 'bezier' } },
      { selector: 'edge[kind = "tag"]', style: { 'width': 1, 'line-style': 'dashed', 'line-color': 'rgba(155,152,184,0.3)' } },
      { selector: 'node.kb-open', style: { 'border-width': 3, 'border-color': '#5bf29b' } },
      { selector: '.kb-dim', style: { 'opacity': 0.18 } },
    ],
    layout: { name: 'cose', animate: false, padding: 30, nodeRepulsion: 9000, idealEdgeLength: 90 },
  });
  _kb.cy.on('tap', 'node[kind = "note"]', ev => _kbOpenNote(ev.target.id()));
  // Hover a node to see just its neighbourhood.
  _kb.cy.on('mouseover', 'node', ev => {
    const near = ev.target.closedNeighborhood();
    _kb.cy.elements().not(near).addClass('kb-dim');
  });
  _kb.cy.on('mouseout', 'node', () => _kb.cy.elements().removeClass('kb-dim'));
  if (_kb.open) { const cur = _kb.cy.getElementById(_kb.open); if (cur) cur.addClass('kb-open'); }

  if (legend) {
    legend.innerHTML = folders.map(f =>
      `<span class="kb-legend-item"><span class="kb-legend-dot" style="background:${colorOf(f)}"></span>${esc(f || 'top level')}</span>`).join('');
  }
  if (hint) {
    const links = _kb.graph.edges.filter(e => e.kind === 'link').length;
    hint.textContent = `${notes.length} notes, ${links} link${links === 1 ? '' : 's'} between them` +
      (_kb.graph.truncated ? ' (only the first notes are drawn)' : '') +
      '. Lines are links, diamonds are tags. Click a note to read it.';
  }
}

// ── Brain (chat) ─────────────────────────────────────────────────────────────
function _kbSyncAskScope() {
  const scope = document.getElementById('kb-ask-scope');
  const name = document.getElementById('kb-ask-note-name');
  if (scope) scope.hidden = !_kb.open;
  if (name) name.textContent = _kb.openTitle || '';
}

// Turn "[2]" in an answer into a button that opens source 2's note.
function _kbLinkCitations(root, sources) {
  const byN = {};
  for (const s of sources || []) byN[String(s.n)] = s;
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  const texts = [];
  while (walker.nextNode()) texts.push(walker.currentNode);
  for (const node of texts) {
    if (node.parentElement && node.parentElement.closest('code, pre')) continue;
    if (!/\[\d{1,2}\]/.test(node.nodeValue)) continue;
    const frag = document.createDocumentFragment();
    node.nodeValue.split(/(\[\d{1,2}\])/).forEach(part => {
      const m = /^\[(\d{1,2})\]$/.exec(part);
      const src = m && byN[m[1]];
      if (!src) { frag.appendChild(document.createTextNode(part)); return; }
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'kb-cite';
      btn.textContent = m[1];
      btn.title = src.path + (src.heading ? ' › ' + src.heading : '');
      btn.setAttribute('data-kb-note', src.path);
      frag.appendChild(btn);
    });
    node.parentNode.replaceChild(frag, node);
  }
}

function _kbSourcesHtml(sources, label) {
  if (!(sources || []).length) return '';
  return `<div class="kb-msg-sources"><span class="kb-msg-sources-label">${esc(label)}</span>` +
    sources.map(s => `<button type="button" class="kb-src" data-kb-note="${esc(s.path)}" title="${esc(s.text || '')}">
        <span class="kb-src-n">${esc(s.n)}</span><span class="kb-src-name">${esc(s.heading && s.heading !== 'the open note' ? s.heading : _kbStem(s.path))}</span>
      </button>`).join('') + '</div>';
}

function _kbRenderChat() {
  const box = document.getElementById('kb-chat');
  if (!box) return;
  const newBtn = document.getElementById('kb-chat-new');
  if (newBtn) newBtn.hidden = !_kb.chat.length;
  if (!_kb.chat.length) {
    box.innerHTML = `<div class="kb-chat-empty">
      <p>Ask a question in plain words. The brain finds the notes that answer it, writes a short answer and shows which notes it used.</p>
      <div class="kb-starters">${_KB_STARTERS.map(q =>
        `<button type="button" class="kb-starter" data-kb-ask="${esc(q)}">${esc(q)}</button>`).join('')}</div>
    </div>`;
    return;
  }
  box.innerHTML = _kb.chat.map((m, i) => {
    if (m.role === 'user') {
      return `<div class="kb-msg kb-msg-user"><p>${esc(m.text)}</p>${m.note ? `<small>About ${esc(_kbStem(m.note))}</small>` : ''}</div>`;
    }
    if (m.pending) {
      return '<div class="kb-msg kb-msg-brain kb-msg-pending"><span class="kb-thinking" aria-hidden="true"></span>Reading your notes…</div>';
    }
    if (m.text) {
      // List the notes the answer actually cites; all of them if it cited none.
      const cited = new Set((m.text.match(/\[(\d{1,2})\]/g) || []).map(c => c.slice(1, -1)));
      const used = (m.sources || []).filter(s => cited.has(String(s.n)));
      return `<div class="kb-msg kb-msg-brain">
        <div class="kb-msg-body kb-note-body" data-kb-answer="${i}">${_kbMd(m.text)}</div>
        ${used.length ? _kbSourcesHtml(used, 'Sources') : _kbSourcesHtml(m.sources, 'Passages it was shown')}
        <div class="kb-msg-actions">
          <button type="button" class="pf-link" data-kb-action="copy" data-kb-msg="${i}">Copy</button>
          <button type="button" class="pf-link" data-kb-action="save" data-kb-msg="${i}"${m.saved ? ' hidden' : ''}>Save to vault</button>
          ${m.saved ? `<span class="kb-saved">Saved as ${esc(m.saved)}</span>` : ''}
        </div>
      </div>`;
    }
    return `<div class="kb-msg kb-msg-brain kb-msg-none">
      <p>${esc(m.message || 'No answer this time.')}</p>
      ${_kbSourcesHtml(m.sources, 'Closest passages')}
    </div>`;
  }).join('');
  box.querySelectorAll('[data-kb-answer]').forEach(el => {
    const msg = _kb.chat[Number(el.getAttribute('data-kb-answer'))];
    if (msg) _kbLinkCitations(el, msg.sources);
  });
  box.scrollTop = box.scrollHeight;
}

async function _kbAsk(question) {
  question = String(question || '').trim();
  if (!question || _kb.asking || !_kb.current) return;
  const aboutNote = _kb.open && (document.getElementById('kb-ask-note') || {}).checked ? _kb.open : '';
  const history = _kb.chat.filter(m => !m.pending && (m.role === 'user' || m.text))
    .map(m => ({ role: m.role === 'user' ? 'user' : 'brain', text: m.text }));
  _kb.chat.push({ role: 'user', text: question, note: aboutNote });
  const pending = { role: 'brain', pending: true };
  _kb.chat.push(pending);
  _kb.asking = true;
  const send = document.getElementById('kb-ask-send');
  if (send) send.disabled = true;
  _kbRenderChat();

  const forSource = _kb.current;
  const res = await _kbPost(_kbApi('/ask'), { question: question, history: history, note: aboutNote });
  _kb.asking = false;
  if (send) send.disabled = false;
  if (forSource !== _kb.current) return;             // the chat was reset by a vault switch
  pending.pending = false;
  pending.question = question;
  if (res.ok) {
    pending.text = res.data.answer || '';
    pending.sources = res.data.sources || [];
    pending.message = res.data.message || '';
  } else {
    pending.message = res.data.error || 'The brain could not be reached. Is the platform still running?';
  }
  _kbRenderChat();
}

async function _kbSaveAnswer(index) {
  const msg = _kb.chat[index];
  if (!msg || !msg.text || msg.saved) return;
  const cited = new Set((msg.text.match(/\[(\d{1,2})\]/g) || []).map(c => c.slice(1, -1)));
  const used = (msg.sources || []).filter(s => !cited.size || cited.has(String(s.n)));
  // Plain Markdown for the saved note (not page markup).
  const sources = used.map(s => '- [' + s.n + '] ' + s.path + (s.heading ? ' › ' + s.heading : '')).join('\n');
  const text = `**Question:** ${msg.question || ''}\n\n${msg.text}\n\n## Sources\n\n${sources}\n`;
  const res = await _kbPost(_kbApi('/notes'), { title: (msg.question || 'Brain answer').slice(0, 100), text: text, tags: ['brain'] });
  if (res.ok && res.data.saved) {
    msg.saved = res.data.path;
    _kbRenderChat();
    const forSource = _kb.current;
    const notes = await _pfGet(_kbApi('/notes'));       // the new note joins the tree
    if (notes.ok && forSource === _kb.current) { _kb.notes = notes.data.notes || []; _kb.graph = null; _kbRenderTree(); }
  } else if (typeof _notify === 'function') {
    _notify('Could not save the note', res.data.error || 'The vault did not accept it.');
  }
}

// ── Wiring ───────────────────────────────────────────────────────────────────
function _kbOnClick(ev) {
  const t = ev.target;
  if (!t.closest) return;
  const source = t.closest('[data-kb-source]');
  if (source) { _kbSelectSource(source.getAttribute('data-kb-source')); return; }
  const viewBtn = t.closest('[data-kb-view]');
  if (viewBtn) { _kbSetView(viewBtn.getAttribute('data-kb-view')); return; }
  const ask = t.closest('[data-kb-ask]');
  if (ask) { _kbAsk(ask.getAttribute('data-kb-ask')); return; }
  const folder = t.closest('[data-kb-folder]');
  if (folder) {
    _kb.filter = folder.getAttribute('data-kb-folder') + '/';
    const input = document.getElementById('kb-tree-filter');
    if (input) input.value = _kb.filter;
    _kbRenderTree();
    return;
  }
  const action = t.closest('[data-kb-action]');
  if (action) {
    const kind = action.getAttribute('data-kb-action');
    const index = Number(action.getAttribute('data-kb-msg'));
    if (kind === 'ask-note') {
      const box = document.getElementById('kb-ask-note');
      if (box) box.checked = true;
      const q = document.getElementById('kb-ask-q');
      if (q) { q.placeholder = 'Ask about this note…'; q.focus(); }
    } else if (kind === 'copy' && _kb.chat[index] && navigator.clipboard) {
      navigator.clipboard.writeText(_kb.chat[index].text || '').then(() => { action.textContent = 'Copied'; }, () => {});
    } else if (kind === 'save') {
      _kbSaveAnswer(index);
    }
    return;
  }
  const note = t.closest('[data-kb-note]');
  if (note) _kbOpenNote(note.getAttribute('data-kb-note'));
}

function _initKnowledge() {
  const page = document.getElementById('tab-knowledge');
  if (!page) return;
  page.addEventListener('click', _kbOnClick);

  const search = document.getElementById('kb-search-form');
  if (search) search.addEventListener('submit', ev => { ev.preventDefault(); _kbSearch(); });
  const filter = document.getElementById('kb-tree-filter');
  if (filter) filter.addEventListener('input', () => { _kb.filter = filter.value; _kbRenderTree(); });
  const retry = document.getElementById('kb-setup-retry');
  if (retry) retry.addEventListener('click', kbRefresh);

  const askForm = document.getElementById('kb-ask-form');
  const askBox = document.getElementById('kb-ask-q');
  const submitAsk = () => {
    if (!askBox || _kb.asking) return;
    const q = askBox.value;
    if (!q.trim()) return;
    askBox.value = '';
    _kbAsk(q);
  };
  if (askForm) askForm.addEventListener('submit', ev => { ev.preventDefault(); submitAsk(); });
  // Enter sends; Shift+Enter makes a new line.
  if (askBox) askBox.addEventListener('keydown', ev => {
    if (ev.key === 'Enter' && !ev.shiftKey) { ev.preventDefault(); submitAsk(); }
  });
  const newChat = document.getElementById('kb-chat-new');
  if (newChat) newChat.addEventListener('click', () => { if (!_kb.asking) { _kb.chat = []; _kbRenderChat(); } });
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', _initKnowledge);
else _initKnowledge();
