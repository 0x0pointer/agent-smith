// ── tool-results.js — the "Tool Results" page (tab id: activity) ─────────────
// Shows what every tool that ran actually found. One card per tool: a headline
// ("4 open ports on 1 host"), the de-duplicated results as a table, and the
// individual runs with a link to each run's raw output. Every card has a
// "Steer Smith" action that opens the instruction box pre-filled with that
// tool's context, so the operator can correct course from what they just read.
//
// Data: GET /api/tool-results (core/tool_results.py). FLAT classic script.

let _trData = null;
let _trSig = '';
let _trOpen = null;              // Set of expanded tool keys (persisted)
let _trQuery = '';
const _TR_OPEN_KEY = 'smith_tool_results_open';

function _trEsc(s) {
  return String(s == null ? '' : s).replace(/[&<>"]/g,
    c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

function _trLoadOpen() {
  if (_trOpen) return _trOpen;
  try { _trOpen = new Set(JSON.parse(localStorage.getItem(_TR_OPEN_KEY) || 'null') || []); }
  catch (e) { _trOpen = new Set(); }
  return _trOpen;
}

function _trSaveOpen() {
  try { localStorage.setItem(_TR_OPEN_KEY, JSON.stringify(Array.from(_trOpen).slice(-80))); }
  catch (e) { /* ignore */ }
}

function _trTime(iso) {
  const d = new Date(iso);
  if (!iso || isNaN(d.getTime())) return { text: '', title: '' };
  return { text: d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }), title: d.toLocaleString() };
}

function _trRowText(row) {
  return Object.keys(row).filter(k => k !== 'artifact_id' && k !== 'time').map(k => row[k]).join(' ').toLowerCase();
}

// Severity and HTTP status get a text label AND a colour class, never colour alone.
function _trCell(key, value) {
  const v = _trEsc(value);
  if (key === 'severity' && value) return `<span class="badge badge-${_trEsc(String(value).toLowerCase())}">${v}</span>`;
  if (key === 'status' && /^\d{3}$/.test(String(value))) {
    const cls = value[0] === '2' ? 'ok' : value[0] === '3' ? 'redir' : value[0] === '4' ? 'client' : 'server';
    return `<span class="tr-status tr-status-${cls}">${v}</span>`;
  }
  if (key === 'port') return `<strong>${v}</strong>`;
  return v;
}

function _trOverview(ov) {
  const box = document.getElementById('tr-overview');
  if (!box) return;
  const tiles = [
    ['Domains', (ov.domains || []).concat(ov.ips || [])],
    ['Open ports', ov.ports || []],
    ['Endpoints', ov.endpoints || []],
    ['Technologies', ov.technologies || []],
  ];
  const any = tiles.some(t => t[1].length) || ov.credentials || ov.auth_tokens;
  box.hidden = !any;
  if (!any) { box.innerHTML = ''; return; }
  const chips = list => list.slice(0, 12).map(x => `<span class="tr-chip">${_trEsc(x)}</span>`).join('') +
    (list.length > 12 ? `<span class="tr-more">+${list.length - 12} more</span>` : '');
  box.innerHTML = tiles.map(([label, list]) => `<div class="tr-ov-item">
      <div class="tr-ov-head"><span class="tr-ov-num">${list.length}</span><span class="tr-ov-label">${label}</span></div>
      <div class="tr-ov-chips">${list.length ? chips(list) : '<span class="tr-none">none yet</span>'}</div>
    </div>`).join('') +
    `<div class="tr-ov-item">
      <div class="tr-ov-head"><span class="tr-ov-num">${(ov.credentials || 0) + (ov.auth_tokens || 0)}</span><span class="tr-ov-label">Credentials &amp; tokens</span></div>
      <div class="tr-ov-chips"><span class="tr-none">${ov.credentials || 0} credential${ov.credentials === 1 ? '' : 's'}, ${ov.auth_tokens || 0} token${ov.auth_tokens === 1 ? '' : 's'} captured. Values are not shown here.</span></div>
    </div>`;
}

function _trCard(tool, q) {
  const open = _trLoadOpen().has(tool.tool) || !!q;
  const rows = q ? tool.rows.filter(r => _trRowText(r).includes(q)) : tool.rows;
  const runs = q ? tool.runs.filter(r => (r.command + ' ' + r.target).toLowerCase().includes(q)) : tool.runs;
  if (q && !rows.length && !runs.length && !tool.label.toLowerCase().includes(q)) return '';
  const last = _trTime(tool.last_run);
  const cols = tool.columns || [];

  let results = '';
  if (rows.length && cols.length) {
    const shown = rows.slice(0, 200);
    results = `<div class="tr-table-wrap"><table class="sessions-table tr-table">
        <thead><tr>${cols.map(c => `<th>${_trEsc(c[1])}</th>`).join('')}<th></th></tr></thead>
        <tbody>${shown.map(r => `<tr>${cols.map(c => `<td>${_trCell(c[0], r[c[0]])}</td>`).join('')}
          <td class="runs-actions"><button type="button" class="runs-select-btn" data-raw="${_trEsc(r.artifact_id)}" title="Show the raw output this came from">Raw</button></td></tr>`).join('')}</tbody>
      </table></div>` +
      (rows.length > shown.length ? `<div class="tr-note">Showing ${shown.length} of ${rows.length}. Use the search box to narrow down.</div>` : '') +
      (tool.total_rows > tool.rows.length ? `<div class="tr-note">${tool.total_rows} results in total; the newest ${tool.rows.length} are loaded.</div>` : '');
  } else if (tool.parsed && !q) {
    results = '<div class="tr-note">This tool ran but reported nothing. Check a run\'s raw output if that is unexpected.</div>';
  }

  const runRows = runs.slice(0, 60).map(r => {
    const t = _trTime(r.time);
    const what = r.command ? `<code class="tr-cmd" title="${_trEsc(r.command)}">${_trEsc(r.command)}</code>` : _trEsc(r.target || '—');
    const flags = (r.timed_out ? ' <span class="tr-flag">timed out</span>' : '') + (r.error ? ` <span class="tr-flag" title="${_trEsc(r.error)}">error</span>` : '');
    const outcome = tool.parsed ? `${r.results} result${r.results === 1 ? '' : 's'}` : `${r.lines} line${r.lines === 1 ? '' : 's'}`;
    return `<tr><td class="act-time" title="${_trEsc(t.title)}">${_trEsc(t.text)}</td><td class="tr-what">${what}${flags}</td>
      <td class="tr-outcome">${outcome}</td>
      <td class="runs-actions"><button type="button" class="runs-select-btn" data-raw="${_trEsc(r.artifact_id)}">Raw output</button></td></tr>`;
  }).join('');
  const runsBlock = runs.length ? `<details class="tr-runs"${(!rows.length || !cols.length) ? ' open' : ''}>
      <summary>${runs.length} run${runs.length === 1 ? '' : 's'}${tool.total_runs > tool.runs.length ? ` (of ${tool.total_runs})` : ''}</summary>
      <table class="sessions-table tr-table"><tbody>${runRows}</tbody></table>
    </details>` : '';

  return `<section class="tr-card${open ? ' is-open' : ''}" data-tool="${_trEsc(tool.tool)}">
    <button type="button" class="tr-card-head" data-toggle="${_trEsc(tool.tool)}" aria-expanded="${open}">
      <span class="tr-caret" aria-hidden="true">${open ? '▾' : '▸'}</span>
      <span class="tr-name">${_trEsc(tool.label)}</span>
      <span class="tr-headline${tool.total_rows || !tool.parsed ? '' : ' is-empty'}">${_trEsc(tool.headline)}</span>
      <span class="fx-grow"></span>
      <span class="tr-meta">${tool.total_runs} run${tool.total_runs === 1 ? '' : 's'} · last ${_trEsc(last.text)}</span>
    </button>
    ${open ? `<div class="tr-card-body">
      <div class="tr-purpose">
        <span>${_trEsc(tool.purpose)}</span>
        <button type="button" class="empty-action" data-steer="${_trEsc(tool.tool)}">Steer Smith on this</button>
      </div>
      ${results}${runsBlock}
    </div>` : ''}
  </section>`;
}

function renderToolResults() {
  const wrap = document.getElementById('tr-cards');
  if (!wrap || !_trData) return;
  const tools = _trData.tools || [];
  const q = _trQuery.trim().toLowerCase();
  _trOverview(_trData.overview || {});
  const summary = document.getElementById('tr-summary');
  if (!tools.length) {
    if (summary) summary.textContent = '';
    wrap.innerHTML = '<div class="empty-placeholder">No tools have run yet. Each tool Smith runs gets a card here with what it found.</div>';
    return;
  }
  // First visit: open the recon tools that have results, so the page is useful at a glance.
  const open = _trLoadOpen();
  let firstVisit = false;
  try { firstVisit = localStorage.getItem(_TR_OPEN_KEY) === null; } catch (e) { firstVisit = false; }
  if (firstVisit) {
    tools.filter(t => t.parsed && t.total_rows && t.base_tool !== 'http_request').slice(0, 4).forEach(t => open.add(t.tool));
    _trSaveOpen();
  }
  const html = tools.map(t => _trCard(t, q)).join('');
  if (summary) summary.textContent = `${tools.length} tool${tools.length === 1 ? '' : 's'} · ${_trData.total_runs || 0} runs`;
  wrap.innerHTML = html || '<div class="empty-placeholder">Nothing matches this search. <button type="button" class="runs-clear-btn" data-action="tr-clear">Clear search</button></div>';
  const btn = document.getElementById('tr-expand');
  if (btn) btn.textContent = tools.every(t => open.has(t.tool)) ? 'Collapse all' : 'Expand all';
}

async function pollToolResults() {
  try {
    const r = await fetch('/api/tool-results?_=' + Date.now());
    if (!r.ok) return;
    const data = await r.json();
    // Re-render only when something changed, so open tables do not flicker and
    // a selection or scroll position inside a card is not lost every 5 seconds.
    const sig = JSON.stringify([(data.tools || []).map(t => [t.tool, t.total_runs, t.total_rows, t.last_run]), data.overview]);
    _trData = data;
    if (sig === _trSig) return;
    _trSig = sig;
    renderToolResults();
  } catch (e) { /* keep the last good data */ }
}

function resetToolResults() {
  _trData = { overview: {}, tools: [], total_runs: 0 };
  _trSig = '';
  renderToolResults();
}

function toggleAllToolCards() {
  if (!_trData) return;
  const open = _trLoadOpen();
  const tools = _trData.tools || [];
  const all = tools.every(t => open.has(t.tool));
  tools.forEach(t => { if (all) open.delete(t.tool); else open.add(t.tool); });
  _trSaveOpen();
  renderToolResults();
}

// Pre-fill the instruction box with what the operator was just looking at.
function steerOnTool(toolKey) {
  const tool = ((_trData || {}).tools || []).find(t => t.tool === toolKey);
  if (!tool) return;
  const text = `About the ${tool.label} results (${tool.headline}): `;
  if (typeof askSmith === 'function') askSmith(text);
  const inp = document.getElementById('cmd-smith-input');
  if (inp) { inp.focus(); try { inp.setSelectionRange(text.length, text.length); } catch (e) { /* ignore */ } }
}

async function showToolRaw(artifactId) {
  const dlg = document.getElementById('tr-raw-dialog');
  const text = document.getElementById('tr-raw-text');
  const meta = document.getElementById('tr-raw-meta');
  if (!dlg || !text) return;
  text.textContent = 'Loading…';
  if (meta) meta.textContent = artifactId;
  if (typeof dlg.showModal === 'function' && !dlg.open) dlg.showModal();
  try {
    const r = await fetch('/api/tool-results/raw?id=' + encodeURIComponent(artifactId));
    const doc = await r.json();
    if (!r.ok) { text.textContent = 'This output is no longer available.'; return; }
    text.textContent = doc.text || '(empty output)';
    if (meta) meta.textContent = `${doc.artifact_id} · ${new Date(doc.time).toLocaleString()} · ${doc.size} bytes` +
      (doc.truncated ? ' · truncated' : '') + ' · secrets are masked';
  } catch (e) { text.textContent = 'Could not load the output.'; }
}

(function _wireToolResults() {
  const tab = document.getElementById('tab-activity');
  if (tab) tab.addEventListener('click', ev => {
    const t = ev.target;
    const raw = t.closest && t.closest('[data-raw]');
    if (raw) { showToolRaw(raw.getAttribute('data-raw')); return; }
    const steer = t.closest && t.closest('[data-steer]');
    if (steer) { steerOnTool(steer.getAttribute('data-steer')); return; }
    if (t.closest && t.closest('[data-action="tr-clear"]')) {
      _trQuery = ''; const s = document.getElementById('tr-search'); if (s) s.value = '';
      renderToolResults(); return;
    }
    const head = t.closest && t.closest('[data-toggle]');
    if (head) {
      const key = head.getAttribute('data-toggle');
      const open = _trLoadOpen();
      if (open.has(key)) open.delete(key); else open.add(key);
      _trSaveOpen();
      renderToolResults();
    }
  });
  const search = document.getElementById('tr-search');
  if (search) search.addEventListener('input', () => { _trQuery = search.value; renderToolResults(); });
  const dlg = document.getElementById('tr-raw-dialog');
  if (dlg) dlg.addEventListener('click', ev => { if (ev.target === dlg) dlg.close(); });
})();
