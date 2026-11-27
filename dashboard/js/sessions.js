// ── Runs / Sessions tab ──────────────────────────────────────────────────────
// Platform mode manages run creation and selection through /api/runs. The
// operator token is kept separately so the selected per-run token can scope the
// rest of the dashboard without losing the ability to list/start/stop runs.

let _sessionsSeen = null;        // kept for backwards-compatible globals used by older tabs
let _sessionsInit = false;
const _RUN_TOKEN_KEY = 'smith_selected_run_token';
const _RUN_TOKEN_MAP_KEY = 'smith_run_tokens';
const _OPERATOR_TOKEN_KEY = 'smith_operator_token';
const _DASH_TOKEN_KEY = 'smith_dash_token';
const selectedRunToken = 'selected-run-token';
const _GOTO_TAB_KEY = 'smith_goto_tab';

function _sessEsc(s) {
  return String(s == null ? '' : s).replace(/[&<>"]/g,
    c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

function _sessStorageGet(key) {
  try { return sessionStorage.getItem(key) || localStorage.getItem(key) || ''; }
  catch (e) { return ''; }
}

function _sessStorageSet(key, value, persist) {
  try { sessionStorage.setItem(key, value || ''); } catch (e) { /* ignore */ }
  if (persist) {
    try { localStorage.setItem(key, value || ''); } catch (e) { /* ignore */ }
  }
}

function _operatorToken() {
  const existing = _sessStorageGet(_OPERATOR_TOKEN_KEY);
  if (existing) return existing;
  // No operator token known: fall back to the page's current token for this
  // call only. It is NOT remembered as the operator token — it may be a
  // run-scoped one; _resolveControlPlane() stores a token only once the server
  // has confirmed its role.
  return _sessStorageGet(_DASH_TOKEN_KEY);
}

function _runTokenMap() {
  try { return JSON.parse(localStorage.getItem(_RUN_TOKEN_MAP_KEY) || '{}') || {}; }
  catch (e) { return {}; }
}

function _rememberRunToken(runId, token) {
  if (!runId || !token) return;
  const tokens = _runTokenMap();
  tokens[runId] = token;
  try { localStorage.setItem(_RUN_TOKEN_MAP_KEY, JSON.stringify(tokens)); } catch (e) { /* ignore */ }
}

function _headersFor(token) {
  return token ? { 'Authorization': 'Bearer ' + token } : {};
}

function _selectedRunId() {
  try { return localStorage.getItem('smith_selected_run_id') || ''; }
  catch (e) { return ''; }
}

function _setSelectedRunId(runId) {
  try {
    if (runId) localStorage.setItem('smith_selected_run_id', runId);
    else localStorage.removeItem('smith_selected_run_id');
  } catch (e) { /* ignore */ }
}

// ── Control-plane mode ───────────────────────────────────────────────────────
// The dashboard runs in one of three modes, decided by GET /api/control-plane:
//   * platform  — operator token + database: scans are started/selected here,
//                 and the other tabs are GATED until a scan is selected.
//   * classic   — operator token, no database (single scan driven from the
//                 client): nothing is gated, the tabs show the one scan.
//   * run-view  — a run-scoped link: the viewer sees that one scan, no switcher.
let _cpMeta = null;              // {enabled, role, run_id} for the operator token, or null until probed
let _cpGated = false;

async function _probeToken(token) {
  if (!token) return null;
  try {
    const r = await fetch('/api/control-plane', { headers: _headersFor(token) });
    if (!r.ok) return null;
    return await r.json();
  } catch (e) { return null; }
}

// Work out which stored token (if any) is an operator token. The token the page
// was just opened with wins over a remembered one, so a fresh `smith start` link
// replaces a stale operator token instead of being shadowed by it.
async function _resolveControlPlane() {
  const current = _sessStorageGet(_DASH_TOKEN_KEY);
  let stored = '';
  try { stored = localStorage.getItem(_OPERATOR_TOKEN_KEY) || sessionStorage.getItem(_OPERATOR_TOKEN_KEY) || ''; }
  catch (e) { stored = ''; }

  const currentMeta = await _probeToken(current);
  if (currentMeta && currentMeta.role === 'operator') {
    if (current !== stored) _sessStorageSet(_OPERATOR_TOKEN_KEY, current, true);
    _cpMeta = currentMeta;
    return _cpMeta;
  }
  // Opened through a run-scoped link: adopt that run as the selected one.
  if (currentMeta && currentMeta.role === 'run' && currentMeta.run_id) {
    _rememberRunToken(currentMeta.run_id, current);
    _setSelectedRunId(currentMeta.run_id);
  }
  const storedMeta = (stored && stored !== current) ? await _probeToken(stored) : null;
  if (storedMeta && storedMeta.role === 'operator') {
    _cpMeta = storedMeta;
    return _cpMeta;
  }
  _cpMeta = currentMeta || { enabled: false, role: '', run_id: '' };
  return _cpMeta;
}

function _isOperator() { return !!(_cpMeta && _cpMeta.role === 'operator'); }
function _platformMode() { return _isOperator() && !!_cpMeta.enabled; }

function _currentTab() {
  try { return (typeof _activeTab === 'string' && _activeTab) || 'findings'; }
  catch (e) { return 'findings'; }
}

// Gate / un-gate the dashboard. Gated = no scan selected in platform mode: the
// Scans page becomes the landing page and every other tab is locked (styling is
// driven by the body class; see "scan-gated" in dashboard.css).
function _setGated(gated) {
  _cpGated = !!gated;
  document.body.classList.toggle('scan-gated', _cpGated);
  _placeStartRunForm();
  if (_cpGated && _currentTab() !== 'sessions') {
    try { _origSwitchTab('sessions'); } catch (e) { /* shell not ready */ }
  }
}

// Wrap the shell's switchTab so a locked tab bounces back to the landing page.
let _origSwitchTab = null;
try {
  _origSwitchTab = switchTab;
  switchTab = function (name) {                       // eslint-disable-line no-global-assign
    if (_cpGated && name !== 'sessions') {
      _origSwitchTab('sessions');
      const hint = document.getElementById('scan-landing-hint');
      if (hint) {
        hint.classList.remove('is-flash');
        void hint.offsetWidth;                        // restart the CSS animation
        hint.classList.add('is-flash');
      }
      return;
    }
    return _origSwitchTab(name);
  };
} catch (e) { /* common.js not loaded (standalone page) */ }

function _forgetRunToken(runId) {
  const tokens = _runTokenMap();
  delete tokens[runId];
  try { localStorage.setItem(_RUN_TOKEN_MAP_KEY, JSON.stringify(tokens)); } catch (e) { /* ignore */ }
}

// Tokens verified against the server during this page load (never trust a
// remembered token blindly: after a database reset the same scan ID can exist
// again with different tokens, and a stale one 401s every request).
const _verifiedRunTokens = {};

async function _tokenForRun(runId) {
  const cached = _runTokenMap()[runId] || '';
  if (cached) {
    if (_verifiedRunTokens[runId] === cached) return cached;
    const meta = await _probeToken(cached);
    if (meta && meta.role === 'run' && meta.run_id === runId) {
      _verifiedRunTokens[runId] = cached;
      return cached;
    }
    _forgetRunToken(runId);                 // stale — mint a fresh one below
  }
  const operatorToken = _operatorToken();
  if (!operatorToken) return '';
  const r = await fetch('/api/runs/' + encodeURIComponent(runId) + '/token', {
    method: 'POST',
    headers: _headersFor(operatorToken),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || 'Run token unavailable');
  if (data.token) { _rememberRunToken(runId, data.token); _verifiedRunTokens[runId] = data.token; }
  return data.token || '';
}

// Scope the dashboard to one scan. Every tab keeps its own cached state for the
// scan it was showing, so the reliable way to switch is to swap the token and
// reload: the page comes back authenticated as that scan, on `opts.tab`.
//   opts.tab     — tab to land on (default: Findings when leaving the Scans
//                  page, otherwise the tab the operator is already on)
async function selectRun(runId, opts) {
  opts = opts || {};
  if (!runId) return;
  let token = '';
  try {
    token = await _tokenForRun(runId);
  } catch (e) {
    if (typeof _notify === 'function') _notify('Run token unavailable', e.message || 'Could not select this run.');
    return;
  }
  if (!token) {
    if (typeof _notify === 'function') _notify('Run token unavailable', 'Start or open this run from its dashboard URL to select it.');
    return;
  }
  const alreadyScoped = _selectedRunId() === runId && _sessStorageGet(_DASH_TOKEN_KEY) === token && !_cpGated;
  const here = _currentTab();
  const tab = opts.tab || (here === 'sessions' ? 'findings' : here);
  _setSelectedRunId(runId);
  _sessStorageSet(_RUN_TOKEN_KEY, token, true);
  _sessStorageSet(_DASH_TOKEN_KEY, token, false);
  if (alreadyScoped) {
    try { switchTab(tab); } catch (e) { /* ignore */ }
    return;
  }
  try { sessionStorage.setItem(_GOTO_TAB_KEY, tab); } catch (e) { /* ignore */ }
  location.reload();
}

// Leave the selected scan and return to the landing page.
function deselectRun() {
  _setSelectedRunId('');
  const op = _operatorToken();
  if (op) _sessStorageSet(_DASH_TOKEN_KEY, op, false);
  try { sessionStorage.setItem(_GOTO_TAB_KEY, 'sessions'); } catch (e) { /* ignore */ }
  location.reload();
}

// ── New Scan dialog ──────────────────────────────────────────────────────────
let _startRunBusy = false;

// The one start form has two homes: inline on the landing page (no scan
// selected yet) and inside the dialog (opened from the top bar on any tab).
function _placeStartRunForm() {
  const form = document.getElementById('start-run-form');
  if (!form) return;
  const dlg = document.getElementById('start-run-dialog');
  const inline = document.getElementById('start-run-inline-slot');
  const dialogSlot = document.getElementById('start-run-dialog-slot');
  const wantInline = _cpGated && inline && !(dlg && dlg.open);
  const home = wantInline ? inline : dialogSlot;
  if (home && form.parentElement !== home) home.appendChild(form);
}

function openNewScanDialog() {
  const status = document.getElementById('start-run-status');
  if (status) { status.textContent = ''; status.classList.remove('is-error'); }
  const target = document.getElementById('start-run-target');
  // On the landing page the form is already on screen — just go to it.
  if (_cpGated && _currentTab() === 'sessions') {
    _placeStartRunForm();
    if (target) { target.focus(); try { target.scrollIntoView({ block: 'center' }); } catch (e) { /* ignore */ } }
    return;
  }
  const dlg = document.getElementById('start-run-dialog');
  if (!dlg) return;
  const dialogSlot = document.getElementById('start-run-dialog-slot');
  const form = document.getElementById('start-run-form');
  if (form && dialogSlot && form.parentElement !== dialogSlot) dialogSlot.appendChild(form);
  if (typeof dlg.showModal === 'function') {
    if (!dlg.open) dlg.showModal();
  } else {
    dlg.setAttribute('open', '');   // very old browsers: non-modal fallback
  }
  if (target) target.focus();
}

function closeNewScanDialog() {
  const dlg = document.getElementById('start-run-dialog');
  if (!dlg) return;
  if (typeof dlg.close === 'function' && dlg.open) dlg.close();
  else dlg.removeAttribute('open');
}

// Turn an /api/runs failure into something the operator can act on.
function _startRunError(httpStatus, data) {
  if (httpStatus === 401 || httpStatus === 403) {
    return 'Starting scans needs the operator link — open the dashboard URL printed by `smith start`.';
  }
  if (httpStatus === 503) {
    return 'The control plane database is not running. Start it with `smith start`, then try again.';
  }
  return (data && data.error) || 'Could not start the scan.';
}

async function startRunFromForm(ev) {
  if (ev && ev.preventDefault) ev.preventDefault();
  if (_startRunBusy) return;
  const target = (document.getElementById('start-run-target') || {}).value || '';
  const depth = (document.getElementById('start-run-depth') || {}).value || 'standard';
  const scopeText = (document.getElementById('start-run-scope') || {}).value || '';
  const outText = (document.getElementById('start-run-out-of-scope') || {}).value || '';
  const splitLines = s => s.split(/\n|,/).map(x => x.trim()).filter(Boolean);
  const body = {
    target: target.trim(),
    depth: depth,
    scope: splitLines(scopeText),
    out_of_scope: splitLines(outText),
  };
  const source = (document.getElementById('start-run-source') || {}).value || '';
  if (source) body.source = source;
  const status = document.getElementById('start-run-status');
  const setStatus = (text, isError) => {
    if (!status) return;
    status.textContent = text;
    status.classList.toggle('is-error', !!isError);
  };
  if (!body.target) { setStatus('Enter a target.', true); return; }
  _startRunBusy = true;
  setStatus('Starting…', false);
  try {
    const r = await fetch('/api/runs', {
      method: 'POST',
      headers: Object.assign({ 'Content-Type': 'application/json' }, _headersFor(_operatorToken())),
      body: JSON.stringify(body),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) {
      setStatus(_startRunError(r.status, data), true);
      return;
    }
    _rememberRunToken(data.run_id, data.token);
    setStatus('Scan started — opening it…', false);
    const form = document.getElementById('start-run-form');
    if (form && typeof form.reset === 'function') form.reset();
    closeNewScanDialog();
    // A filter left over from earlier must not hide the new scan later.
    _runFilters = Object.assign({}, _RUN_FILTER_DEFAULTS, { sort: _runFilters.sort });
    _saveRunFilters();
    // Scope the dashboard to the new scan and continue on the scan pages.
    await selectRun(data.run_id, { tab: 'findings' });
  } catch (e) {
    setStatus('Could not reach the dashboard server.', true);
  } finally {
    _startRunBusy = false;
  }
}

// ── Scan list: filters ───────────────────────────────────────────────────────
// Filtering is client-side over the last /api/runs response, so it is instant
// and survives the periodic re-poll. Filter state persists in localStorage.
const _RUN_FILTER_KEY = 'smith_run_filters';
const _RUN_FILTER_DEFAULTS = { q: '', status: '', depth: '', sort: 'newest' };
let _runsCache = [];
let _runFilters = _loadRunFilters();

function _loadRunFilters() {
  let saved = {};
  try { saved = JSON.parse(localStorage.getItem(_RUN_FILTER_KEY) || '{}') || {}; }
  catch (e) { saved = {}; }
  const out = Object.assign({}, _RUN_FILTER_DEFAULTS);
  for (const k of Object.keys(out)) {
    if (typeof saved[k] === 'string') out[k] = saved[k];
  }
  return out;
}

function _saveRunFilters() {
  try { localStorage.setItem(_RUN_FILTER_KEY, JSON.stringify(_runFilters)); }
  catch (e) { /* private mode — filters just won't persist */ }
}

function _runFiltersActive() {
  return !!(_runFilters.q || _runFilters.status || _runFilters.depth);
}

function setRunFilter(key, value) {
  if (!(key in _RUN_FILTER_DEFAULTS)) return;
  _runFilters[key] = String(value == null ? '' : value);
  _saveRunFilters();
  _renderRunsView();
}

function clearRunFilters() {
  _runFilters = Object.assign({}, _RUN_FILTER_DEFAULTS, { sort: _runFilters.sort });
  _saveRunFilters();
  _syncRunFilterControls();
  _renderRunsView();
}

function _syncRunFilterControls() {
  const set = (id, value) => {
    const el = document.getElementById(id);
    if (el && el.value !== value) el.value = value;
  };
  set('runs-filter-q', _runFilters.q);
  set('runs-filter-depth', _runFilters.depth);
  set('runs-filter-sort', _runFilters.sort);
}

function _runStatus(r) { return String((r && r.status) || 'unknown').toLowerCase(); }

function _applyRunFilters(rows) {
  const q = _runFilters.q.trim().toLowerCase();
  const filtered = rows.filter(r => {
    if (_runFilters.status && _runStatus(r) !== _runFilters.status) return false;
    if (_runFilters.depth && String(r.depth || '') !== _runFilters.depth) return false;
    if (q) {
      const hay = (String(r.target || '') + ' ' + String(r.run_id || '')).toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
  const by = (key) => (a, b) => String(a[key] || '').localeCompare(String(b[key] || ''));
  switch (_runFilters.sort) {
    case 'oldest':  filtered.sort(by('created_at')); break;
    case 'updated': filtered.sort(by('updated_at')).reverse(); break;
    case 'target':  filtered.sort(by('target')); break;
    default:        filtered.sort(by('created_at')).reverse();
  }
  return filtered;
}

function _renderStatusChips(rows) {
  const box = document.getElementById('runs-status-chips');
  if (!box) return;
  const counts = {};
  for (const r of rows) counts[_runStatus(r)] = (counts[_runStatus(r)] || 0) + 1;
  // Keep the active status visible even when no scan currently has it, so the
  // operator can see (and clear) the filter that is hiding everything.
  if (_runFilters.status && !(_runFilters.status in counts)) counts[_runFilters.status] = 0;
  const statuses = Object.keys(counts).sort();
  if (!rows.length && !_runFilters.status) { box.innerHTML = ''; return; }
  const chip = (value, label, n) =>
    `<button type="button" class="runs-chip${_runFilters.status === value ? ' active' : ''}"
       data-status="${_sessEsc(value)}" aria-pressed="${_runFilters.status === value}">${_sessEsc(label)}
       <span class="runs-chip-n">${n}</span></button>`;
  box.innerHTML = chip('', 'All', rows.length) + statuses.map(s => chip(s, s, counts[s])).join('');
}

function _fmtRunTime(iso) {
  if (!iso) return { text: '—', title: '' };
  const d = new Date(iso);
  if (isNaN(d.getTime())) return { text: '—', title: '' };
  const secs = Math.max(0, Math.round((Date.now() - d.getTime()) / 1000));
  let text;
  if (secs < 60) text = 'just now';
  else if (secs < 3600) text = Math.floor(secs / 60) + ' min ago';
  else if (secs < 86400) text = Math.floor(secs / 3600) + ' h ago';
  else text = d.toLocaleDateString();
  return { text: text, title: d.toLocaleString() };
}

function _renderRuns(rows, total) {
  const out = document.getElementById('runs-output') || document.getElementById('sessions-output');
  const selected = _selectedRunId();
  if (!out) return;
  if (!total) {
    out.innerHTML = '<div class="empty-placeholder">No scans yet.</div>';
    return;
  }
  if (!rows.length) {
    out.innerHTML = '<div class="empty-placeholder">No scans match these filters. ' +
      '<button type="button" class="runs-clear-btn" data-action="clear-filters">Clear filters</button></div>';
    return;
  }
  const body = rows.map(r => {
    const isSel = r.run_id === selected;
    const st = _runStatus(r);
    const started = _fmtRunTime(r.created_at);
    return `<tr class="sess-row${isSel ? ' sess-new' : ''}" data-run-id="${_sessEsc(r.run_id)}" title="Open this scan">
      <td class="runs-target">${_sessEsc(r.target || '—')}${isSel ? ' <span class="badge-cur">SELECTED</span>' : ''}</td>
      <td><span class="sess-status sess-${_sessEsc(st)}">${_sessEsc(st)}</span></td>
      <td>${_sessEsc(r.depth || '—')}</td>
      <td title="${_sessEsc(started.title)}">${_sessEsc(started.text)}</td>
      <td class="sess-id">${_sessEsc(r.run_id || '')}</td>
      <td class="runs-actions"><button type="button" class="runs-select-btn" data-run-id="${_sessEsc(r.run_id)}">${isSel ? 'Open' : 'Select'}</button></td>
    </tr>`;
  }).join('');
  out.innerHTML = `<table class="sessions-table">
    <thead><tr><th>Target</th><th>Status</th><th>Depth</th><th>Started</th><th>Scan ID</th><th></th></tr></thead>
    <tbody>${body}</tbody></table>`;
}

// Top-bar scan switcher: one option per scan, newest first.
function _renderScanSwitcher(rows) {
  const sel = document.getElementById('scan-switcher');
  if (!sel) return;
  if (document.activeElement === sel) return;      // don't rebuild under an open menu
  const selected = _selectedRunId();
  const sorted = rows.slice().sort((a, b) => String(b.created_at || '').localeCompare(String(a.created_at || '')));
  const known = sorted.some(r => r.run_id === selected);
  const opts = [];
  if (!known) opts.push(`<option value="">${rows.length ? 'Select a scan…' : 'No scans yet'}</option>`);
  for (const r of sorted) {
    const label = `${r.target || '—'}  ·  ${_runStatus(r)}  ·  ${r.run_id}`;
    opts.push(`<option value="${_sessEsc(r.run_id)}"${r.run_id === selected ? ' selected' : ''}>${_sessEsc(label)}</option>`);
  }
  const html = opts.join('');
  if (sel.dataset.rendered !== html) { sel.innerHTML = html; sel.dataset.rendered = html; }
  const count = document.getElementById('scan-switcher-count');
  if (count) count.textContent = rows.length > 1 ? `${rows.length} scans` : '';
}

function _renderRunsView() {
  const rows = _runsCache;
  const shown = _applyRunFilters(rows);
  _renderStatusChips(rows);
  _renderScanSwitcher(rows);
  const clearBtn = document.getElementById('runs-filter-clear');
  if (clearBtn) clearBtn.hidden = !_runFiltersActive();
  const listBlock = document.getElementById('runs-list-block');
  if (listBlock) listBlock.classList.toggle('is-empty', !rows.length);
  const summary = document.getElementById('sessions-summary');
  if (summary) {
    const noun = rows.length === 1 ? 'scan' : 'scans';
    const count = _runFiltersActive() ? `${shown.length} of ${rows.length} ${noun}` : `${rows.length} ${noun}`;
    summary.textContent = _cpGated ? count : `${count} · selected: ${_selectedRunId() || 'none'}`;
  }
  _renderRuns(shown, rows.length);
}

async function pollSessions() {
  if (!_cpMeta) return;                    // mode not resolved yet — _initControlPlane will call us
  if (!_isOperator()) return;              // run-scoped viewer: no scan list
  let rows = [];
  try {
    const r = await fetch('/api/runs?_=' + Date.now(), { headers: _headersFor(_operatorToken()) });
    if (!r.ok) return;
    rows = await r.json();
    if (!Array.isArray(rows)) rows = [];
  } catch (e) { return; }

  _runsCache = rows;
  if (_platformMode()) {
    // The selected scan must still exist; otherwise fall back to the landing page.
    const selected = _selectedRunId();
    const valid = !!selected && rows.some(r => r.run_id === selected);
    if (!valid && selected) _setSelectedRunId('');
    if (_cpGated !== !valid) _setGated(!valid);
  }
  _renderRunsView();
  _sessionsInit = true;
}

// Decide the mode, then either scope the page to the selected scan or show the
// landing page. Runs once per page load.
async function _initControlPlane() {
  await _resolveControlPlane();
  document.body.classList.toggle('cp-operator', _isOperator());
  document.body.classList.toggle('cp-platform', _platformMode());

  let gotoTab = '';
  try {
    gotoTab = sessionStorage.getItem(_GOTO_TAB_KEY) || '';
    sessionStorage.removeItem(_GOTO_TAB_KEY);
  } catch (e) { gotoTab = ''; }

  if (!_platformMode()) {
    _setGated(false);
    await pollSessions();
    if (gotoTab) { try { switchTab(gotoTab); } catch (e) { /* ignore */ } }
    return;
  }

  await pollSessions();                    // sets/clears the gate from the live scan list
  if (_cpGated) {
    // Nothing selected: make sure API calls carry the operator token again.
    const op = _operatorToken();
    if (op && _sessStorageGet(_DASH_TOKEN_KEY) !== op) _sessStorageSet(_DASH_TOKEN_KEY, op, false);
    return;
  }
  // A scan is selected. If the page was opened with the operator link, the data
  // tabs are not scoped to it yet — swap in the scan's token (reloads once).
  const selected = _selectedRunId();
  let token = '';
  try { token = await _tokenForRun(selected); } catch (e) { token = ''; }
  if (token && _sessStorageGet(_DASH_TOKEN_KEY) !== token) {
    await selectRun(selected, { tab: gotoTab || _currentTab() });
    return;
  }
  if (gotoTab) { try { switchTab(gotoTab); } catch (e) { /* ignore */ } }
}

// Fill the Source picker (Advanced options) from the Source registry.
async function _loadSources() {
  const sel = document.getElementById('start-run-source');
  const hint = document.getElementById('start-run-source-hint');
  if (!sel) return;
  let sources = [];
  try {
    const r = await fetch('/api/sources', { headers: _headersFor(_operatorToken()) });
    if (r.ok) sources = (await r.json()).sources || [];
  } catch (e) { sources = []; }
  const keep = sel.value;
  sel.innerHTML = '<option value="">None</option>' + sources.map(s =>
    `<option value="${_sessEsc(s.name)}">${_sessEsc(s.name)}</option>`).join('');
  if (sources.some(s => s.name === keep)) sel.value = keep;
  if (hint) hint.textContent = sources.length ? '' : 'No Sources are registered yet. Add one to sources.yaml to use this.';
}

function _initScansTab() {
  const form = document.getElementById('start-run-form');
  if (form) form.addEventListener('submit', startRunFromForm);

  const dlg = document.getElementById('start-run-dialog');
  if (dlg) {
    // Click on the backdrop (the <dialog> element itself) closes it.
    dlg.addEventListener('click', ev => { if (ev.target === dlg) closeNewScanDialog(); });
    dlg.addEventListener('close', _placeStartRunForm);
  }

  const switcher = document.getElementById('scan-switcher');
  if (switcher) switcher.addEventListener('change', () => {
    const id = switcher.value;
    switcher.blur();
    if (id) selectRun(id);
  });

  _syncRunFilterControls();
  const q = document.getElementById('runs-filter-q');
  if (q) q.addEventListener('input', () => setRunFilter('q', q.value));
  const depth = document.getElementById('runs-filter-depth');
  if (depth) depth.addEventListener('change', () => setRunFilter('depth', depth.value));
  const sort = document.getElementById('runs-filter-sort');
  if (sort) sort.addEventListener('change', () => setRunFilter('sort', sort.value));
  const clear = document.getElementById('runs-filter-clear');
  if (clear) clear.addEventListener('click', clearRunFilters);

  const chips = document.getElementById('runs-status-chips');
  if (chips) chips.addEventListener('click', ev => {
    const btn = ev.target.closest && ev.target.closest('.runs-chip');
    if (btn) setRunFilter('status', btn.getAttribute('data-status') || '');
  });

  // Delegated so run IDs never get interpolated into inline handlers.
  const out = document.getElementById('runs-output');
  if (out) out.addEventListener('click', ev => {
    const t = ev.target;
    if (t.closest && t.closest('[data-action="clear-filters"]')) { clearRunFilters(); return; }
    const row = t.closest && t.closest('[data-run-id]');
    if (row) selectRun(row.getAttribute('data-run-id'), { tab: 'findings' });
  });

  _initControlPlane().then(() => { if (_isOperator()) _loadSources(); });
}

// Avoid a flash of the (empty) Findings tab on the landing page: if this browser
// already holds an operator token and no scan is selected, gate before the first
// paint; _initControlPlane() confirms or lifts it once the server has answered.
try {
  let _storedOp = '';
  try { _storedOp = localStorage.getItem(_OPERATOR_TOKEN_KEY) || ''; } catch (e) { _storedOp = ''; }
  if (_storedOp && !_selectedRunId() && document.body) document.body.classList.add('scan-gated');
} catch (e) { /* ignore */ }

try {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', _initScansTab);
  else _initScansTab();
} catch (e) { /* ignore */ }
