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
  const current = _sessStorageGet(_DASH_TOKEN_KEY);
  if (current) _sessStorageSet(_OPERATOR_TOKEN_KEY, current, true);
  return current;
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

function selectRun(runId) {
  const token = _runTokenMap()[runId] || '';
  if (!token) {
    if (typeof _notify === 'function') _notify('Run token unavailable', 'Start or open this run from its dashboard URL to select it.');
    return;
  }
  try { localStorage.setItem('smith_selected_run_id', runId); } catch (e) { /* ignore */ }
  _sessStorageSet(_RUN_TOKEN_KEY, token, true);
  _sessStorageSet(_DASH_TOKEN_KEY, token, false);
  pollSessions();
}

async function startRunFromForm(ev) {
  if (ev && ev.preventDefault) ev.preventDefault();
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
  const status = document.getElementById('start-run-status');
  if (status) status.textContent = 'Starting…';
  try {
    const r = await fetch('/api/runs', {
      method: 'POST',
      headers: Object.assign({ 'Content-Type': 'application/json' }, _headersFor(_operatorToken())),
      body: JSON.stringify(body),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) {
      if (status) status.textContent = data.error || 'Run creation failed';
      return;
    }
    _rememberRunToken(data.run_id, data.token);
    selectRun(data.run_id);
    if (status) status.textContent = 'Run started: ' + data.run_id;
  } catch (e) {
    if (status) status.textContent = 'Run creation failed';
  }
}

function _renderRuns(rows) {
  const out = document.getElementById('runs-output') || document.getElementById('sessions-output');
  const selected = _selectedRunId();
  if (!out) return;
  if (!rows.length) {
    out.innerHTML = '<div class="empty-placeholder">No runs yet.</div>';
    return;
  }
  const tokens = _runTokenMap();
  const body = rows.map(r => {
    const active = r.run_id === selected ? ' <span class="badge-cur">SELECTED</span>' : '';
    const selectable = tokens[r.run_id] ? '' : ' disabled';
    return `<tr class="sess-row${r.run_id === selected ? ' sess-new' : ''}">
      <td><span class="badge-op">RUN</span>${active}</td>
      <td>${_sessEsc(r.target || '—')}</td>
      <td><span class="sess-status sess-${_sessEsc(r.status)}">${_sessEsc(r.status || 'unknown')}</span></td>
      <td>${_sessEsc(r.depth || '—')}</td>
      <td class="sess-id">${_sessEsc((r.run_id || '').slice(0, 12))}</td>
      <td><button type="button" onclick="selectRun('${_sessEsc(r.run_id)}')"${selectable}>Select</button></td>
    </tr>`;
  }).join('');
  out.innerHTML = `<table class="sessions-table">
    <thead><tr><th>Type</th><th>Target</th><th>Status</th><th>Depth</th><th>Run ID</th><th></th></tr></thead>
    <tbody>${body}</tbody></table>`;
}

async function pollSessions() {
  let rows = [];
  try {
    const r = await fetch('/api/runs?_=' + Date.now(), { headers: _headersFor(_operatorToken()) });
    if (!r.ok) return;
    rows = await r.json();
    if (!Array.isArray(rows)) rows = [];
  } catch (e) { return; }

  const summary = document.getElementById('sessions-summary');
  if (summary) {
    const selected = _selectedRunId() || 'none';
    summary.textContent = `${rows.length} run${rows.length === 1 ? '' : 's'} · selected: ${selected}`;
  }
  _renderRuns(rows);
  _sessionsInit = true;
}

try {
  document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('start-run-form');
    if (form) form.addEventListener('submit', startRunFromForm);
  });
} catch (e) { /* ignore */ }
