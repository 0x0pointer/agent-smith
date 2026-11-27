// ── Platform pages: Home · Scans (live cards) · All findings · Apps ─────────────
// These pages are about ALL scans, so every request here carries the OPERATOR
// token explicitly (the page's default token may be scoped to the open scan).
// Data: GET /api/platform/overview, /api/platform/findings. (The Knowledge page
// is knowledge.js.)
// Also holds the New Scan wizard's step logic (the dialog markup is in
// tabs/sessions.html; the request itself is sent by sessions.js).
//
// Everything rendered here that came from a scan or a notes vault is untrusted:
// it goes through esc(), or sanitizeHtml() for Markdown. IDs are never
// interpolated into inline handlers — clicks are delegated on data-* attributes.

const _PF_SEVS = ['critical', 'high', 'medium', 'low', 'info'];
const _PF_SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
const _PF_STATUS = {
  starting: 'Starting', running: 'Running', idle: 'Idle',
  intervention_required: 'Waiting for you', complete: 'Complete',
  failed: 'Failed', stopped: 'Stopped',
};
const _PF_POLL_MS = 10000;

let _pfOverview = null;          // last /api/platform/overview
let _pfFindings = null;          // last /api/platform/findings (.findings array)
let _pfFindingFilters = { q: '', app: '', run: '', group: 'app', fp: false, sev: '' };
let _pfAppsQuery = '';

function _pfHeaders() {
  return (typeof _headersFor === 'function' && typeof _operatorToken === 'function')
    ? _headersFor(_operatorToken()) : {};
}

async function _pfGet(path) {
  try {
    const r = await fetch(path, { headers: _pfHeaders() });
    const data = await r.json().catch(() => ({}));
    return { ok: r.ok, status: r.status, data: data };
  } catch (e) {
    return { ok: false, status: 0, data: {} };
  }
}

async function _pfPost(path) {
  try {
    const r = await fetch(path, { method: 'POST', headers: _pfHeaders() });
    const data = await r.json().catch(() => ({}));
    return { ok: r.ok, status: r.status, data: data };
  } catch (e) {
    return { ok: false, status: 0, data: {} };
  }
}

function _pfActiveTab() {
  try { return (typeof _activeTab === 'string' && _activeTab) || ''; } catch (e) { return ''; }
}

function _pfAgo(iso) {
  return (typeof _fmtRunTime === 'function') ? _fmtRunTime(iso) : { text: iso || '—', title: '' };
}

// ── Shared with sessions.js ──────────────────────────────────────────────────
function pfRunExtras(runId) {
  const runs = (_pfOverview && _pfOverview.runs) || [];
  return runs.find(r => r.run_id === runId) || null;
}

// The client-driven scan (no control-plane row), shaped like an /api/runs row.
function pfLocalRun() {
  const runs = (_pfOverview && _pfOverview.runs) || [];
  const local = runs.find(r => r.local);
  if (!local) return null;
  return {
    run_id: local.run_id, target: local.target, status: local.status, depth: local.depth,
    created_at: local.created_at, updated_at: local.updated_at,
  };
}

// Severity counts as small pills; zero counts are left out.
function pfSevPills(counts) {
  counts = counts || {};
  const pills = _PF_SEVS.filter(s => counts[s] > 0).map(s =>
    `<span class="pf-sev pf-sev-${s}" title="${counts[s]} ${_PF_SEV_LABEL[s].toLowerCase()}">${counts[s]} ${_PF_SEV_LABEL[s]}</span>`);
  return pills.length ? `<span class="pf-sevs">${pills.join('')}</span>` : '<span class="pf-muted">No findings</span>';
}

function _pfStatusPill(status) {
  const st = String(status || 'unknown').toLowerCase();
  const label = _PF_STATUS[st] || st;
  return `<span class="pf-status pf-st-${esc(st)}">${esc(label)}</span>`;
}

// ── Polling ──────────────────────────────────────────────────────────────────
let _pfPolling = false;

async function pollPlatform() {
  if (typeof _isOperator !== 'function' || !_isOperator()) return;
  if (_pfPolling) return;
  _pfPolling = true;
  try {
    const res = await _pfGet('/api/platform/overview?_=' + Date.now());
    if (res.ok && res.data && Array.isArray(res.data.runs)) _pfOverview = res.data;
    const tab = _pfActiveTab();
    if (_pfFindings === null || tab === 'home' || tab === 'all-findings') {
      const f = await _pfGet('/api/platform/findings?_=' + Date.now());
      if (f.ok && f.data && Array.isArray(f.data.findings)) _pfFindings = f.data.findings;
    }
  } finally {
    _pfPolling = false;
  }
  _pfRenderCurrent();
}

function _pfRenderCurrent() {
  const tab = _pfActiveTab();
  if (tab === 'home') _pfRenderHome();
  if (tab === 'sessions') {
    _pfRenderLive();
    if (typeof _renderRunsView === 'function') _renderRunsView();
  }
  if (tab === 'all-findings') _pfRenderAllFindings();
  if (tab === 'apps') _pfRenderApps();
}

// Called by switchTab() in common.js for every tab change.
function platformOnTab(name) {
  if (name === 'home' || name === 'sessions' || name === 'all-findings' || name === 'apps') {
    _pfRenderCurrent();          // paint from cache at once…
    pollPlatform();              // …then refresh from the server
  }
  if (name === 'knowledge' && typeof kbRefresh === 'function') kbRefresh();   // knowledge.js
}

// ── Scan cards ───────────────────────────────────────────────────────────────
function _pfLiveRuns() {
  const runs = (_pfOverview && _pfOverview.runs) || [];
  return runs.filter(r => r.active || r.status === 'idle');
}

function _pfProgress(run) {
  const cov = run.coverage || {};
  if (!cov.total) return '';
  return `<div class="pf-progress" title="${cov.done} of ${cov.total} checks done">
      <div class="pf-progress-bar" style="width:${Math.max(2, Math.min(100, cov.pct || 0))}%"></div>
    </div>
    <span class="pf-progress-txt">${cov.pct || 0}% of ${cov.total} checks done</span>`;
}

function _pfRunCard(run, compact) {
  const started = _pfAgo(run.created_at);
  const meta = [`Started ${started.text}`, run.depth, run.skill].filter(Boolean).map(esc).join(' · ');
  const needs = (run.needs_you || []).map(n => `<li>${esc(n)}</li>`).join('');
  const id = esc(run.run_id);
  const actions = [`<button type="button" class="btn btn-primary btn-sm" data-pf-action="open-run" data-run-id="${id}">Open</button>`];
  if (!run.local && run.status === 'idle') {
    actions.push(`<button type="button" class="btn btn-secondary btn-sm" data-pf-action="resume-run" data-run-id="${id}">Resume</button>`);
  }
  if (!run.local && !compact) {
    actions.push(`<button type="button" class="btn btn-danger btn-sm" data-pf-action="stop-run" data-run-id="${id}">Stop</button>`);
  }
  return `<article class="pf-run${compact ? ' pf-run-compact' : ''}${needs ? ' pf-run-needs' : ''}">
    <header class="pf-run-head">
      ${_pfStatusPill(run.status)}
      <span class="pf-run-id">${run.whitebox ? '<span class="pf-tag pf-tag-wb">white-box</span> ' : ''}${id}</span>
    </header>
    <h4 class="pf-run-target" title="${esc(run.target)}">${esc(run.target || '—')}</h4>
    <p class="pf-run-meta" title="${esc(started.title)}">${meta}</p>
    ${_pfProgress(run)}
    <div class="pf-run-findings">${pfSevPills(run.findings)}</div>
    ${needs ? `<ul class="pf-run-needs-list">${needs}</ul>` : ''}
    <footer class="pf-run-actions">${actions.join('')}</footer>
  </article>`;
}

function _pfRenderLive() {
  const box = document.getElementById('pf-live-cards');
  if (!box) return;
  const count = document.getElementById('pf-live-count');
  if (!_pfOverview) { box.innerHTML = '<div class="empty-placeholder">Loading…</div>'; return; }
  const live = _pfLiveRuns();
  if (count) count.textContent = live.length ? String(live.length) : '';
  box.innerHTML = live.length
    ? live.map(r => _pfRunCard(r, false)).join('')
    : `<div class="pf-empty">
         <p>No scan is running right now.</p>
         <button type="button" class="btn btn-primary btn-sm" data-pf-action="new-scan">Start a scan</button>
       </div>`;
}

// ── Home ─────────────────────────────────────────────────────────────────────
function _pfKpi(label, value, hint, tone, tab) {
  return `<button type="button" class="pf-kpi${tone ? ' pf-kpi-' + tone : ''}" data-pf-action="goto" data-tab="${esc(tab)}">
    <span class="pf-kpi-value">${esc(value)}</span>
    <span class="pf-kpi-label">${esc(label)}</span>
    <span class="pf-kpi-hint">${esc(hint)}</span>
  </button>`;
}

function _pfFindingRow(f, showApp) {
  const when = _pfAgo(f.timestamp);
  return `<button type="button" class="pf-frow" data-pf-action="open-finding"
      data-finding-id="${esc(f.id)}" data-run-id="${esc(f.run_id)}">
    <span class="pf-sev pf-sev-${esc(f.severity)}">${esc(_PF_SEV_LABEL[f.severity] || f.severity)}</span>
    <span class="pf-frow-main">
      <span class="pf-frow-title">${esc(f.title)}${f.status === 'false_positive' ? ' <span class="pf-tag">false positive</span>' : ''}</span>
      <span class="pf-frow-target">${esc(f.target || f.run_target || '')}</span>
    </span>
    ${showApp ? `<span class="pf-frow-app">${esc(f.app)}</span>` : ''}
    <span class="pf-frow-time" title="${esc(when.title)}">${esc(when.text)}</span>
  </button>`;
}

function _pfRenderHome() {
  const kpis = document.getElementById('pf-kpis');
  if (!kpis) return;
  if (!_pfOverview) return;
  const t = _pfOverview.totals || {};
  const f = t.findings || {};
  const serious = (f.critical || 0) + (f.high || 0);
  kpis.innerHTML = [
    _pfKpi('Active scans', t.active || 0, `${t.scans || 0} in total`, t.active ? 'good' : '', 'sessions'),
    _pfKpi('Need you', t.needs_you || 0, t.needs_you ? 'Scans waiting for you' : 'Nothing is waiting', t.needs_you ? 'warn' : '', 'sessions'),
    _pfKpi('Open findings', f.total || 0, serious ? `${f.critical || 0} critical · ${f.high || 0} high` : 'None critical or high', serious ? 'bad' : '', 'all-findings'),
    _pfKpi('Apps tested', t.apps || 0, 'Grouped by host', '', 'apps'),
  ].join('');

  const running = document.getElementById('pf-home-running');
  if (running) {
    const live = _pfLiveRuns().slice(0, 4);
    running.innerHTML = live.length
      ? live.map(r => _pfRunCard(r, true)).join('')
      : '<div class="pf-empty"><p>No scan is running. Enter a target above to start one.</p></div>';
  }

  const needs = document.getElementById('pf-home-needs');
  if (needs) {
    const waiting = (_pfOverview.runs || []).filter(r => (r.needs_you || []).length);
    needs.innerHTML = waiting.length
      ? waiting.map(r => `<button type="button" class="pf-need" data-pf-action="open-run" data-run-id="${esc(r.run_id)}">
            <span class="pf-need-target">${esc(r.target || r.run_id)}</span>
            <span class="pf-need-why">${r.needs_you.map(esc).join(' · ')}</span>
          </button>`).join('')
      : '<div class="pf-empty"><p>Nothing needs you right now.</p></div>';
  }

  const latest = document.getElementById('pf-home-findings');
  if (latest) {
    const open = (_pfFindings || []).filter(x => x.status !== 'false_positive').slice(0, 6);
    latest.innerHTML = open.length
      ? open.map(x => _pfFindingRow(x, true)).join('')
      : '<div class="pf-empty"><p>No findings yet. They appear here as soon as a scan confirms one.</p></div>';
  }
}

// ── All findings ─────────────────────────────────────────────────────────────
function _pfFilteredFindings() {
  const fl = _pfFindingFilters;
  const q = fl.q.trim().toLowerCase();
  return (_pfFindings || []).filter(f => {
    if (!fl.fp && f.status === 'false_positive') return false;
    if (fl.app && f.app !== fl.app) return false;
    if (fl.run && f.run_id !== fl.run) return false;
    if (fl.sev && f.severity !== fl.sev) return false;
    if (q) {
      const hay = [f.title, f.target, f.cve, f.app, f.run_target].join(' ').toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}

function _pfFillSelect(id, options, current, allLabel) {
  const sel = document.getElementById(id);
  if (!sel || document.activeElement === sel) return;
  const html = `<option value="">${esc(allLabel)}</option>` + options.map(o =>
    `<option value="${esc(o.value)}"${o.value === current ? ' selected' : ''}>${esc(o.label)}</option>`).join('');
  if (sel.dataset.rendered !== html) { sel.innerHTML = html; sel.dataset.rendered = html; }
}

function _pfRenderAllFindings() {
  const out = document.getElementById('pf-findings-output');
  if (!out) return;
  if (_pfFindings === null) { out.innerHTML = '<div class="empty-placeholder">Loading…</div>'; return; }
  const all = _pfFindings;
  const fl = _pfFindingFilters;

  const apps = [...new Set(all.map(f => f.app))].sort();
  _pfFillSelect('pf-findings-app', apps.map(a => ({ value: a, label: a })), fl.app, 'All apps');
  const runs = ((_pfOverview && _pfOverview.runs) || []).filter(r => all.some(f => f.run_id === r.run_id));
  _pfFillSelect('pf-findings-run', runs.map(r => ({
    value: r.run_id, label: `${r.target || '—'} · ${_pfAgo(r.created_at).text}`,
  })), fl.run, 'All scans');

  // Severity chips count what the OTHER filters leave, so a chip never lies.
  const saved = fl.sev; fl.sev = '';
  const base = _pfFilteredFindings();
  fl.sev = saved;
  const chips = document.getElementById('pf-findings-sev');
  if (chips) {
    const chip = (value, label, n) =>
      `<button type="button" class="runs-chip${fl.sev === value ? ' active' : ''}" data-sev="${esc(value)}"
         aria-pressed="${fl.sev === value}">${esc(label)} <span class="runs-chip-n">${n}</span></button>`;
    chips.innerHTML = chip('', 'All', base.length) + _PF_SEVS.map(s =>
      chip(s, _PF_SEV_LABEL[s], base.filter(f => f.severity === s).length)).join('');
  }

  const shown = _pfFilteredFindings();
  const active = !!(fl.q || fl.app || fl.run || fl.sev || fl.fp);
  const clear = document.getElementById('pf-findings-clear');
  if (clear) clear.hidden = !active;
  const summary = document.getElementById('pf-findings-summary');
  if (summary) {
    const noun = all.length === 1 ? 'finding' : 'findings';
    summary.textContent = active ? `${shown.length} of ${all.length} ${noun}` : `${shown.length} ${noun}`;
  }

  if (!all.length) {
    out.innerHTML = `<div class="pf-empty"><p>No findings yet. Start a scan and they will collect here.</p>
      <button type="button" class="btn btn-primary btn-sm" data-pf-action="new-scan">Start a scan</button></div>`;
    return;
  }
  if (!shown.length) {
    out.innerHTML = '<div class="pf-empty"><p>No findings match these filters.</p></div>';
    return;
  }

  const keyOf = { app: f => f.app, severity: f => f.severity, run: f => f.run_id }[fl.group];
  if (!keyOf) {
    out.innerHTML = `<div class="pf-finding-list">${shown.map(f => _pfFindingRow(f, true)).join('')}</div>`;
    return;
  }
  const groups = new Map();
  for (const f of shown) {
    const k = keyOf(f);
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(f);
  }
  const title = (k, items) => {
    if (fl.group === 'severity') return _PF_SEV_LABEL[k] || k;
    if (fl.group === 'run') return `${items[0].run_target || '—'} · ${k}`;
    return k;
  };
  out.innerHTML = [...groups.entries()].map(([k, items]) => {
    const counts = {};
    for (const f of items) counts[f.severity] = (counts[f.severity] || 0) + 1;
    return `<section class="pf-fgroup">
      <header class="pf-fgroup-head">
        <h3>${esc(title(k, items))}</h3>
        ${fl.group === 'severity' ? `<span class="pf-count">${items.length}</span>` : pfSevPills(counts)}
      </header>
      <div class="pf-finding-list">${items.map(f => _pfFindingRow(f, fl.group !== 'app')).join('')}</div>
    </section>`;
  }).join('');
}

function _pfCsvCell(value) {
  let s = String(value == null ? '' : value);
  // Spreadsheet formula injection: neutralise a leading = + - @.
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return '"' + s.replace(/"/g, '""') + '"';
}

function _pfExportFindings() {
  const rows = _pfFilteredFindings();
  const head = ['Severity', 'Title', 'Target', 'App', 'Scan', 'Status', 'CVE', 'Found'];
  const lines = [head.map(_pfCsvCell).join(',')].concat(rows.map(f =>
    [f.severity, f.title, f.target, f.app, f.run_id, f.status, f.cve, f.timestamp].map(_pfCsvCell).join(',')));
  const blob = new Blob([lines.join('\r\n')], { type: 'text/csv;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'smith-findings.csv';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

// Open the finding's detail page in a new tab, authenticated as ITS scan.
async function _pfOpenFinding(findingId, runId) {
  if (!findingId) return;
  let token = '';
  try { token = (typeof _tokenForRun === 'function') ? await _tokenForRun(runId) : ''; } catch (e) { token = ''; }
  const url = '/finding/' + encodeURIComponent(findingId) + (token ? '#k=' + encodeURIComponent(token) : '');
  window.open(url, '_blank', 'noopener');
}

// ── Apps ─────────────────────────────────────────────────────────────────────
function _pfRenderApps() {
  const out = document.getElementById('pf-apps-output');
  if (!out) return;
  if (!_pfOverview) { out.innerHTML = '<div class="empty-placeholder">Loading…</div>'; return; }
  const q = _pfAppsQuery.trim().toLowerCase();
  const all = _pfOverview.apps || [];
  const apps = all.filter(a => !q || [a.app].concat(a.targets || []).join(' ').toLowerCase().includes(q));
  if (!all.length) {
    out.innerHTML = `<div class="pf-empty"><p>No apps yet. An app appears here after its first scan.</p>
      <button type="button" class="btn btn-primary btn-sm" data-pf-action="new-scan">Start a scan</button></div>`;
    return;
  }
  if (!apps.length) { out.innerHTML = '<div class="pf-empty"><p>No app matches that filter.</p></div>'; return; }
  out.innerHTML = apps.map(a => {
    const last = _pfAgo(a.last_scan_at);
    const scans = `${a.scans} scan${a.scans === 1 ? '' : 's'}`;
    return `<article class="pf-app">
      <header class="pf-app-head">
        <h4 title="${esc((a.targets || []).join('\n'))}">${esc(a.app)}</h4>
        ${a.active ? '<span class="pf-status pf-st-running">Scanning now</span>' : ''}
      </header>
      <p class="pf-app-meta" title="${esc(last.title)}">${esc(scans)} · last tested ${esc(last.text)} · ${esc(_PF_STATUS[a.last_status] || a.last_status || '—')}</p>
      <div class="pf-app-findings">${pfSevPills(a.findings)}</div>
      <footer class="pf-run-actions">
        <button type="button" class="btn btn-primary btn-sm" data-pf-action="rescan-app" data-app="${esc(a.app)}">Scan again</button>
        <button type="button" class="btn btn-secondary btn-sm" data-pf-action="app-findings" data-app="${esc(a.app)}">Findings</button>
        <button type="button" class="btn btn-secondary btn-sm" data-pf-action="app-scans" data-app="${esc(a.app)}">Scan history</button>
      </footer>
    </article>`;
  }).join('');
}

// ── Click actions (delegated) ────────────────────────────────────────────────
async function _pfStopRun(runId) {
  const run = pfRunExtras(runId) || {};
  const ok = (typeof confirmAction === 'function')
    ? await confirmAction({
        title: 'Stop this scan?',
        body: `Smith stops testing ${run.target || runId} and its tools are shut down. Findings so far are kept.`,
        confirmLabel: 'Stop scan',
      })
    : window.confirm('Stop this scan?');
  if (!ok) return;
  const res = await _pfPost('/api/runs/' + encodeURIComponent(runId) + '/stop');
  if (!res.ok && typeof _notify === 'function') _notify('Could not stop the scan', res.data.error || 'Try again.');
  pollPlatform();
  if (typeof pollSessions === 'function') pollSessions();
}

async function _pfResumeRun(runId) {
  const res = await _pfPost('/api/runs/' + encodeURIComponent(runId) + '/resume');
  if (!res.ok && typeof _notify === 'function') _notify('Could not resume the scan', res.data.error || 'Try again.');
  pollPlatform();
}

function _pfOnClick(ev) {
  const el = ev.target.closest && ev.target.closest('[data-pf-action]');
  if (!el) return;
  const action = el.getAttribute('data-pf-action');
  const runId = el.getAttribute('data-run-id') || '';
  const app = el.getAttribute('data-app') || '';
  if (action === 'open-run' && typeof selectRun === 'function') selectRun(runId, { tab: 'findings' });
  else if (action === 'stop-run') _pfStopRun(runId);
  else if (action === 'resume-run') _pfResumeRun(runId);
  else if (action === 'new-scan' && typeof openNewScanDialog === 'function') openNewScanDialog();
  else if (action === 'goto') switchTab(el.getAttribute('data-tab') || 'home');
  else if (action === 'open-finding') _pfOpenFinding(el.getAttribute('data-finding-id'), runId);
  else if (action === 'rescan-app') {
    const a = ((_pfOverview && _pfOverview.apps) || []).find(x => x.app === app);
    if (a && typeof openNewScanDialog === 'function') openNewScanDialog({ target: a.last_target, depth: a.last_depth });
  } else if (action === 'app-findings') {
    _pfFindingFilters = Object.assign({}, _pfFindingFilters, { app: app, run: '', q: '', sev: '' });
    _pfSyncFindingControls();
    switchTab('all-findings');
  } else if (action === 'app-scans') {
    if (typeof setRunFilter === 'function') setRunFilter('q', app);
    if (typeof _syncRunFilterControls === 'function') _syncRunFilterControls();
    switchTab('sessions');
  }
}

function _pfSyncFindingControls() {
  const fl = _pfFindingFilters;
  const set = (id, value) => { const el = document.getElementById(id); if (el) el.value = value; };
  set('pf-findings-q', fl.q);
  set('pf-findings-app', fl.app);
  set('pf-findings-run', fl.run);
  set('pf-findings-group', fl.group);
  const fp = document.getElementById('pf-findings-fp');
  if (fp) fp.checked = !!fl.fp;
}

// ── New Scan wizard ──────────────────────────────────────────────────────────
const _WIZ_DEPTHS = {
  recon: 'Recon · about 15 min',
  standard: 'Standard · about 45 min',
  thorough: 'Thorough · runs until you stop it',
  danger: 'Danger · thorough, plus internal hosts',
};
const _WIZ_LAST = 4;
let _wizStep = 1;

function _wizVal(id) { return ((document.getElementById(id) || {}).value || '').trim(); }

function _wizStatus(text, isError) {
  const el = document.getElementById('start-run-status');
  if (!el) return;
  el.textContent = text || '';
  el.classList.toggle('is-error', !!isError);
}

function _wizSetDepth(depth) {
  if (!_WIZ_DEPTHS[depth]) depth = 'standard';
  const input = document.getElementById('start-run-depth');
  if (input) input.value = depth;
  document.querySelectorAll('.wiz-depth').forEach(btn => {
    const on = btn.getAttribute('data-depth') === depth;
    btn.classList.toggle('active', on);
    btn.setAttribute('aria-checked', on ? 'true' : 'false');
  });
}

function _wizShow(step) {
  _wizStep = Math.max(1, Math.min(_WIZ_LAST, step));
  document.querySelectorAll('#start-run-form .wiz-step').forEach(sec => {
    sec.hidden = Number(sec.getAttribute('data-step')) !== _wizStep;
  });
  document.querySelectorAll('#wiz-steps li').forEach(li => {
    const n = Number(li.getAttribute('data-step'));
    li.classList.toggle('active', n === _wizStep);
    li.classList.toggle('done', n < _wizStep);
    if (n === _wizStep) li.setAttribute('aria-current', 'step'); else li.removeAttribute('aria-current');
  });
  const show = (id, on) => { const el = document.getElementById(id); if (el) el.hidden = !on; };
  show('wiz-back', _wizStep > 1);
  show('wiz-next', _wizStep < _WIZ_LAST);
  show('wiz-start', _wizStep === _WIZ_LAST);
  _wizStatus('');
  if (_wizStep === _WIZ_LAST) _wizRenderReview();
}

function _wizValidate(step) {
  if (step === 1) {
    const target = _wizVal('start-run-target');
    if (!target) { _wizStatus('Enter what you want to test, for example https://example.com.', true); return false; }
    if (/\s/.test(target)) { _wizStatus('A target is one address with no spaces. Add more in “Also in scope” in step 3.', true); return false; }
  }
  if (step === 3) {
    const cost = _wizVal('start-run-cost-limit');
    if (cost && !(Number(cost) >= 0.1 && Number(cost) <= 10000)) {
      _wizStatus('The cost limit must be between 0.1 and 10000 USD.', true); return false;
    }
  }
  return true;
}

// ── Source code folder (white-box) ───────────────────────────────────────────
const _WIZ_CODE_DIR_KEY = 'smith_wiz_code_dir';
let _wizBrowsePath = '';

function _wizCodeStatus(text, kind) {
  const el = document.getElementById('wiz-code-status');
  if (!el) return;
  el.hidden = !text;
  el.textContent = text || '';
  el.classList.toggle('is-error', kind === 'error');
  el.classList.toggle('is-ok', kind === 'ok');
}

function _wizFolderSummary(d) {
  const n = (count, word) => `${count} ${word}${count === 1 ? '' : 's'}`;
  const parts = [n(d.folders.length, 'folder'), n(d.files, 'file')];
  return parts.join(', ') + ((d.markers || []).length ? ' · ' + d.markers.join(' · ') : '');
}

// Ask the server whether the typed folder exists. True when it is fine to go
// on (also when the field is empty: a black-box test).
async function _wizCheckCode() {
  const input = document.getElementById('start-run-codebase');
  const path = _wizVal('start-run-codebase');
  if (!path) { _wizCodeStatus(''); return true; }
  const res = await _pfGet('/api/fs/folders?path=' + encodeURIComponent(path));
  if (!res.ok) {
    _wizCodeStatus(res.status === 404
      ? 'That folder was not found on this computer. Check the path, or use Browse.'
      : 'The folder could not be checked. Is the platform still running?', 'error');
    return false;
  }
  if (res.data.is_root) {
    _wizCodeStatus('Pick the project folder, not a whole drive.', 'error');
    return false;
  }
  if (input) input.value = res.data.path;
  _wizCodeStatus('Folder found: ' + _wizFolderSummary(res.data), 'ok');
  try { localStorage.setItem(_WIZ_CODE_DIR_KEY, res.data.parent || res.data.path); } catch (e) { /* ignore */ }
  return true;
}

async function _wizBrowse(path) {
  const panel = document.getElementById('wiz-browser');
  const list = document.getElementById('wiz-browser-list');
  if (!panel || !list) return;
  panel.hidden = false;
  list.innerHTML = '<div class="empty-placeholder">Loading…</div>';
  let res = await _pfGet('/api/fs/folders' + (path ? '?path=' + encodeURIComponent(path) : ''));
  if (!res.ok && path) res = await _pfGet('/api/fs/folders');       // gone or unreadable: start over
  const d = res.data || {};
  _wizBrowsePath = d.path || '';
  const roots = document.getElementById('wiz-browser-roots');
  if (roots) {
    roots.innerHTML = (d.roots || []).map(r =>
      `<button type="button" class="cmd-chip" data-wiz-dir="${esc(r.path)}">${esc(r.name)}</button>`).join('');
  }
  const here = document.getElementById('wiz-browser-path');
  if (here) here.textContent = _wizBrowsePath || 'Choose where to start';
  const up = document.getElementById('wiz-browser-up');
  if (up) up.hidden = !d.parent;
  if (up) up.setAttribute('data-wiz-dir', d.parent || '');
  const use = document.getElementById('wiz-browser-use');
  if (use) use.hidden = !_wizBrowsePath || !!d.is_root;
  const info = document.getElementById('wiz-browser-info');
  if (info) info.textContent = !res.ok ? 'Folders could not be listed.' : (_wizBrowsePath ? _wizFolderSummary(d) : '');
  const folders = _wizBrowsePath ? (d.folders || []) : (d.roots || []);
  list.innerHTML = folders.length
    ? folders.map(f => `<button type="button" class="wiz-dir" role="option" data-wiz-dir="${esc(f.path)}">${esc(f.name)}</button>`).join('')
    : '<div class="wiz-browser-empty">No folders in here.</div>';
  list.scrollTop = 0;
}

function _wizOpenBrowser() {
  let start = _wizVal('start-run-codebase');
  if (!start) { try { start = localStorage.getItem(_WIZ_CODE_DIR_KEY) || ''; } catch (e) { start = ''; } }
  _wizBrowse(start);
}

function _wizCloseBrowser() {
  const panel = document.getElementById('wiz-browser');
  if (panel) panel.hidden = true;
}

async function wizardNext() {
  if (!_wizValidate(_wizStep)) return;
  if (_wizStep === 3) {
    _wizCloseBrowser();
    if (!(await _wizCheckCode())) return;
  }
  _wizShow(_wizStep + 1);
  const focusId = { 3: 'start-run-notes', 4: 'wiz-authorized' }[_wizStep];
  const el = focusId && document.getElementById(focusId);
  if (el) el.focus();
}

function wizardBack() { _wizShow(_wizStep - 1); }

// Called by startRunFromForm(): true only when the request may be sent.
function wizardCanSubmit() {
  if (_wizStep < _WIZ_LAST) { wizardNext(); return false; }
  if (!_wizValidate(1) || !_wizValidate(3)) return false;
  const auth = document.getElementById('wiz-authorized');
  if (auth && !auth.checked) {
    _wizStatus('Tick the box to confirm you are authorized to test this target.', true);
    auth.focus();
    return false;
  }
  return true;
}

function _wizLines(id) {
  return _wizVal(id).split(/\n|,/).map(x => x.trim()).filter(Boolean);
}

function _wizRenderReview() {
  const dl = document.getElementById('wiz-review');
  if (!dl) return;
  const target = _wizVal('start-run-target');
  const depth = _wizVal('start-run-depth') || 'standard';
  const scope = _wizLines('start-run-scope');
  const out = _wizLines('start-run-out-of-scope');
  const timeSel = document.getElementById('start-run-time-limit');
  const time = timeSel && timeSel.value ? timeSel.options[timeSel.selectedIndex].text : '';
  const cost = _wizVal('start-run-cost-limit');
  const limits = [time && `stop after ${time}`, cost && `at most $${cost}`].filter(Boolean).join(', ');
  const rows = [
    ['Target', target],
    ['Depth', _WIZ_DEPTHS[depth] || depth],
    ['Source code', _wizVal('start-run-codebase') || 'None (black-box test)'],
    ['In scope', [target].concat(scope).join(', ')],
    ['Never touch', out.join(', ') || 'Nothing listed'],
    ['Limits', limits || 'The depth’s default'],
    ['Knowledge vault', _wizVal('start-run-source') || 'None'],
    ['Notes for Smith', _wizVal('start-run-notes') ? 'Included' : 'None'],
  ];
  dl.innerHTML = rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('');
}

// Reset the wizard to step 1, optionally pre-filled ({target, depth, …}).
function wizardReset(prefill) {
  prefill = prefill || {};
  const form = document.getElementById('start-run-form');
  if (form && typeof form.reset === 'function') form.reset();
  const set = (id, value) => { const el = document.getElementById(id); if (el && value != null) el.value = value; };
  set('start-run-target', prefill.target || '');
  set('start-run-scope', (prefill.scope || []).join('\n'));
  set('start-run-out-of-scope', (prefill.out_of_scope || []).join('\n'));
  _wizSetDepth(prefill.depth || 'standard');
  _wizCodeStatus('');
  _wizCloseBrowser();

  // "Tested before": one chip per app, most recent first.
  const recent = document.getElementById('wiz-recent');
  const chips = document.getElementById('wiz-recent-chips');
  const apps = ((_pfOverview && _pfOverview.apps) || []).filter(a => a.last_target).slice(0, 5);
  if (recent && chips) {
    recent.hidden = !apps.length;
    chips.innerHTML = apps.map(a =>
      `<button type="button" class="cmd-chip" data-wiz-target="${esc(a.last_target)}" data-wiz-depth="${esc(a.last_depth || '')}">${esc(a.last_target)}</button>`).join('');
  }
  _wizShow(1);
}

// ── Wiring ───────────────────────────────────────────────────────────────────
function _initPlatform() {
  document.addEventListener('click', _pfOnClick);

  const quick = document.getElementById('pf-quick-form');
  if (quick) quick.addEventListener('submit', ev => {
    ev.preventDefault();
    const target = _wizVal('pf-quick-target');
    if (typeof openNewScanDialog !== 'function') return;
    openNewScanDialog({ target: target });
    if (target) wizardNext();            // the target is known: go straight to depth
  });

  // All findings: filters.
  const fl = (key, id, event, read) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener(event, () => { _pfFindingFilters[key] = read(el); _pfRenderAllFindings(); });
  };
  fl('q', 'pf-findings-q', 'input', el => el.value);
  fl('app', 'pf-findings-app', 'change', el => el.value);
  fl('run', 'pf-findings-run', 'change', el => el.value);
  fl('group', 'pf-findings-group', 'change', el => el.value);
  fl('fp', 'pf-findings-fp', 'change', el => el.checked);
  const sevChips = document.getElementById('pf-findings-sev');
  if (sevChips) sevChips.addEventListener('click', ev => {
    const btn = ev.target.closest && ev.target.closest('.runs-chip');
    if (!btn) return;
    _pfFindingFilters.sev = btn.getAttribute('data-sev') || '';
    _pfRenderAllFindings();
  });
  const clear = document.getElementById('pf-findings-clear');
  if (clear) clear.addEventListener('click', () => {
    _pfFindingFilters = { q: '', app: '', run: '', group: _pfFindingFilters.group, fp: false, sev: '' };
    _pfSyncFindingControls();
    _pfRenderAllFindings();
  });
  const exportBtn = document.getElementById('pf-findings-export');
  if (exportBtn) exportBtn.addEventListener('click', _pfExportFindings);

  const appsQ = document.getElementById('pf-apps-q');
  if (appsQ) appsQ.addEventListener('input', () => { _pfAppsQuery = appsQ.value; _pfRenderApps(); });

  // Wizard.
  const next = document.getElementById('wiz-next');
  if (next) next.addEventListener('click', wizardNext);
  const back = document.getElementById('wiz-back');
  if (back) back.addEventListener('click', wizardBack);
  document.querySelectorAll('.wiz-depth').forEach(btn =>
    btn.addEventListener('click', () => _wizSetDepth(btn.getAttribute('data-depth'))));
  const steps = document.getElementById('wiz-steps');
  if (steps) steps.addEventListener('click', ev => {
    const li = ev.target.closest && ev.target.closest('li[data-step]');
    if (!li) return;
    const n = Number(li.getAttribute('data-step'));
    if (n < _wizStep) _wizShow(n);                      // going back is always allowed
  });
  const recent = document.getElementById('wiz-recent-chips');
  if (recent) recent.addEventListener('click', ev => {
    const chip = ev.target.closest && ev.target.closest('[data-wiz-target]');
    if (!chip) return;
    const target = document.getElementById('start-run-target');
    if (target) target.value = chip.getAttribute('data-wiz-target');
    if (chip.getAttribute('data-wiz-depth')) _wizSetDepth(chip.getAttribute('data-wiz-depth'));
  });
  // Source code folder: check what was typed, and the folder browser.
  const code = document.getElementById('start-run-codebase');
  if (code) {
    code.addEventListener('input', () => _wizCodeStatus(''));
    code.addEventListener('change', _wizCheckCode);
  }
  const browse = document.getElementById('wiz-code-browse');
  if (browse) browse.addEventListener('click', () => {
    const panel = document.getElementById('wiz-browser');
    if (panel && !panel.hidden) _wizCloseBrowser(); else _wizOpenBrowser();
  });
  const browser = document.getElementById('wiz-browser');
  if (browser) browser.addEventListener('click', ev => {
    const dir = ev.target.closest && ev.target.closest('[data-wiz-dir]');
    if (dir) _wizBrowse(dir.getAttribute('data-wiz-dir'));
  });
  const useDir = document.getElementById('wiz-browser-use');
  if (useDir) useDir.addEventListener('click', () => {
    if (!_wizBrowsePath || !code) return;
    code.value = _wizBrowsePath;
    _wizCloseBrowser();
    _wizCheckCode();
  });
  const cancelDir = document.getElementById('wiz-browser-cancel');
  if (cancelDir) cancelDir.addEventListener('click', _wizCloseBrowser);

  const form = document.getElementById('start-run-form');
  if (form) form.addEventListener('keydown', ev => {
    // Enter in a one-line field means "Next", not "send the form now".
    if (ev.key !== 'Enter' || !ev.target || ev.target.tagName !== 'INPUT' || ev.target.type === 'checkbox') return;
    if (_wizStep < _WIZ_LAST) { ev.preventDefault(); wizardNext(); }
  });

  setInterval(pollPlatform, _PF_POLL_MS);
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', _initPlatform);
else _initPlatform();
