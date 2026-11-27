// ── ux.js — cross-cutting operator experience ───────────────────────────────
// Loaded after every tab script and before main.js. FLAT classic script sharing
// the dashboard's global scope; it only READS the state the other scripts keep
// (_sessionData, _lastCoverage, _hirActive, _smithStatus, _oaWishOpen, _oaGates,
// _qaData, allData) and never fetches what they already fetch.
//
//   confirmAction()        one named, in-page confirmation for destructive actions
//   renderScanProgress()   the scan as a story: steps + "what Smith is doing now"
//   Needs-you inbox        one place for everything waiting on the operator
//   exportFindings()       get the results out: Markdown / CSV / JSON / clipboard
//   askSmith()             empty-state actions that pre-fill the steering box

function _uxEsc(s) {
  return String(s == null ? '' : s).replace(/[&<>"]/g,
    c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

function _uxGet(read, fallback) {
  try { const v = read(); return v === undefined ? fallback : v; } catch (e) { return fallback; }
}

// "the scan of https://x (run-abc)" — used so every confirmation names its target.
function scanDisplayName() {
  const target = _uxGet(() => _sessionData && _sessionData.target, '') ||
                 _uxGet(() => allData.meta && allData.meta.target, '');
  const runId = _uxGet(() => _selectedRunId(), '');
  if (target && runId) return `the scan of ${target} (${runId})`;
  if (target) return `the scan of ${target}`;
  if (runId) return `scan ${runId}`;
  return 'the current scan';
}

// ── Confirmation dialog ──────────────────────────────────────────────────────
// Resolves true/false. In-page <dialog>, so it cannot be suppressed by the
// browser's "prevent additional dialogs" checkbox the way confirm() can.
function confirmAction(opts) {
  opts = opts || {};
  const dlg = document.getElementById('confirm-dialog');
  if (!dlg || typeof dlg.showModal !== 'function') {
    return Promise.resolve(window.confirm((opts.title || 'Are you sure?') + '\n\n' + (opts.body || '')));
  }
  const title = document.getElementById('confirm-title');
  const text = document.getElementById('confirm-text');
  const ok = document.getElementById('confirm-ok');
  const cancel = document.getElementById('confirm-cancel');
  title.textContent = opts.title || 'Are you sure?';
  text.textContent = opts.body || '';
  ok.textContent = opts.confirmLabel || 'Confirm';
  ok.className = 'btn ' + (opts.danger === false ? 'btn-primary' : 'btn-danger');
  return new Promise(resolve => {
    let done = false;
    const finish = value => {
      if (done) return;
      done = true;
      ok.removeEventListener('click', onOk);
      cancel.removeEventListener('click', onCancel);
      dlg.removeEventListener('close', onClose);
      dlg.removeEventListener('click', onBackdrop);
      if (dlg.open) dlg.close();
      resolve(value);
    };
    const onOk = () => finish(true);
    const onCancel = () => finish(false);
    const onClose = () => finish(false);                 // Escape
    const onBackdrop = ev => { if (ev.target === dlg) finish(false); };
    ok.addEventListener('click', onOk);
    cancel.addEventListener('click', onCancel);
    dlg.addEventListener('close', onClose);
    dlg.addEventListener('click', onBackdrop);
    dlg.showModal();
    cancel.focus();                                       // safe default
  });
}

// ── Scan progress ────────────────────────────────────────────────────────────
const _SCAN_STEPS = [
  { key: 'exploit',   label: 'Exploitation',   help: 'Deep testing of the most promising attack paths.' },
  { key: 'coverage',  label: 'Coverage sweep', help: 'Systematically checking every remaining endpoint and parameter.' },
  { key: 'synthesis', label: 'Synthesis',      help: 'Chaining findings together and writing up the results.' },
  { key: 'done',      label: 'Done',           help: 'The scan has finished.' },
];

function _scanIsTerminal(status) {
  return ['complete', 'incomplete_with_unresolved_blockers', 'limit_reached', 'stopped', 'failed'].includes(status);
}

function renderScanProgress() {
  const list = document.getElementById('scan-steps');
  const now = document.getElementById('scan-now');
  const session = _uxGet(() => _sessionData, null);
  const phase = _uxGet(() => window._phaseData && window._phaseData.phase, '');
  const status = (session && session.status) || '';
  const terminal = _scanIsTerminal(status);

  if (list) {
    if (!session || !session.target) {
      list.innerHTML = '';
    } else {
      let current = _SCAN_STEPS.findIndex(s => s.key === phase);
      if (current < 0) current = 0;
      if (terminal) current = _SCAN_STEPS.length - 1;
      const html = _SCAN_STEPS.map((s, i) => {
        const state = i < current ? 'done' : i === current ? (terminal ? 'done' : 'current') : 'todo';
        const mark = state === 'done' ? '✓' : String(i + 1);
        const aria = state === 'current' ? ' aria-current="step"' : '';
        return `<li class="scan-step is-${state}"${aria} title="${_uxEsc(s.help)}">
          <span class="scan-step-mark" aria-hidden="true">${mark}</span>
          <span class="scan-step-label">${_uxEsc(s.label)}</span>
          <span class="scan-step-state">${state === 'done' ? '(done)' : state === 'current' ? '(in progress)' : ''}</span>
        </li>`;
      }).join('');
      if (list.dataset.rendered !== html) { list.innerHTML = html; list.dataset.rendered = html; }
    }
  }

  if (now) {
    let text = '';
    let tone = '';
    if (session && session.target) {
      const cov = _uxGet(() => _lastCoverage && _lastCoverage.meta, null);
      const total = cov && cov.total_cells;
      const done = cov ? (cov.addressed || cov.tested || 0) : 0;
      const covTxt = total ? ` ${done} of ${total} test cells done (${Math.round(done / total * 100)}%).` : '';
      const idle = _uxGet(() => window._scanIdle, null);
      const stopped = !!idle;
      if (_uxGet(() => _hirActive, false) || status === 'intervention_required') {
        text = 'Paused — Smith is waiting for your decision.'; tone = 'warn';
      } else if (terminal) {
        text = status === 'complete' ? 'Scan finished. Review the findings, then export them.'
                                     : `Scan ended (${status.replace(/_/g, ' ')}).` + covTxt;
      } else if (stopped) {
        text = `Scan is idle. ${idle.detail || 'Smith is not running.'} Send an instruction or press Resume to continue.`; tone = 'warn';
      } else {
        const doing = session.skill ? `working through /${session.skill}` : 'testing';
        text = `Smith is ${doing}.` + covTxt;
      }
      // Work queue (Source updates and other queued items), when this scan has one.
      const work = _uxGet(() => _smithStatus && _smithStatus.work, null);
      if (work && !terminal) {
        const more = work.queued ? ` ${work.queued} more queued.` : '';
        if (work.running) { text = `Smith is working on: ${work.running.title}.` + more; tone = ''; }
        else if (work.queued) { text = `${work.queued} queued item${work.queued === 1 ? '' : 's'} (new Source information) — Smith starts on the next one shortly.`; tone = ''; }
      }
    }
    if (now.textContent !== text) now.textContent = text;
    now.className = 'scan-now' + (tone ? ' is-' + tone : '');
  }
}

// ── Needs-you inbox ──────────────────────────────────────────────────────────
// Everything that is waiting on the operator, gathered from the three places it
// used to be scattered across (the pause panel, Operator Actions, Activity).
function _needsYouItems() {
  const items = [];
  const session = _uxGet(() => _sessionData, null);
  const status = (session && session.status) || '';

  if (_uxGet(() => _hirActive, false) || status === 'intervention_required') {
    items.push({ tone: 'danger', title: 'Scan paused — Smith needs a decision',
                 detail: 'Nothing happens until you answer.', action: 'Answer now', run: 'hir' });
  }
  const idle = _uxGet(() => window._scanIdle, null);
  if (idle && status !== 'intervention_required') {
    items.push({ tone: 'warn', title: 'Scan is idle',
                 detail: (idle.detail || 'Smith is not running.') + ' Nothing was restarted — it waits for you.',
                 action: 'Resume scan', run: 'restart' });
  }
  const wishes = _uxGet(() => _oaWishOpen, []) || [];
  if (wishes.length) {
    items.push({ tone: 'warn', title: `${wishes.length} request${wishes.length === 1 ? '' : 's'} from Smith`,
                 detail: String((wishes[0] && wishes[0].need) || 'Smith is blocked on something only you can provide.').slice(0, 140),
                 action: 'Review', run: 'tab:setup-gates' });
  }
  const gates = (_uxGet(() => _oaGates, []) || []).filter(g => g && ['pending_election', 'elected_now', 'failed'].includes(g.status));
  if (gates.length) {
    items.push({ tone: 'warn', title: `${gates.length} manual setup step${gates.length === 1 ? '' : 's'} waiting`,
                 detail: 'A skill needs something set up by hand (a device, an emulator, a tunnel).',
                 action: 'Review', run: 'tab:setup-gates' });
  }
  const alerts = (_uxGet(() => _qaData && _qaData.alerts, []) || []).filter(a => a && a.urgency === 'high');
  if (alerts.length) {
    items.push({ tone: 'info', title: `${alerts.length} high-priority QA alert${alerts.length === 1 ? '' : 's'}`,
                 detail: String(alerts[0].message || '').slice(0, 140), action: 'Open Timeline', run: 'tab:timeline' });
  }
  return items;
}

function _runNeedsYou(run) {
  toggleNeedsYou(false);
  if (run === 'hir') {
    const panel = document.getElementById('hir-panel');
    if (panel) { try { panel.scrollIntoView({ block: 'start' }); } catch (e) { /* ignore */ } }
    const msg = document.getElementById('hir-message');
    if (msg) msg.focus();
  } else if (run === 'restart') {
    _uxGet(() => restartSmith(), null);
  } else if (run.indexOf('tab:') === 0) {
    _uxGet(() => switchTab(run.slice(4)), null);
  }
}

function toggleNeedsYou(force) {
  const panel = document.getElementById('needs-you-panel');
  const btn = document.getElementById('needs-you-btn');
  if (!panel || !btn) return;
  const open = (typeof force === 'boolean') ? force : panel.hidden;
  panel.hidden = !open;
  btn.setAttribute('aria-expanded', String(open));
}

function renderNeedsYou() {
  const btn = document.getElementById('needs-you-btn');
  const panel = document.getElementById('needs-you-panel');
  const count = document.getElementById('needs-you-count');
  if (!btn || !panel) return;
  const items = _needsYouItems();
  btn.hidden = items.length === 0;
  if (!items.length) { toggleNeedsYou(false); panel.innerHTML = ''; panel.dataset.rendered = ''; return; }
  if (count) count.textContent = String(items.length);
  btn.classList.toggle('is-urgent', items.some(i => i.tone === 'danger'));
  const html = items.map(i => `<div class="needs-you-item is-${i.tone}">
      <div class="needs-you-text">
        <strong>${_uxEsc(i.title)}</strong>
        <span>${_uxEsc(i.detail)}</span>
      </div>
      <button type="button" class="btn btn-secondary btn-sm" data-run="${_uxEsc(i.run)}">${_uxEsc(i.action)}</button>
    </div>`).join('');
  if (panel.dataset.rendered !== html) { panel.innerHTML = html; panel.dataset.rendered = html; }
}

// ── Empty-state actions ──────────────────────────────────────────────────────
// Opens the steering box with a ready-made instruction instead of telling the
// operator which tool call Smith should make.
function askSmith(text) {
  _uxGet(() => toggleCmdComposer(true), null);
  _uxGet(() => setSmithChip(text), null);
  const box = document.getElementById('cmd-center');
  if (box) { try { box.scrollIntoView({ block: 'start' }); } catch (e) { /* ignore */ } }
}

// ── Export ───────────────────────────────────────────────────────────────────
function toggleExportMenu(force) {
  const menu = document.getElementById('findings-export-menu');
  const btn = document.getElementById('findings-export-btn');
  if (!menu || !btn) return;
  const open = (typeof force === 'boolean') ? force : menu.hidden;
  menu.hidden = !open;
  btn.setAttribute('aria-expanded', String(open));
}

function _exportRows() {
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return (_uxGet(() => allData.findings, []) || [])
    .filter(f => f && f.status !== 'false_positive')
    .slice().sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
}

function _exportTarget() {
  return _uxGet(() => _sessionData && _sessionData.target, '') || _uxGet(() => allData.meta && allData.meta.target, '') || 'scan';
}

function _vsPlain(f) {
  const vs = f.verification_status || 'unverified';
  const label = _uxGet(() => VS_LABELS[vs], vs) || vs;
  return String(label).replace(/^[^A-Za-z]+/, '');
}

function buildFindingsMarkdown() {
  const rows = _exportRows();
  const target = _exportTarget();
  const counts = {};
  rows.forEach(f => { counts[f.severity] = (counts[f.severity] || 0) + 1; });
  const confirmed = rows.filter(f => _uxGet(() => VS_CONFIRMED.has(f.verification_status), false)).length;
  const lines = [
    `# Security findings — ${target}`, '',
    `Exported ${new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC. AI-generated; validate before acting on it.`, '',
    '## Summary', '',
    `- **${rows.length} findings**: ` + ['critical', 'high', 'medium', 'low', 'info'].filter(s => counts[s]).map(s => `${counts[s]} ${s}`).join(', '),
    `- **${confirmed} of ${rows.length} confirmed**` + (confirmed < rows.length ? ' — the rest are not yet independently re-tested' : ''),
    '', '| # | Severity | Finding | Where | Verification |', '|---|---|---|---|---|',
  ];
  const cell = s => String(s == null ? '' : s).replace(/\|/g, '\\|').replace(/\s+/g, ' ').trim();
  rows.forEach((f, i) => lines.push(`| ${i + 1} | ${cell(f.severity)} | ${cell(f.title)} | ${cell(f.target)} | ${cell(_vsPlain(f))} |`));
  lines.push('', '## Findings', '');
  rows.forEach((f, i) => {
    lines.push(`### ${i + 1}. ${f.title || 'Untitled'}`, '',
      `- **Severity:** ${f.severity || 'unknown'}`,
      `- **Where:** ${f.target || 'not recorded'}`,
      `- **Verification:** ${_vsPlain(f)}`);
    if (f.cve) lines.push(`- **CVE:** ${f.cve}`);
    if (f.tool_used) lines.push(`- **Found with:** ${f.tool_used}`);
    if (f.business_impact) lines.push('', '**Impact**', '', String(f.business_impact));
    if (f.description) lines.push('', '**What it is**', '', String(f.description));
    if (f.evidence) lines.push('', '**Evidence**', '', '```', String(f.evidence).slice(0, 4000), '```');
    if (f.reproduction && f.reproduction.command) lines.push('', '**Reproduce**', '', '```', String(f.reproduction.command), '```');
    const fix = f.remediation && (f.remediation.summary || f.remediation.description || f.remediation.fix);
    if (fix) lines.push('', '**Fix**', '', String(fix));
    lines.push('');
  });
  return lines.join('\n');
}

function buildFindingsCsv() {
  const q = v => '"' + String(v == null ? '' : v).replace(/"/g, '""').replace(/\r?\n/g, ' ') + '"';
  const head = ['severity', 'title', 'target', 'verification', 'cve', 'tool', 'time', 'id'];
  const rows = _exportRows().map(f => [f.severity, f.title, f.target, _vsPlain(f), f.cve, f.tool_used, f.timestamp, f.id].map(q).join(','));
  return [head.join(',')].concat(rows).join('\r\n');
}

function _downloadText(name, mime, text) {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = document.createElement('a');
  a.href = url; a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

function _exportFeedback(text) {
  const btn = document.getElementById('findings-export-btn');
  if (!btn) return;
  const prev = 'Export';
  btn.textContent = text;
  setTimeout(() => { btn.textContent = prev; }, 2200);
}

async function exportFindings(kind) {
  toggleExportMenu(false);
  if (!_exportRows().length) { _exportFeedback('Nothing to export yet'); return; }
  const slug = String(_exportTarget()).replace(/^https?:\/\//, '').replace(/[^a-zA-Z0-9.-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60) || 'scan';
  const stamp = new Date().toISOString().slice(0, 10);
  if (kind === 'markdown') {
    _downloadText(`findings-${slug}-${stamp}.md`, 'text/markdown', buildFindingsMarkdown());
    _exportFeedback('Report downloaded');
  } else if (kind === 'csv') {
    _downloadText(`findings-${slug}-${stamp}.csv`, 'text/csv', buildFindingsCsv());
    _exportFeedback('CSV downloaded');
  } else if (kind === 'json') {
    _downloadText(`findings-${slug}-${stamp}.json`, 'application/json', JSON.stringify({ target: _exportTarget(), exported_at: new Date().toISOString(), findings: _exportRows() }, null, 2));
    _exportFeedback('JSON downloaded');
  } else {
    try {
      await navigator.clipboard.writeText(buildFindingsMarkdown());
      _exportFeedback('Copied');
    } catch (e) { _exportFeedback('Copy blocked by browser'); }
  }
}

// A link that opens the dashboard scoped to this one scan (read access to it).
async function copyScanLink() {
  toggleExportMenu(false);
  const runId = _uxGet(() => _selectedRunId(), '');
  if (!runId) { _exportFeedback('No scan selected'); return; }
  try {
    const token = await _tokenForRun(runId);
    if (!token) throw new Error('no token');
    await navigator.clipboard.writeText(`${location.origin}/#k=${token}`);
    _exportFeedback('Link copied — anyone with it can view this scan');
  } catch (e) { _exportFeedback('Could not create a link'); }
}

// ── Wiring ───────────────────────────────────────────────────────────────────
function _initUx() {
  const panel = document.getElementById('needs-you-panel');
  if (panel) panel.addEventListener('click', ev => {
    const b = ev.target.closest && ev.target.closest('[data-run]');
    if (b) _runNeedsYou(b.getAttribute('data-run'));
  });
  // Click-away closes the two popovers.
  document.addEventListener('click', ev => {
    const t = ev.target;
    if (!(t.closest && t.closest('#needs-you'))) toggleNeedsYou(false);
    if (!(t.closest && t.closest('.fx-export'))) toggleExportMenu(false);
  });
  document.addEventListener('keydown', ev => {
    if (ev.key === 'Escape') { toggleNeedsYou(false); toggleExportMenu(false); }
  });
  const tick = () => { renderNeedsYou(); renderScanProgress(); };
  tick();
  setInterval(tick, 2000);     // reads cached state only — no network
}

try {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', _initUx);
  else _initUx();
} catch (e) { /* ignore */ }
