  // ── Timeline tab ───────────────────────────────────────────────────────────
  // ONE timeline. Tool calls, findings, instructions, blocked steps, quality
  // checks and review verdicts are all entries of the same list, newest first,
  // with a kind filter. Entries that are not finished yet (an unresolved block,
  // a standing quality alert, an instruction Smith has not picked up) are also
  // lifted into "Open right now" at the top.
  //
  // Data comes from what other pollers already hold (_qaData, _steeringData,
  // _sessionData via _collectStuckEvents) plus two fetches of our own, made only
  // while the tab is open: the tool log and the review log.

  const ACT_RENDER_CAP = 300;       // newest N rows after filtering (multi-day scans)
  const _ACT_KINDS = {
    tool:        { label: 'Tool calls',     word: 'Tool',        mark: '›' },
    finding:     { label: 'Findings',       word: 'Finding',     mark: '!' },
    progress:    { label: 'Progress',       word: 'Progress',    mark: '→' },
    instruction: { label: 'Instructions',   word: 'Instruction', mark: '✎' },
    blocked:     { label: 'Blocked',        word: 'Blocked',     mark: '■' },
    check:       { label: 'Quality checks', word: 'Check',       mark: '✓' },
    review:      { label: 'Reviews',        word: 'Review',      mark: '⚖' },
    work:        { label: 'Queued work',    word: 'Work item',   mark: '⧉' },
  };
  const _ACT_FILTER_KEY = 'smith_activity_filter';
  let _actQuick = [];               // /api/quicklog
  let _actAdj = [];                 // /api/adjudication-log
  let _actWork = [];                // /api/runs/<id>/work (dashboard-started scans only)
  let _actFilter = { kind: '', q: '' };
  let _actOpenKeys = new Set();     // expanded rows survive re-renders
  let _actSig = '';
  let _actBusy = false;
  try {
    const saved = localStorage.getItem(_ACT_FILTER_KEY) || '';
    if (saved in _ACT_KINDS) _actFilter.kind = saved;
  } catch (_) { /* default: everything */ }

  function _actTime(ts) {
    const d = new Date(ts);
    if (!ts || isNaN(d.getTime())) return { text: '', title: '', n: 0 };
    return { text: d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }), title: d.toLocaleString(), n: d.getTime() };
  }

  function _actFirstLine(text, max) {
    const line = String(text || '').split('\n')[0].trim();
    return line.length > max ? line.slice(0, max) + '…' : line;
  }

  // Build the merged, time-sorted list of entries from every source.
  function _collectActivity() {
    const items = [];
    const add = (kind, ts, key, summaryHtml, opts) => items.push(Object.assign(
      { kind, ts, key: kind + ':' + key, summaryHtml, detailHtml: '', open: false, tone: '', text: '' }, opts || {}));

    // Tool log: tool calls, findings, playbook/coverage progress.
    _actQuick.forEach((e, i) => {
      if (!e || typeof e !== 'object') return;
      const kind = e.type === 'TOOL' || e.type === 'SPIDER' ? 'tool' : e.type === 'FINDING' ? 'finding' : 'progress';
      add(kind, e.ts, (e.ts || '') + ':' + i, _qlDesc(e), {
        text: [e.type, e.name, e.command, e.target, e.title, e.reason, e.message].filter(Boolean).join(' '),
        tone: e.type === 'FINDING' ? (e.severity || '') : '',
      });
    });

    // Instructions (operator steering and automatic nudges).
    const directives = ((_steeringData || {}).directives || []).filter(d => d && typeof d === 'object');
    const statusWord = { pending: 'waiting for Smith', injected: 'delivered, not yet acknowledged', acknowledged: 'acknowledged', auto_satisfied: 'no longer needed' };
    directives.forEach((d, i) => {
      const open = d.status === 'pending' || d.status === 'injected';
      const origin = [d.code, d.trigger].filter(Boolean).join(' · ');
      add('instruction', d.ts, (d.id || d.ts || i), `${esc(_actFirstLine(d.message, 160))} <span class="act-state">${esc(statusWord[d.status] || d.status || '')}</span>`, {
        open, tone: open ? 'warn' : '',
        text: [d.message, d.code, d.trigger, d.skill, d.ack_message].filter(Boolean).join(' '),
        detailHtml: `<div class="act-pre">${esc(d.message || '')}</div>` +
          (d.ack_message ? `<div class="act-reply"><strong>Smith:</strong> ${esc(d.ack_message)}</div>` : '') +
          (origin ? `<div class="act-meta">${esc(origin)}${d.skill ? ' → ' + esc(d.skill) : ''}</div>` : ''),
      });
    });

    // Blocked / paused.
    const typeWord = { HIR: 'Paused for your input', STALL: 'Coverage stalled', GATE: 'Step blocked' };
    (typeof _collectStuckEvents === 'function' ? _collectStuckEvents() : []).forEach((e, i) => {
      add('blocked', e.ts, (e.ts || '') + ':' + (e.code || i),
        `<strong>${esc(typeWord[e.type] || 'Blocked')}</strong> ${esc(_actFirstLine(e.reason, 140))} <span class="act-state">${e.resolved ? 'resolved' : 'still open'}</span>`, {
        open: !e.resolved, tone: e.resolved ? '' : 'danger',
        text: [e.type, e.code, e.reason, e.resolution].concat(e.tried || []).filter(Boolean).join(' '),
        detailHtml: `<div class="act-pre">${esc(e.reason || '')}</div>` +
          ((e.tried || []).length ? `<div class="act-meta">What Smith already tried</div><ol class="act-list">${e.tried.map(t => `<li>${esc(t)}</li>`).join('')}</ol>` : '') +
          (e.resolution ? `<div class="act-reply"><strong>Resolved:</strong> ${esc(e.resolution)}</div>` : '') +
          `<div class="act-meta">${esc(e.code || '')}</div>`,
      });
    });

    // Quality checks. A check runs every couple of minutes and usually repeats the
    // same alerts until Smith acts on them, so consecutive checks with an
    // identical result collapse into ONE entry ("repeated 9× since 03:13").
    const history = ((_qaData || {}).history || []).filter(c => c && typeof c === 'object');
    const runs = [];
    history.forEach(c => {
      const sigOf = (c.alerts || []).map(a => (a.urgency || '') + ':' + (a.message || '')).join('|') + '§' + (c.smith_reply || '');
      const last = runs[runs.length - 1];
      if (last && last.sig === sigOf) { last.cycles.push(c); } else { runs.push({ sig: sigOf, cycles: [c] }); }
    });
    runs.forEach((run, i) => {
      const c = run.cycles[run.cycles.length - 1];            // newest of the run
      const first = run.cycles[0];
      const alerts = c.alerts || [];
      const high = alerts.filter(a => a.urgency === 'high').length;
      const repeat = run.cycles.length > 1
        ? ` <span class="act-repeat">repeated ${run.cycles.length}× since ${esc(_actTime(first.ts).text)}</span>` : '';
      const summary = (alerts.length
        ? `Quality check raised <strong>${alerts.length}</strong> alert${alerts.length === 1 ? '' : 's'}${high ? ` (${high} high)` : ''}: ${esc(_actFirstLine(alerts[0].message, 110))}`
        : 'Quality check passed — nothing to flag.') + repeat;
      const actions = run.cycles.reduce((all, x) => all.concat(x.smith_actions || []), []);
      const narrative = _smithNarrative(actions);
      add('check', c.ts, (first.ts || i), summary, {
        tone: high ? 'warn' : '',
        text: alerts.map(a => a.message).concat([c.smith_reply]).filter(Boolean).join(' '),
        detailHtml:
          (alerts.length ? alerts.map(a => `<div class="act-alert"><span class="qa-urgency ${esc(a.urgency || 'low')}">${esc(a.urgency || 'low')}</span><span>${esc(a.message || '')}</span></div>`).join('') : '') +
          (c.smith_reply ? `<div class="act-reply"><strong>Smith replied:</strong> ${esc(c.smith_reply)}</div>` : '') +
          (narrative.length ? `<div class="act-meta">What Smith did meanwhile</div><ul class="act-list">${narrative.map(p => `<li>${p}</li>`).join('')}</ul>` : ''),
      });
    });

    // Review pass (triage verdicts).
    _actAdj.forEach((e, i) => {
      if (!e || typeof e !== 'object') return;
      if (e.type === 'directive') {
        add('review', e.ts, 'd' + (e.ts || i), `Review requested for <strong>${esc(e.n_pending)}</strong> finding${e.n_pending === 1 ? '' : 's'}.`, {
          text: (e.titles || []).join(' '),
          detailHtml: (e.titles || []).length ? `<ul class="act-list">${e.titles.map(t => `<li>${esc(t)}</li>`).join('')}</ul>` : '',
        });
      } else if (e.type === 'verdict') {
        const repro = e.reproducible === true || e.reproducible === 'true' || e.reproducible === 'yes';
        const changed = e.original_severity && e.revised_severity && String(e.original_severity).toLowerCase() !== String(e.revised_severity).toLowerCase();
        const sev = changed ? `${esc(e.original_severity)} → ${esc(e.revised_severity)}` : esc(e.original_severity || e.revised_severity || '—');
        add('review', e.ts, 'v' + (e.finding_id || e.ts || i),
          `<strong>${repro ? 'Reproduced' : 'Not reproduced'}</strong> ${esc(_actFirstLine(e.title || e.finding_id, 120))} <span class="act-state">severity ${sev}</span>`, {
          tone: repro ? '' : 'warn',
          text: [e.title, e.finding_id, e.rationale].filter(Boolean).join(' '),
          detailHtml: `<div class="act-pre">${esc(e.rationale || 'No rationale recorded.')}</div>`,
        });
      } else if (e.type === 'complete') {
        add('review', e.ts, 'c' + (e.ts || i), `Review pass finished — ${esc(e.n_adjudicated)} finding${e.n_adjudicated === 1 ? '' : 's'} reviewed.`, {});
      }
    });

    // Queued work (e.g. Source updates handed to Smith one at a time).
    const workState = { queued: 'waiting for Smith to be idle', running: 'in progress', done: 'done', failed: 'failed' };
    _actWork.forEach(w => {
      if (!w || typeof w !== 'object') return;
      const notes = ((w.payload || {}).notes || []);
      add('work', w.started_at || w.created_at, 'w' + w.id,
        `${esc(w.title || 'Work item')} <span class="act-state">${esc(workState[w.status] || w.status)}</span>`, {
        open: w.status === 'queued' || w.status === 'running',
        tone: w.status === 'failed' ? 'danger' : (w.status === 'running' ? 'warn' : ''),
        text: [w.title, w.note, (w.payload || {}).text].concat(notes.map(n => n.path)).filter(Boolean).join(' '),
        detailHtml:
          (notes.length ? `<ul class="act-list">${notes.map(n => `<li><code>${esc(n.path)}</code> (${esc(n.change)})</li>`).join('')}</ul>` : '') +
          ((w.payload || {}).text ? `<div class="act-pre">${esc(w.payload.text)}</div>` : '') +
          (w.note ? `<div class="act-meta">${esc(w.note)}</div>` : '') +
          `<div class="act-meta">queued ${esc(_actTime(w.created_at).title)} · attempt ${esc(w.attempts || 0)}</div>`,
      });
    });

    items.forEach(it => { it.t = _actTime(it.ts); });
    items.sort((a, b) => b.t.n - a.t.n);
    return items;
  }

  function _actRow(it) {
    const k = _ACT_KINDS[it.kind];
    const head = `<span class="act-time" title="${esc(it.t.title)}">${esc(it.t.text)}</span>
      <span class="act-kind act-kind-${it.kind}"><span aria-hidden="true">${k.mark}</span> ${k.word}</span>
      <span class="act-summary">${it.summaryHtml}</span>`;
    const tone = it.tone ? ' is-' + esc(it.tone) : '';
    if (!it.detailHtml) return `<div class="act-row${tone}">${head}</div>`;
    return `<details class="act-row act-expandable${tone}" data-key="${esc(it.key)}"${_actOpenKeys.has(it.key) ? ' open' : ''}>
      <summary>${head}</summary>
      <div class="act-detail">${it.detailHtml}</div>
    </details>`;
  }

  function renderActivityFeed() {
    const feed = document.getElementById('act-feed');
    if (!feed) return;
    const items = _collectActivity();

    // Standing quality alerts are "open" too, though they have no timeline row of their own.
    const standing = ((_qaData || {}).alerts || []).filter(a => a && typeof a === 'object');
    const openItems = items.filter(it => it.open);
    const q = _actFilter.q.trim().toLowerCase();
    const shown = items.filter(it =>
      (!_actFilter.kind || it.kind === _actFilter.kind) &&
      (!q || (it.text + ' ' + _ACT_KINDS[it.kind].word).toLowerCase().includes(q)));

    const sig = [items.length, items[0] ? items[0].key + items[0].t.n : '', openItems.map(i => i.key).join(','),
                 standing.map(a => a.message).join('|'), _actFilter.kind, q,
                 items.filter(i => i.kind === 'instruction' || i.kind === 'check').map(i => i.summaryHtml.length).join(','),
                 ((_qaData || {}).history || []).length,
                 _actWork.map(w => w.id + w.status).join(',')].join('§');
    if (sig === _actSig) return;
    _actSig = sig;

    // ── Open right now ──
    const openBox = document.getElementById('act-open');
    const openList = document.getElementById('act-open-list');
    if (openBox && openList) {
      const rows = openItems.map(_actRow).concat(standing.map(a => {
        const u = ['high', 'medium', 'low'].includes(a.urgency) ? a.urgency : 'low';
        return `<div class="act-row${u === 'high' ? ' is-warn' : ''}">
          <span class="act-time"></span>
          <span class="act-kind act-kind-check"><span aria-hidden="true">✓</span> Check</span>
          <span class="act-summary"><span class="qa-urgency ${u}">${u}</span> ${esc(a.message || '')}</span>
        </div>`;
      }));
      openBox.hidden = rows.length === 0;
      openList.innerHTML = rows.join('');
    }

    // ── Kind filter ──
    const chips = document.getElementById('act-chips');
    if (chips) {
      const counts = {};
      items.forEach(it => { counts[it.kind] = (counts[it.kind] || 0) + 1; });
      const chip = (value, label, n) => `<button type="button" class="runs-chip${_actFilter.kind === value ? ' active' : ''}"
          data-kind="${value}" aria-pressed="${_actFilter.kind === value}">${label} <span class="runs-chip-n">${n}</span></button>`;
      chips.innerHTML = chip('', 'All', items.length) +
        Object.keys(_ACT_KINDS).filter(k => counts[k] || _actFilter.kind === k).map(k => chip(k, _ACT_KINDS[k].label, counts[k] || 0)).join('');
    }

    // ── Timeline ──
    const summary = document.getElementById('act-summary');
    if (!items.length) {
      if (summary) summary.textContent = '';
      feed.innerHTML = '<div class="empty-placeholder">Nothing has happened yet. Every tool call, instruction, quality check and review appears here as it happens.</div>';
      return;
    }
    if (!shown.length) {
      if (summary) summary.textContent = `0 of ${items.length} entries`;
      feed.innerHTML = '<div class="empty-placeholder">Nothing matches this filter. <button type="button" class="runs-clear-btn" data-action="act-clear">Show everything</button></div>';
      return;
    }
    const capped = shown.slice(0, ACT_RENDER_CAP);
    if (summary) {
      const filtered = _actFilter.kind || q;
      summary.textContent = (filtered ? `${shown.length} of ${items.length} entries` : `${items.length} entries`) +
        (shown.length > capped.length ? ` · showing the newest ${capped.length}` : '');
    }
    feed.innerHTML = capped.map(_actRow).join('');
  }

  // Fetch the two logs only this tab needs, then render.
  async function refreshActivity() {
    if (_actBusy) return;
    _actBusy = true;
    try {
      const [rq, ra] = await Promise.all([
        fetch(`/api/quicklog?_=${Date.now()}`).catch(() => null),
        fetch(`/api/adjudication-log?_=${Date.now()}`).catch(() => null),
      ]);
      if (rq && rq.ok) { const d = await rq.json(); if (Array.isArray(d)) _actQuick = d; }
      // The work queue exists only for dashboard-started scans (a selected run).
      const runId = (typeof _selectedRunId === 'function') ? _selectedRunId() : '';
      if (runId) {
        const rw = await fetch(`/api/runs/${encodeURIComponent(runId)}/work?_=${Date.now()}`).catch(() => null);
        if (rw && rw.ok) { const d = await rw.json(); if (d && Array.isArray(d.items)) _actWork = d.items; }
      }
      if (ra && ra.ok) { const d = await ra.json(); if (Array.isArray(d)) _actAdj = d; }
    } catch { /* keep the last good data */ }
    finally { _actBusy = false; }
    _safeRender('activity', renderActivityFeed);
  }

  function resetActivityFeed() {
    _actQuick = []; _actAdj = []; _actWork = []; _actOpenKeys = new Set(); _actSig = '';
    renderActivityFeed();
  }

  function setActivityFilter(kind) {
    _actFilter.kind = (kind in _ACT_KINDS) ? kind : '';
    try { localStorage.setItem(_ACT_FILTER_KEY, _actFilter.kind); } catch (_) { /* ignore */ }
    renderActivityFeed();
  }

  (function _wireActivity() {
    const chips = document.getElementById('act-chips');
    if (chips) chips.addEventListener('click', ev => {
      const b = ev.target.closest && ev.target.closest('[data-kind]');
      if (b) setActivityFilter(b.getAttribute('data-kind'));
    });
    const search = document.getElementById('act-search');
    if (search) search.addEventListener('input', () => { _actFilter.q = search.value; renderActivityFeed(); });
    const tab = document.getElementById('tab-timeline');
    if (tab) {
      tab.addEventListener('click', ev => {
        if (ev.target.closest && ev.target.closest('[data-action="act-clear"]')) {
          _actFilter.q = ''; if (search) search.value = '';
          setActivityFilter('');
        }
      });
      // Remember which rows are expanded so the 5-second refresh does not collapse them.
      tab.addEventListener('toggle', ev => {
        const d = ev.target;
        const key = d && d.getAttribute && d.getAttribute('data-key');
        if (!key) return;
        if (d.open) _actOpenKeys.add(key); else _actOpenKeys.delete(key);
      }, true);
    }
  })();

  // Synthesise a readable narrative from Smith's raw action log
  function _smithNarrative(actions) {
    if (!actions.length) return [];
    const parts = [];
    const skills   = actions.filter(a => a.type === 'SKILL');
    const tools    = actions.filter(a => a.type === 'TOOL');
    const findings = actions.filter(a => a.type === 'FINDING');
    const coverage = actions.filter(a => a.type === 'COVERAGE');

    skills.forEach(s => {
      const r = s.reason ? ` — ${s.reason}` : '';
      parts.push(`🎯 Invoked <strong>/${esc(s.name)}</strong>${esc(r)}`);
    });

    if (tools.length) {
      const counts = {};
      tools.forEach(t => counts[t.name||'?'] = (counts[t.name||'?']||0) + 1);
      const toolStr = Object.entries(counts).map(([n,c]) => c > 1 ? `${esc(n)} ×${c}` : esc(n)).join(', ');
      parts.push(`🔧 Ran ${tools.length} tool call${tools.length > 1 ? 's' : ''} (${toolStr})`);
    }

    if (findings.length) {
      const bySev = {};
      findings.forEach(f => { const s = f.severity||'info'; bySev[s] = (bySev[s]||0)+1; });
      const sevStr = ['critical','high','medium','low','info']
        .filter(s => bySev[s]).map(s => `${bySev[s]} ${s}`).join(', ');
      const titles = findings.slice(0,2).map(f => esc(f.title||'')).join('; ');
      const more = findings.length > 2 ? ` +${findings.length-2} more` : '';
      parts.push(`🔍 Logged ${findings.length} finding${findings.length>1?'s':''} (${sevStr}): ${titles}${more}`);
    }

    if (coverage.length) {
      const c = coverage[coverage.length-1];
      const tested = (c.tested||0) + (c.vulnerable||0);
      parts.push(`📋 Coverage — ${c.registered||0} endpoints · ${tested} tested · ${c.pending||0} pending`);
    }

    return parts;
  }

  // Run a single render call defensively so one failing renderer doesn't
  // silently kill the rest of the Activity tab.
  function _safeRender(name, fn) {
    try { fn(); }
    catch (e) { console.error(`Activity render '${name}' failed:`, e); }
  }

  async function pollQA() {
    try {
      const [rQA, rSteering] = await Promise.all([
        fetch(`/api/qa?_=${Date.now()}`),
        fetch(`/api/steering?_=${Date.now()}`),
      ]);
      let alerts = [];
      let active = [];
      if (rQA.ok) {
        _qaData = await rQA.json();
        if (_activeTab === 'timeline') refreshActivity();
        alerts = (_qaData.alerts || []);

        // Notify on new high-urgency QA alerts
        const highAlerts = alerts.filter(a => a.urgency === 'high');
        if (highAlerts.length > _notifState.alertCount && highAlerts.length > 0) {
          if (!_hirActive) {  // HIR notification takes priority
            _notify(
              `QA: ${highAlerts.length} alert${highAlerts.length > 1 ? 's' : ''} need attention`,
              highAlerts[0].message.slice(0, 120),
              'normal'
            );
          }
        }
        _notifState.alertCount = highAlerts.length;
      }
      if (rSteering.ok) {
        _steeringData = await rSteering.json();
        if (_activeTab === 'timeline') _safeRender('activity', renderActivityFeed);
        updateStallBanner(_steeringData.directives || []);
        active = (_steeringData.directives || []).filter(
          d => d.status === 'pending' || d.status === 'injected'
        );
      }
      // Combined badge on Activity tab button
      // Open items are counted on the Timeline entry (the Needs-you inbox in the
      // top bar is the primary signal; this is the secondary one).
      const btn = document.getElementById('tab-btn-timeline');
      if (btn) btn.textContent = alerts.length || active.length ? `Timeline (${alerts.length + active.length})` : 'Timeline';
      _updateTitleBadge(_notifState.alertCount, _notifState.stall, _hirActive);
    } catch { /* ignore */ }
  }

  function updateStallBanner(directives) {
    const dot  = document.getElementById('cmd-smith-dot');
    const hint = document.getElementById('cmd-smith-hint');
    if (!dot) return;
    if (_hirActive) return; // HIR styling takes precedence
    const stall = directives.find(d =>
      d.code === 'RESUME_REQUIRED' && (d.status === 'pending' || d.status === 'injected')
    );
    if (stall) {
      // Fire notification once when stall first detected, using the actual directive message
      if (!_notifState.stall) {
        _notify('Smith needs guidance', (stall.message || 'Smith may be stalled — send a steering instruction.').slice(0, 140), 'normal');
        _notifState.stall = true;
      }
      dot.style.background  = '#f97316';
      dot.style.boxShadow   = '0 0 6px #f97316';
      dot.title = 'Smith may be stalled — send guidance';
      if (hint && !_hirActive) hint.textContent = '— Smith may need guidance';
    } else {
      _notifState.stall = false;
      dot.style.background  = '';
      dot.style.boxShadow   = '';
      dot.title = '';
      if (hint && !_hirActive) hint.textContent = '';
    }
    _updateTitleBadge(_notifState.alertCount, !!stall, _hirActive);
  }

  // ── Metrics ───────────────────────────────────────────────────────────────

  let _metricsData = null;
