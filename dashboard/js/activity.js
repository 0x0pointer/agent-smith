  function renderQA() {
    const qa = _qaData || {};

    // ── Alerts panel ──
    const alertsWrap = document.getElementById('qa-alerts-wrap');
    const alerts = qa.alerts || [];
    const lastCheck = document.getElementById('qa-last-check');
    if (lastCheck && qa.ts) {
      lastCheck.textContent = 'Last check: ' + _qlTime(qa.ts);
    }

    if (!alerts.length) {
      alertsWrap.innerHTML = '<div class="empty-placeholder">No alerts — QA agent found no workflow gaps, or cycle has not run yet.</div>';
    } else {
      const _safeUrgency = u => ['high','medium','low'].includes(u) ? u : 'low';
      alertsWrap.innerHTML = alerts.map(a => {
        const u = _safeUrgency(a.urgency);
        return `<div class="qa-alert urgency-${u}">
          <span class="qa-urgency ${u}">${esc(u)}</span>
          <span class="qa-msg">${esc(a.message || '')}</span>
        </div>`;
      }).join('');
    }

    // ── Quick Log ──
    // fetch separately since it's a different endpoint
  }

  const QUICKLOG_RENDER_CAP = 500;  // newest N entries; capping prevents the
                                    // Activity tab from stalling on multi-day scans

  async function renderQuickLog() {
    try {
      const r = await fetch(`/api/quicklog?_=${Date.now()}`);
      if (!r.ok) return;
      const entries = await r.json();
      const wrap = document.getElementById('quicklog-wrap');
      if (!wrap) return;
      if (!entries.length) {
        wrap.innerHTML = '<div class="empty-placeholder">No tool activity yet — start a scan.</div>';
        return;
      }
      // Slice to newest first, then cap. With multi-day scans the unbounded
      // innerHTML write was producing 6000+ DOM nodes and making the tab
      // appear empty until the browser unfroze.
      const reversed = [...entries].reverse().slice(0, QUICKLOG_RENDER_CAP);
      const moreCount = entries.length - reversed.length;
      const header = moreCount > 0
        ? `<div class="empty-placeholder" style="text-align:left;padding:0.4rem 0.6rem;border-bottom:1px solid var(--border);margin-bottom:0.5rem">Showing newest ${reversed.length} of ${entries.length} entries (${moreCount} older hidden — scroll for live tail)</div>`
        : '';
      wrap.innerHTML = header + reversed.map(e => `
        <div class="ql-entry">
          <span class="ql-time">${_qlTime(e.ts)}</span>
          <span class="ql-icon">${QL_ICONS[e.type] || '·'}</span>
          <span class="ql-body">${_qlDesc(e)}</span>
        </div>`).join('');
    } catch { /* ignore */ }
  }

  let _cycleRenderedCount = 0;
  let _adjudicationRenderedCount = 0;

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

  // Compact one-liner for the scan-context summary strip
  function renderCycleHistory() {
    const wrap = document.getElementById('cycle-history-wrap');
    if (!wrap) return;
    const history = (_qaData || {}).history || [];

    const placeholder = wrap.querySelector('.empty-placeholder');
    if (placeholder && history.length) placeholder.remove();
    if (!history.length) {
      if (!wrap.querySelector('.empty-placeholder'))
        wrap.innerHTML = '<div class="empty-placeholder">No cycles yet — QA starts 30 s after scan begins.</div>';
      return;
    }

    const newCycles = history.slice(_cycleRenderedCount);
    if (!newCycles.length) return;

    const frag = document.createDocumentFragment();

    newCycles.forEach(cycle => {
      const tsEl = document.createElement('div');
      tsEl.className = 'chat-ts-chip';
      tsEl.textContent = _qlTime(cycle.ts);
      frag.appendChild(tsEl);

      // QA alerts bubble
      const qaDiv = document.createElement('div');
      qaDiv.className = 'chat-bubble qa';
      const alerts = cycle.alerts || [];
      const alertsInner = alerts.length
        ? alerts.map(a =>
            `<div class="chat-alert-row">` +
            `<span class="qa-urgency ${esc(a.urgency||'low')}">${esc(a.urgency||'low')}</span>` +
            `<span class="qa-msg">${esc(a.message||'')}</span>` +
            `</div>`
          ).join('')
        : '<span class="chat-ok">✓ No issues this cycle — all checks passed.</span>';
      qaDiv.innerHTML = `<div class="chat-sender">QA Agent</div>${alertsInner}`;
      frag.appendChild(qaDiv);

      // Smith qa_reply bubble (optional)
      const reply = cycle.smith_reply;
      if (reply) {
        const replyDiv = document.createElement('div');
        replyDiv.className = 'chat-bubble smith';
        replyDiv.innerHTML =
          `<div class="chat-sender">Smith — reply to QA</div>` +
          `<div class="chat-narrative">${esc(reply)}</div>`;
        frag.appendChild(replyDiv);
      }

      // Smith actions bubble
      const actions = cycle.smith_actions || [];
      const narrative = _smithNarrative(actions);
      const smithDiv = document.createElement('div');
      smithDiv.className = narrative.length ? 'chat-bubble smith' : 'chat-bubble smith-idle';
      let inner = `<div class="chat-sender">Smith — actions after this cycle</div>`;
      if (narrative.length) {
        inner += `<div class="chat-narrative">${narrative.map(p => `<div class="chat-narrative-part">${p}</div>`).join('')}</div>`;
        if (actions.length) {
          inner +=
            `<div class="chat-actions-toggle" onclick="this.nextElementSibling.classList.toggle('open');this.textContent=this.nextElementSibling.classList.contains('open')?'▲ hide raw events':'▼ ${actions.length} raw events'">` +
            `▼ ${actions.length} raw events</div>` +
            `<div class="chat-actions-detail">` +
            actions.map(e => `<div class="chat-smith-action">${QL_ICONS[e.type]||'·'} ${_qlDesc(e)}</div>`).join('') +
            `</div>`;
        }
      } else {
        inner += `<span class="chat-ok">No tool activity recorded between this cycle and the next.</span>`;
      }
      smithDiv.innerHTML = inner;
      frag.appendChild(smithDiv);
    });

    wrap.appendChild(frag);
    _cycleRenderedCount = history.length;
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
        if (_activeTab === 'activity') {
          _safeRender('stuckLog',        renderStuckLog);
          _safeRender('QA',              renderQA);
          _safeRender('quickLog',        renderQuickLog);
          _safeRender('cycleHistory',    renderCycleHistory);
          _safeRender('adjudicationLog', renderAdjudicationLog);
        }
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
        if (_activeTab === 'activity') {
          _safeRender('steering', renderSteering);
          _safeRender('stuckLog', renderStuckLog);
        }
        updateStallBanner(_steeringData.directives || []);
        active = (_steeringData.directives || []).filter(
          d => d.status === 'pending' || d.status === 'injected'
        );
      }
      // Combined badge on Activity tab button
      const btn = document.getElementById('tab-btn-activity');
      if (btn) btn.textContent = alerts.length || active.length ? `Activity (${alerts.length + active.length})` : 'Activity';
      _updateTitleBadge(_notifState.alertCount, _notifState.stall, _hirActive);
    } catch { /* ignore */ }
  }

  function renderSteering() {
    if (!_steeringData) return;
    const directives = _steeringData.directives || [];

    // Timestamp
    const lastEl = document.getElementById('steering-last-update');
    if (lastEl && _steeringData.updated_at) {
      lastEl.textContent = 'updated ' + new Date(_steeringData.updated_at).toLocaleTimeString();
    }

    // Active directives (pending + injected)
    const activeWrap = document.getElementById('steering-active-wrap');
    const active = directives.filter(d => d.status === 'pending' || d.status === 'injected');
    if (activeWrap) {
      if (active.length === 0) {
        activeWrap.innerHTML = '<div class="empty-placeholder">No active steering directives.</div>';
      } else {
        activeWrap.innerHTML = '';
        active.forEach(d => activeWrap.appendChild(_buildDirectiveCard(d)));
      }
    }

    // History (acknowledged + auto_satisfied), newest first
    const historyWrap = document.getElementById('steering-history-wrap');
    const done = directives.filter(d => d.status === 'acknowledged' || d.status === 'auto_satisfied');
    if (historyWrap) {
      if (done.length === 0) {
        historyWrap.innerHTML = '<div class="empty-placeholder">No steering history yet.</div>';
      } else {
        historyWrap.innerHTML = '';
        done.forEach(d => historyWrap.appendChild(_buildDirectiveCard(d)));
      }
    }
  }

  function _buildDirectiveCard(d) {
    const statusColor = { pending: '#f97316', injected: '#facc15', acknowledged: '#4ade80', auto_satisfied: '#60a5fa' };
    const color = statusColor[d.status] || '#9b98b8';
    const ts = d.ts ? new Date(d.ts).toLocaleTimeString() : '';
    const priorityLabel = d.priority === 'high' ? '<span style="color:#f87171">HIGH</span>' : '<span style="color:#facc15">MED</span>';
    const el = document.createElement('div');
    el.style.cssText = `background:var(--bg-card);border:1px solid var(--border);border-left:3px solid ${color};border-radius:6px;padding:0.6rem 0.85rem;margin-bottom:0.5rem;font-size:0.82rem;`;
    el.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:0.25rem;">
        <span style="color:${color};font-weight:600;font-family:'IBM Plex Mono',monospace;font-size:0.76rem;">● ${esc(d.status.replace('_',' ').toUpperCase())}</span>
        <span style="color:var(--text-dim);font-size:0.72rem;">${priorityLabel} &nbsp; ${esc(ts)}</span>
      </div>
      <div style="color:var(--text);font-size:0.8rem;line-height:1.5;margin-bottom:0.2rem;">${esc(d.message || '')}</div>
      <div style="color:var(--text-dim);font-size:0.72rem;font-family:'IBM Plex Mono',monospace;">${esc(d.code || '')}${d.skill ? ' → ' + esc(d.skill) : ''} &nbsp;|&nbsp; trigger: ${esc(d.trigger || '—')}</div>
      ${d.ack_message ? `<div style="margin-top:0.3rem;padding:0.3rem 0.5rem;background:rgba(74,222,128,0.08);border-radius:4px;color:#86efac;font-size:0.75rem;">Smith: ${esc(d.ack_message)}</div>` : ''}
    `;
    return el;
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

  // ── Adjudication log ─────────────────────────────────────────────────────

  async function renderAdjudicationLog() {
    try {
      const r = await fetch(`/api/adjudication-log?_=${Date.now()}`);
      if (!r.ok) return;
      const entries = await r.json();
      const wrap = document.getElementById('adjudication-log-wrap');
      if (!wrap) return;

      if (!entries.length) return;

      const newEntries = entries.slice(_adjudicationRenderedCount);
      if (!newEntries.length) return;

      const placeholder = wrap.querySelector('.empty-placeholder');
      if (placeholder) placeholder.remove();

      const frag = document.createDocumentFragment();

      newEntries.forEach(entry => {
        if (entry.type === 'directive') {
          const el = document.createElement('div');
          el.className = 'chat-bubble qa';
          el.style.borderLeftColor = '#e3a000';
          const titles = (entry.titles || []).map(t => `<li>${esc(t)}</li>`).join('');
          el.innerHTML =
            `<div class="chat-sender" style="color:#e3a000">Adjudicator — ${_qlTime(entry.ts)}</div>` +
            `<div style="margin-bottom:0.35rem">Senior review requested for <strong>${entry.n_pending}</strong> finding(s):</div>` +
            `<ul style="margin:0 0 0 1rem;padding:0;list-style:disc;line-height:1.7">${titles}</ul>`;
          frag.appendChild(el);

        } else if (entry.type === 'verdict') {
          const repro    = entry.reproducible === true || entry.reproducible === 'true' || entry.reproducible === 'yes';
          const reproTxt = repro ? '✓ Reproducible' : '✗ Not reproducible';
          const sevChanged = entry.original_severity && entry.revised_severity &&
                             entry.original_severity.toLowerCase() !== entry.revised_severity.toLowerCase();
          const sevLine = sevChanged
            ? `<span style="color:#f87171">${esc(entry.original_severity)}</span> → <span style="color:#4ade80">${esc(entry.revised_severity)}</span>`
            : `<span style="color:#94a3b8">${esc(entry.original_severity || entry.revised_severity || '—')}</span> (unchanged)`;
          const el = document.createElement('div');
          el.className = 'chat-bubble smith';
          el.innerHTML =
            `<div class="chat-sender">Smith — verdict · ${_qlTime(entry.ts)}</div>` +
            `<div style="font-weight:600;margin-bottom:0.3rem">${esc(entry.title || entry.finding_id)}</div>` +
            `<div style="display:grid;grid-template-columns:max-content 1fr;gap:0.15rem 0.75rem;font-size:0.79rem;line-height:1.6">` +
              `<span style="color:var(--text-dim)">Reproducible</span><span>${reproTxt}</span>` +
              `<span style="color:var(--text-dim)">Severity</span><span>${sevLine}</span>` +
              `<span style="color:var(--text-dim)">Rationale</span><span style="color:var(--text)">${esc(entry.rationale || '—')}</span>` +
            `</div>`;
          frag.appendChild(el);

        } else if (entry.type === 'complete') {
          const el = document.createElement('div');
          el.className = 'chat-ts-chip';
          el.style.cssText = 'color:#4ade80;border-color:#4ade80;font-weight:600;margin:0.75rem auto;';
          el.textContent = `✓ Adjudication complete — ${entry.n_adjudicated} finding(s) reviewed · ${_qlTime(entry.ts)}`;
          frag.appendChild(el);
        }
      });

      wrap.appendChild(frag);
      _adjudicationRenderedCount = entries.length;
    } catch { /* ignore */ }
  }

  // ── Metrics ───────────────────────────────────────────────────────────────

  let _metricsData = null;
