  function renderStuckLog() {
    const wrap = document.getElementById('stuck-log-wrap');
    if (!wrap) return;

    const events = [];
    const seen   = new Set();  // deduplicate by ts+code

    // HIR events from session intervention_history (resolved pauses).
    // Filter null entries — session.resolve_intervention has occasionally
    // pushed None into the history, and the loop crashes on h.ts otherwise.
    const hirHistory = ((_sessionData || {}).intervention_history || []).filter(h => h && typeof h === 'object');
    hirHistory.forEach(h => {
      const key = (h.ts || h.triggered_at || '') + (h.code || '');
      if (seen.has(key)) return;
      seen.add(key);
      events.push({
        ts:         h.ts || h.triggered_at,
        type:       'HIR',
        code:       h.code || 'HIR',
        reason:     h.situation || '',
        tried:      h.tried || [],
        resolved:   !!h.resolved_at,
        resolution: h.choice ? (h.choice + (h.message ? ': ' + h.message : '')) : null,
      });
    });

    // Active HIR (not yet in history)
    const current = (_sessionData || {}).intervention;
    if (current && typeof current === 'object' && current.code) {
      const key = (current.ts || '') + (current.code || '');
      if (!seen.has(key)) {
        seen.add(key);
        events.push({
          ts:       current.ts,
          type:     'HIR',
          code:     current.code,
          reason:   current.situation || '',
          tried:    current.tried || [],
          resolved: false,
          resolution: null,
        });
      }
    }

    // Stall + gate-block directives from steering queue
    const directives = ((_steeringData || {}).directives || []).filter(d => d && typeof d === 'object');
    directives
      .filter(d => d.trigger === 'COVERAGE_STALL' || d.trigger === 'ENDPOINT_TRIGGER_GAP' || d.code === 'RESUME_REQUIRED')
      .forEach(d => {
        const key = (d.ts || '') + (d.id || d.code || '');
        if (seen.has(key)) return;
        seen.add(key);
        events.push({
          ts:       d.ts,
          type:     d.trigger === 'COVERAGE_STALL' ? 'STALL' : 'GATE',
          code:     d.trigger || d.code || '—',
          reason:   d.message || '',
          tried:    [],
          resolved: d.status === 'acknowledged' || d.status === 'auto_satisfied',
          resolution: d.ack_message || null,
        });
      });

    if (!events.length) {
      wrap.innerHTML = '<div class="empty-placeholder">No stuck events yet — Smith is running smoothly.</div>';
      return;
    }

    // Sort newest first
    events.sort((a, b) => new Date(b.ts || 0) - new Date(a.ts || 0));

    const typeStyle = {
      HIR:   { color: '#f97316', bg: 'rgba(249,115,22,0.13)', cls: 'stuck-entry-hir' },
      STALL: { color: '#facc15', bg: 'rgba(250,204,21,0.1)',  cls: 'stuck-entry-stall' },
      GATE:  { color: '#60a5fa', bg: 'rgba(96,165,250,0.1)',  cls: 'stuck-entry-stall' },
    };

    wrap.innerHTML = events.map(e => {
      const s   = typeStyle[e.type] || typeStyle.STALL;
      const ts  = e.ts ? new Date(e.ts).toLocaleTimeString() : '';
      const statusColor = e.resolved ? 'var(--green)' : '#f97316';
      const statusText  = e.resolved ? '✓ resolved' : '● active';
      const triedHtml = e.tried.length
        ? `<div style="margin:0.3rem 0 0.15rem">${e.tried.map((t, i) =>
            `<div class="stuck-tried-item"><span class="stuck-tried-num">${i+1}.</span><span>${esc(t)}</span></div>`
          ).join('')}</div>`
        : '';
      const resHtml = e.resolution
        ? `<div class="stuck-resolution">↳ ${esc(e.resolution)}</div>`
        : '';
      return `<div class="stuck-entry ${s.cls}">
        <div class="stuck-entry-header">
          <span class="stuck-type-badge" style="color:${s.color};background:${s.bg};border-color:${s.color}">${e.type}</span>
          <span class="stuck-code">${esc(e.code)}</span>
          <span class="stuck-status" style="color:${statusColor}">${statusText}</span>
          <span class="stuck-ts">${ts}</span>
        </div>
        <div class="stuck-reason">${esc(e.reason)}</div>
        ${triedHtml}${resHtml}
      </div>`;
    }).join('');
  }

  // ── Polling intervals ─────────────────────────────────────────────────────
  setInterval(pollFindings,      POLL_MS);
  setInterval(pollSession,       POLL_MS);
  setInterval(pollIntervention,  3000);    // HIR needs fast response — poll every 3s
  setInterval(pollCoverage,      POLL_MS);
  setInterval(pollSkills,        POLL_MS);
  setInterval(pollThreatModel,   POLL_MS);
  setInterval(pollQA,            POLL_MS);
  setInterval(pollMetrics,       POLL_MS * 6);
  // #status is a shared header shown on every tab, so the "last updated Ns ago"
  // counter must keep ticking regardless of which menu item is open.
  setInterval(() => { if (!scanDone && lastOk) updateFreshness(); }, 1000);
  setInterval(() => { if (!scanDone && _activeTab === 'logs') pollLogs(); }, 3000);
  setInterval(() => { if (_activeTab === 'overview') pollOverview(); }, POLL_MS);
  setInterval(() => { if (_activeTab === 'world-model') pollWorldModel(); }, POLL_MS);

  // Request browser notification permission on load
  _requestNotifPermission();

  // Initial load
  pollOverview();
  pollFindings();
  pollSession();
  pollIntervention();
  pollCoverage();
  pollSkills();
  pollThreatModel();
  pollLogs();
  pollQA();
  pollMetrics();
