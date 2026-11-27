  // Everything that blocked or paused the scan: pauses for the operator's input,
  // stalled coverage, and blocked steps. A data source for the Activity
  // timeline (activity.js) — it no longer renders a section of its own.
  function _collectStuckEvents() {
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

    return events;
  }

  // Kept under its old name: several pollers call it when new data arrives.
  function renderStuckLog() {
    if (typeof renderActivityFeed === 'function') renderActivityFeed();
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
  // Sessions: poll in the background (not tab-gated) so a newly auto-started /
  // watchdog-respawned session toasts and appears within seconds, even when the
  // operator is on another tab (issue #187, acceptance #1 & #4).
  setInterval(pollSessions,      POLL_MS * 2);
  // Operator Actions (wishlist + setup gates): poll in the background, not
  // tab-gated, so a new resource request toasts and badges the tab within
  // seconds even when the operator is elsewhere (issue #181).
  setInterval(pollSetupGates,    POLL_MS);
  // #status is a shared header shown on every tab, so the "last updated Ns ago"
  // counter must keep ticking regardless of which menu item is open.
  setInterval(() => { if (!scanDone && lastOk) updateFreshness(); }, 1000);
  setInterval(() => { if (!scanDone && _activeTab === 'logs') pollLogs(); }, 3000);
  setInterval(() => { if (!scanDone && _activeTab === 'session-log') pollSessionLog(); }, 3000);
  setInterval(() => { if (_activeTab === 'overview') pollOverview(); }, POLL_MS);
  setInterval(() => { if (_activeTab === 'activity') pollToolResults(); }, POLL_MS);
  setInterval(() => { if (_activeTab === 'world-model') pollWorldModel(); }, POLL_MS);
  setInterval(() => { if (_activeTab === 'ai-redteam') pollAiRedteam(); }, POLL_MS);

  // Request browser notification permission on load
  _requestNotifPermission();

  // Apply any persisted collapsed state to the rail groups.
  _initRailGroups();

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
  pollSessions();
  pollSetupGates();
