  mermaid.initialize({
    startOnLoad: false,
    theme: 'base',
    themeVariables: {
      // Background
      background: '#0d1117',
      primaryColor: '#1f2937',
      primaryTextColor: '#e5e7eb',
      primaryBorderColor: '#374151',
      // Secondary (decisions, conditions)
      secondaryColor: '#1e3a5f',
      secondaryTextColor: '#e5e7eb',
      secondaryBorderColor: '#2563eb',
      // Tertiary
      tertiaryColor: '#2d1f3d',
      tertiaryTextColor: '#e5e7eb',
      tertiaryBorderColor: '#7c3aed',
      // Lines and text
      lineColor: '#6b7280',
      textColor: '#e5e7eb',
      // Notes
      noteBkgColor: '#1e293b',
      noteTextColor: '#cbd5e1',
      noteBorderColor: '#334155',
      // Fonts — consistent size
      fontSize: '14px',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
    },
    flowchart: { curve: 'linear', htmlLabels: false },
  });

  const POLL_MS   = 5000;
  const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

  let filter     = 'all';
  let vfilter    = 'all';
  let seenIds    = new Set();
  let scanDone   = false;   // true once session status is "complete" — stops polling
  let freshIds   = new Set();
  let allData    = { findings: [], diagrams: [] };
  let lastOk     = null;
  let _steeringData = null;
  let _sessionData  = null;
  let _activeTab = 'findings';
  let _logLines  = [];

  // ── Notification system ───────────────────────────────────────────────────
  // Tracks state so we only fire once per event, not on every poll.
  let _notifState = { hir: false, stall: false, alertCount: 0 };

  function _requestNotifPermission() {
    // Browsers (Firefox in particular) now reject requestPermission() unless
    // it is called inside a short-running user gesture (click/keydown).
    // We piggy-back on the FIRST user interaction with the page, then remove
    // the listeners so this runs at most once.
    if (!('Notification' in window) || Notification.permission !== 'default') return;
    const handler = () => {
      document.removeEventListener('click',   handler, true);
      document.removeEventListener('keydown', handler, true);
      try { Notification.requestPermission().catch(() => {}); } catch {}
    };
    document.addEventListener('click',   handler, true);
    document.addEventListener('keydown', handler, true);
  }

  function _notify(title, body, urgency = 'normal') {
    // Always update the page title
    document.title = `⚠ ${title} — Pentest Dashboard`;
    // Browser notification only when tab is not focused
    if (document.hidden && 'Notification' in window && Notification.permission === 'granted') {
      try {
        const n = new Notification(title, {
          body,
          icon: '/logo.png',
          tag: urgency === 'critical' ? 'hir' : 'alert',  // same tag = replaces previous
          requireInteraction: urgency === 'critical',       // HIR stays until dismissed
        });
        n.onclick = () => { window.focus(); n.close(); };
      } catch { /* ignore */ }
    }
  }

  function _clearNotif() {
    document.title = 'Pentest Dashboard';
  }

  function _updateTitleBadge(alertCount, stallActive, hirActive) {
    if (hirActive) {
      document.title = '⚠ PAUSED — Pentest Dashboard';
    } else if (stallActive) {
      document.title = '⟳ Smith needs guidance — Pentest Dashboard';
    } else if (alertCount > 0) {
      document.title = `(${alertCount}) Pentest Dashboard`;
    } else {
      document.title = 'Pentest Dashboard';
    }
  }

  // ── Tab switching ─────────────────────────────────────────────────────────
  const TAB_NAMES = ['findings', 'topology', 'components', 'coverage', 'skills', 'activity', 'threat-model', 'metrics', 'logs'];

  function switchTab(name) {
    _activeTab = name;
    document.querySelectorAll('.tab-btn').forEach((b, i) => {
      b.classList.toggle('active', TAB_NAMES[i] === name);
    });
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.getElementById(`tab-${name}`).classList.add('active');
    if (name === 'topology')      renderTopology(allData.diagrams || []);
    if (name === 'components')    renderComponentMap(allData.findings || []);
    if (name === 'coverage')      pollCoverage();
    if (name === 'skills')        pollSkills();
    if (name === 'activity') {
      // Immediately paint whatever data we already have so the tab is not
      // empty while pollQA's fetch is in flight, then refresh from the wire.
      _safeRender('stuckLog',        renderStuckLog);
      _safeRender('QA',              renderQA);
      _safeRender('steering',        renderSteering);
      _safeRender('quickLog',        renderQuickLog);
      _safeRender('cycleHistory',    renderCycleHistory);
      renderAdjudicationLog();
      pollQA();
    }
    if (name === 'metrics')       pollMetrics();
    if (name === 'threat-model')  pollThreatModel();
    if (name === 'logs')          pollLogs();
  }

  // ── HIR panel ────────────────────────────────────────────────────────────
  let _hirActive = false;
  let _hirSelectedChoice = '';

  async function pollIntervention() {
    try {
      const r = await fetch('/api/intervention?_=' + Date.now());
      if (!r.ok) return;
      const iv = await r.json();
      const panel = document.getElementById('hir-panel');
      if (iv.active) {
        if (!_hirActive) {
          // First time we see this HIR — fire OS notification
          _notify(
            'Smith needs your decision',
            (iv.situation || 'Scan paused — human intervention required').slice(0, 120),
            'critical'
          );
          _notifState.hir = true;
        }
        _hirActive = true;
        panel.classList.add('visible');
        document.getElementById('hir-code').textContent = iv.code || 'HIR';
        document.getElementById('hir-situation').textContent = iv.situation || '';
        const optEl = document.getElementById('hir-options');
        optEl.innerHTML = '';
        (iv.options || []).forEach(opt => {
          const choice = opt.split('—')[0].trim().split(' ')[0];
          const btn = document.createElement('button');
          btn.className = 'hir-opt-btn';
          btn.textContent = opt.length > 60 ? opt.slice(0, 60) + '…' : opt;
          btn.title = opt;
          btn.onclick = () => {
            document.querySelectorAll('.hir-opt-btn').forEach(b => b.classList.remove('selected'));
            btn.classList.add('selected');
            _hirSelectedChoice = choice;
            document.getElementById('hir-message').placeholder = `${choice} — add details or just click Send`;
          };
          optEl.appendChild(btn);
        });
        // Show tried items
        const triedWrap = document.getElementById('hir-tried-wrap');
        const triedEl   = document.getElementById('hir-tried');
        const tried = iv.tried || [];
        if (tried.length && triedWrap && triedEl) {
          triedEl.innerHTML = tried.map((t, i) =>
            `<div class="hir-tried-item"><span class="hir-tried-num">${i+1}.</span><span>${esc(t)}</span></div>`
          ).join('');
          triedWrap.style.display = '';
        } else if (triedWrap) {
          triedWrap.style.display = 'none';
        }
        // Highlight Smith command box as orange (HIR mode)
        const inp = document.getElementById('cmd-smith-input');
        const btn = document.getElementById('cmd-smith-send-btn');
        const hint = document.getElementById('cmd-smith-hint');
        if (inp) inp.classList.add('hir-active');
        if (btn) btn.classList.add('hir-mode');
        if (hint) hint.textContent = '— scan is paused, your response resumes it';
        const dotEl = document.getElementById('cmd-smith-dot');
        if (dotEl) { dotEl.style.background = '#f97316'; dotEl.style.boxShadow = '0 0 6px #f97316'; }
        document.getElementById('status').innerHTML = '<span class="dot" style="background:#f97316;box-shadow:0 0 6px #f97316;animation:blink 1s infinite"></span>⚠ Scan paused — human intervention required';
        // Update cmd-scan-status
        const statusEl = document.getElementById('cmd-scan-status');
        if (statusEl) { statusEl.textContent = 'intervention'; statusEl.className = 'cmd-scan-status intervention'; }
      } else if (_hirActive) {
        _hirActive = false;
        _notifState.hir = false;
        panel.classList.remove('visible');
        _hirSelectedChoice = '';
        const inp = document.getElementById('cmd-smith-input');
        const btn = document.getElementById('cmd-smith-send-btn');
        const hint = document.getElementById('cmd-smith-hint');
        if (inp) inp.classList.remove('hir-active');
        if (btn) btn.classList.remove('hir-mode');
        if (hint) hint.textContent = '';
        const dotEl = document.getElementById('cmd-smith-dot');
        if (dotEl) { dotEl.style.background = ''; dotEl.style.boxShadow = ''; }
        _updateTitleBadge(0, false, false);
      }
      _updateTitleBadge(_notifState.alertCount, _notifState.stall, _hirActive);
    } catch { /* ignore */ }
  }

  function dismissHir() {
    document.getElementById('hir-panel').classList.remove('visible');
  }

  async function sendHirResponse() {
    const choice  = _hirSelectedChoice;
    const message = document.getElementById('hir-message').value.trim();
    if (!choice && !message) { alert('Select an option or type a message.'); return; }
    const btn = document.getElementById('hir-send-btn');
    btn.disabled = true; btn.textContent = 'Sending…';
    try {
      const r = await fetch('/api/intervention/respond', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({choice, message}),
      });
      const res = await r.json();
      if (res.ok) {
        document.getElementById('hir-panel').classList.remove('visible');
        document.getElementById('hir-message').value = '';
        _hirSelectedChoice = '';
        _hirActive = false;
      } else {
        alert('Failed: ' + (res.error || 'unknown error'));
      }
    } catch(e) { alert('Request failed: ' + e.message); }
    btn.disabled = false; btn.textContent = 'Send Response';
  }

  // ── Command center — Smith input ──────────────────────────────────────────
  function setSmithChip(text) {
    const inp = document.getElementById('cmd-smith-input');
    if (inp) { inp.value = text; inp.focus(); }
  }

  async function sendCmdSmith() {
    const inp = document.getElementById('cmd-smith-input');
    const msg = inp ? inp.value.trim() : '';
    if (!msg) return;
    const btn = document.getElementById('cmd-smith-send-btn');
    const fb  = document.getElementById('cmd-smith-feedback');
    if (btn) btn.disabled = true;
    if (fb)  fb.textContent = 'Sending…';
    try {
      const endpoint = _hirActive ? '/api/intervention/respond' : '/api/steer';
      const payload  = _hirActive ? {choice: _hirSelectedChoice, message: msg} : {message: msg};
      const r = await fetch(endpoint, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload),
      });
      const res = await r.json();
      if (res.ok || res.ok === undefined) {
        if (fb)  fb.textContent = '✓ Sent to Smith';
        if (inp) inp.value = '';
        if (_hirActive) {
          document.getElementById('hir-panel').classList.remove('visible');
          _hirSelectedChoice = '';
          _hirActive = false;
          const inpEl = document.getElementById('cmd-smith-input');
          const btnEl = document.getElementById('cmd-smith-send-btn');
          const hintEl = document.getElementById('cmd-smith-hint');
          if (inpEl)  inpEl.classList.remove('hir-active');
          if (btnEl)  btnEl.classList.remove('hir-mode');
          if (hintEl) hintEl.textContent = '';
        }
        setTimeout(() => { if (fb) fb.textContent = ''; }, 3000);
      } else {
        if (fb) fb.textContent = '✗ Failed: ' + (res.error || 'unknown');
      }
    } catch(e) { if (fb) fb.textContent = '✗ Request failed'; }
    if (btn) btn.disabled = false;
  }

  let _activeClient = 'claude';   // refreshed from /api/smith-clients

  async function restartSmith() {
    const btn   = document.getElementById('cmd-restart-btn');
    const label = document.getElementById('cmd-restart-label');
    const fb    = document.getElementById('cmd-smith-feedback');
    const hint  = document.getElementById('cmd-smith-status-hint');
    if (btn) btn.disabled = true;
    if (fb)  fb.textContent = 'Starting ' + _activeClient + '…';
    try {
      // No body — server auto-detects which client to spawn
      const r = await fetch('/api/restart-smith', { method: 'POST' });
      const res = await r.json();
      if (res.ok) {
        if (fb)   fb.textContent = '✓ ' + (res.client || _activeClient) + ' restarted (PID ' + res.pid + ')';
        if (btn) { btn.style.display = 'none'; btn.disabled = false; }
        if (hint) hint.textContent = 'Smith is running — only you can end the scan.';
        pollSession();
        pollIntervention();
        setTimeout(() => { if (fb) fb.textContent = ''; }, 4000);
      } else {
        if (fb)  fb.textContent = '✗ ' + (res.error || 'Failed');
        if (btn) btn.disabled = false;
      }
    } catch(e) {
      if (fb)  fb.textContent = '✗ Request failed';
      if (btn) btn.disabled = false;
    }
  }

  async function _refreshActiveClient() {
    try {
      const r  = await fetch('/api/smith-clients?_=' + Date.now());
      const av = await r.json();
      _activeClient = av.active || 'claude';
      const label = document.getElementById('cmd-restart-label');
      if (label) label.textContent = 'Restart Smith (' + _activeClient + ')';
    } catch(e) {}
  }
  _refreshActiveClient();
  setInterval(_refreshActiveClient, 30000);

  async function _pollSmithStatus() {
    try {
      const [sessionRes, smithRes] = await Promise.all([
        fetch(`/api/session?_=${Date.now()}`).then(r => r.json()).catch(() => ({})),
        fetch(`/api/smith-status?_=${Date.now()}`).then(r => r.ok ? r.json() : {running: null}).catch(() => ({running: null})),
      ]);

      // Update Smith process status badge
      // smithRes.running: true=running, false=confirmed stopped, null=unknown (old server / no endpoint)
      // Only show red "stopped" when a scan is actively running AND Smith is confirmed stopped.
      // Without an active scan, Smith being "idle" is expected — show it as running/ready, not broken.
      const processEl = document.getElementById('cmd-smith-process-status');
      const scanActive = ['running', 'intervention_required'].includes(sessionRes?.status);
      if (processEl) {
        const confirmedStopped = smithRes.running === false && scanActive;
        if (smithRes.running === true || !scanActive) {
          // Running, OR no active scan (idle is fine — not an error state)
          processEl.textContent = smithRes.running === true ? 'running' : 'idle';
          processEl.className = 'cmd-smith-process-status cmd-smith-process-running';
        } else if (confirmedStopped) {
          processEl.textContent = 'stopped';
          processEl.className = 'cmd-smith-process-status cmd-smith-process-stopped';
        } else {
          // null = endpoint unavailable — default to running to avoid false alarms
          processEl.textContent = 'running';
          processEl.className = 'cmd-smith-process-status cmd-smith-process-running';
        }
      }

      // Show/hide restart button — only when scan is active AND Smith is confirmed stopped
      const restartBtn = document.getElementById('cmd-restart-btn');
      const hint       = document.getElementById('cmd-smith-status-hint');
      if (!restartBtn) return;

      if (scanActive && smithRes.running === false) {
        restartBtn.style.display = 'inline-block';
        restartBtn.disabled = false;   // reset in case a prior click left it disabled
        if (hint) hint.textContent = 'Smith has stopped — restart it to continue the scan.';
      } else {
        restartBtn.style.display = 'none';
        if (hint) hint.textContent = 'Only you can end the scan — Smith will keep testing until you do.';
      }
    } catch(e) {}
  }

  // Poll Smith process status every 10s
  setInterval(_pollSmithStatus, 10000);
  _pollSmithStatus();

  let _completeConfirmExpires = 0;

  async function completeScan() {
    const btn = document.getElementById('cmd-complete-btn');
    const fb  = document.getElementById('cmd-smith-feedback');
    const now = Date.now();
    // Two-step inline confirm. First click arms; second click within 5s fires.
    // Replaces the browser-native confirm() dialog which was being silently
    // suppressed by Firefox/Chrome's "prevent additional dialogs" toggle —
    // once the user ticked that, the button stopped doing anything visible.
    if (now > _completeConfirmExpires) {
      _completeConfirmExpires = now + 5000;
      if (btn) btn.textContent = '⚠ Click again to confirm';
      if (fb)  fb.textContent = 'Click again within 5 s to complete the scan.';
      setTimeout(() => {
        if (Date.now() >= _completeConfirmExpires) {
          if (btn && !btn.disabled) btn.textContent = '✓ Complete Scan';
          if (fb) fb.textContent = '';
        }
      }, 5000);
      return;
    }
    _completeConfirmExpires = 0;
    if (btn) btn.disabled = true;
    if (fb)  fb.textContent = 'Completing scan…';
    try {
      const r = await fetch('/api/complete', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({notes: 'Completed by human operator via dashboard'}),
      });
      const res = await r.json();
      if (res.ok) {
        if (res.status === 'adjudicating') {
          // Smith will adjudicate findings and auto-complete — show banner.
          // res.smith_spawned tells us the dashboard actively relaunched Smith
          // to run the pass (Smith had gone idle); surface that so the operator
          // sees motion instead of a banner that looks stuck.
          const spawnedNote = res.smith_spawned ? ' — Smith relaunched to review' : '';
          if (fb)  fb.textContent = '⏳ Adjudicating ' + (res.pending_adjudication || '') + ' finding(s) before closing…' + spawnedNote;
          if (btn) btn.textContent = '⏳ Adjudicating…';
          _showAdjudicationBanner(true);
        } else {
          if (fb)  fb.textContent = '✓ Scan marked complete';
          if (btn) btn.textContent = '✓ Completed';
        }
        // Immediately refresh all dashboard state
        pollSession();
        pollFindings();
        pollIntervention();
        _pollSmithStatus();
      } else {
        if (fb) fb.textContent = '✗ Failed: ' + (res.error || 'unknown');
        if (btn) { btn.disabled = false; btn.textContent = '✓ Complete Scan'; }
      }
    } catch(e) {
      if (fb) fb.textContent = '✗ Request failed';
      if (btn) { btn.disabled = false; btn.textContent = '✓ Complete Scan'; }
    }
  }

  function _showAdjudicationBanner(show) {
    const banner = document.getElementById('adjudication-banner');
    if (banner) banner.style.display = show ? '' : 'none';
  }

  // ── Command center rendering ──────────────────────────────────────────────
  function renderCmdCenter(session, coverage) {
    if (!session || !session.target) return;

    document.getElementById('cmd-target').textContent = session.target || '—';

    // Benchmark mode badge
    const benchBadge = document.getElementById('cmd-benchmark-badge');
    if (benchBadge) benchBadge.style.display = session.scan_mode === 'benchmark' ? '' : 'none';

    // Phase + skill pill
    const pill    = document.getElementById('cmd-phase-pill');
    const phTxt   = document.getElementById('cmd-phase-text');
    const skSep   = document.getElementById('cmd-phase-skill-sep');
    const skName  = document.getElementById('cmd-phase-skill');
    if (pill) {
      pill.style.display = '';
      phTxt.textContent  = session.phase || 'recon';
      if (session.skill) {
        skSep.style.display = '';
        skName.textContent  = '/' + session.skill;
        skName.style.display = '';
      } else {
        skSep.style.display  = 'none';
        skName.style.display = 'none';
      }
    }

    // Coverage mini-bar
    const covGroup = document.getElementById('cmd-cov-group');
    if (coverage && coverage.meta && coverage.meta.total_cells > 0) {
      const total    = coverage.meta.total_cells;
      const addressed = coverage.meta.addressed || coverage.meta.tested || 0;
      const pct      = Math.round(addressed / total * 100);
      document.getElementById('cmd-cov-bar').style.width = pct + '%';
      document.getElementById('cmd-cov-bar').className = 'cmd-cov-bar' + (pct < 40 ? ' warn' : '');
      document.getElementById('cmd-cov-txt').textContent = `${addressed}/${total}`;
      if (covGroup) covGroup.style.display = '';
    } else if (covGroup) { covGroup.style.display = 'none'; }

    // Pending gates
    const gatesAlert = document.getElementById('cmd-gates-alert');
    const pending = session.pending_gates || [];
    if (pending.length && gatesAlert) {
      document.getElementById('cmd-gates-count').textContent =
        pending.length + ' gate' + (pending.length > 1 ? 's' : '') + ' pending';
      gatesAlert.style.display = '';
    } else if (gatesAlert) { gatesAlert.style.display = 'none'; }

    // Status
    const statusEl = document.getElementById('cmd-scan-status');
    if (statusEl && session.status !== 'intervention_required') {
      statusEl.textContent = session.status || '—';
      statusEl.className   = 'cmd-scan-status ' + (session.status || 'running').replace(/_/g, '-');
    }
  }

  let _lastCoverage = null;

  async function pollSession() {
    try {
      const [sr, cr] = await Promise.all([
        fetch('/api/session?_=' + Date.now()),
        fetch('/api/coverage?_=' + Date.now()),
      ]);
      if (!sr.ok) return;
      const s   = await sr.json();
      const cov = cr.ok ? await cr.json() : null;
      _lastCoverage = cov;

      if (!s.target) return;

      _sessionData = s;
      renderCmdCenter(s, cov);
      if (_activeTab === 'activity') renderStuckLog();

      // Show/hide adjudication banner based on session flag.
      const adjudicating = s.force_complete_requested && s.status === 'running';
      _showAdjudicationBanner(adjudicating);

      // Cost
      try {
        const cr2 = await fetch('/api/cost?_=' + Date.now());
        if (cr2.ok) {
          const cost = await cr2.json();
          const usd  = cost.est_cost_usd;
          if (usd !== undefined) {
            document.getElementById('cmd-cost-val').textContent = '$' + usd.toFixed(4);
            document.getElementById('cmd-cost-group').style.display = '';
          }
        }
      } catch { /* ignore */ }

      if (s.status === 'complete' && !scanDone) {
        scanDone = true;
        _showAdjudicationBanner(false);
        document.getElementById('status').innerHTML =
          '<span class="dot" style="background:#6e7681;animation:none"></span>Scan complete';
        const statusEl = document.getElementById('cmd-scan-status');
        if (statusEl) { statusEl.textContent = 'complete'; statusEl.className = 'cmd-scan-status complete'; }
        // Refresh findings to pick up adjudication verdicts written before close.
        pollFindings();
        const wasAdjudicating = !!s.force_complete_requested;
        const msg = wasAdjudicating
          ? 'Adjudication complete — findings updated. Check the Findings tab.'
          : 'Smith has finished — check the Findings tab.';
        _notify('Scan complete', msg, 'normal');
        setTimeout(_clearNotif, 8000);  // restore plain title after 8s
      }
    } catch { /* session may not exist yet */ }
  }

  // ── Findings tab ──────────────────────────────────────────────────────────