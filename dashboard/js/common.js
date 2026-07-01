  // ── Dashboard auth: per-session bearer token ────────────────────────────────
  // The MCP server mints a random token when a scan starts and prints the
  // dashboard URL with it in the fragment (…/#k=<token>). Capture it into
  // sessionStorage (never sent to the server via the URL), strip it from the
  // address bar, and attach it as `Authorization: Bearer …` on every same-origin
  // API call. Closes the unauthenticated-control-plane / CSRF / DNS-rebind class:
  // a cross-origin or rebound page can neither read the token (origin-scoped
  // storage) nor set the Authorization header without a CORS preflight that has
  // no allow. (A same-origin XSS still holds the token — that is handled by
  // output escaping/sanitization, not here.)
  (function initDashboardAuth() {
    const KEY = 'smith_dash_token';
    function token() {
      try { return sessionStorage.getItem(KEY) || ''; } catch (_) { return ''; }
    }
    try {
      const m = (location.hash || '').match(/[#&]k=([^&]+)/);
      if (m) {
        sessionStorage.setItem(KEY, decodeURIComponent(m[1]));
        history.replaceState(null, '', location.pathname + location.search);
      }
    } catch (_) { /* storage unavailable — wrapper simply no-ops */ }

    const _origFetch = window.fetch.bind(window);
    window.fetch = function (input, init) {
      let sameOrigin = true;
      try {
        const raw = (typeof input === 'string') ? input : (input && input.url) || '';
        sameOrigin = new URL(raw, location.href).origin === location.origin;
      } catch (_) { sameOrigin = true; }
      const t = token();
      if (sameOrigin && t) {
        init = init ? Object.assign({}, init) : {};
        const h = new Headers(init.headers || (typeof input !== 'string' && input && input.headers) || {});
        if (!h.has('Authorization')) h.set('Authorization', 'Bearer ' + t);
        init.headers = h;
      }
      return _origFetch(input, init);
    };

    // No token yet (bare URL / bookmark)? Ask once — the CLI prints the key with
    // the dashboard URL. Blank just leaves calls unauthenticated, which is fine
    // before a scan has started (nothing sensitive is served).
    try {
      if (!token()) {
        const pasted = window.prompt(
          'Dashboard key required.\nPaste the key printed with the dashboard URL ' +
          '(leave blank if no scan has started yet):'
        );
        if (pasted) sessionStorage.setItem(KEY, pasted.trim());
      }
    } catch (_) { /* non-interactive context */ }
  })();

  // ── HTML sanitizer for untrusted markdown (threat-model tab) ────────────────
  // marked@9 passes raw HTML through, and scan-derived markdown embeds
  // attacker-influenced recon strings. Render marked's output through this
  // allow-list DOM sanitizer before innerHTML so injected tags / event handlers
  // / scripts / javascript: URLs cannot execute. Keeps <pre><code class=…> so the
  // mermaid post-processing still finds language-mermaid blocks.
  const _SANITIZE_ALLOWED_TAGS = new Set([
    'A','P','DIV','SPAN','BR','HR','PRE','CODE','BLOCKQUOTE','KBD','SMALL',
    'H1','H2','H3','H4','H5','H6','UL','OL','LI','STRONG','EM','B','I','U',
    'DEL','INS','SUP','SUB','TABLE','THEAD','TBODY','TFOOT','TR','TH','TD','DL','DT','DD','IMG',
  ]);
  const _SANITIZE_ALLOWED_ATTRS = new Set([
    'href','src','alt','title','class','colspan','rowspan','align','start',
  ]);
  const _SANITIZE_DROP_TAGS = new Set([
    'SCRIPT','STYLE','IFRAME','OBJECT','EMBED','FORM','LINK','META','BASE','SVG','MATH','TEMPLATE',
  ]);
  function sanitizeHtml(html) {
    const doc = new DOMParser().parseFromString(String(html), 'text/html');
    const walk = (root) => {
      [...root.children].forEach((el) => {
        const tag = el.tagName;
        if (!_SANITIZE_ALLOWED_TAGS.has(tag)) {
          if (_SANITIZE_DROP_TAGS.has(tag)) { el.remove(); return; }
          const span = doc.createElement('span');   // unwrap unknown tags to text
          span.textContent = el.textContent;
          el.replaceWith(span);
          return;
        }
        [...el.attributes].forEach((a) => {
          const name = a.name.toLowerCase();
          if (!_SANITIZE_ALLOWED_ATTRS.has(name)) { el.removeAttribute(a.name); return; }
          if (name === 'href' || name === 'src') {
            const v = (a.value || '').replace(/[\u0000-\u0020]+/g, '').toLowerCase();
            if (v.startsWith('javascript:') || v.startsWith('vbscript:') ||
                (v.startsWith('data:') && !v.startsWith('data:image/'))) {
              el.removeAttribute(a.name);
            }
          }
        });
        walk(el);
      });
    };
    walk(doc.body);
    return doc.body.innerHTML;
  }

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
  const TAB_NAMES = ['findings', 'topology', 'components', 'coverage', 'skills', 'activity', 'threat-model', 'metrics', 'setup-gates', 'logs'];

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
    if (name === 'setup-gates')   pollSetupGates();
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

  let _smithStatus = {};   // latest /api/smith-status (running, idle, heartbeat_age_s)
  async function _pollSmithStatus() {
    try {
      const [sessionRes, smithRes] = await Promise.all([
        fetch(`/api/session?_=${Date.now()}`).then(r => r.json()).catch(() => ({})),
        fetch(`/api/smith-status?_=${Date.now()}`).then(r => r.ok ? r.json() : {running: null}).catch(() => ({running: null})),
      ]);
      _smithStatus = smithRes || {};
      // Re-render the triage banner with the freshest idle signal.
      if (_sessionData) _renderTriageBanner(_sessionData);

      // Update Smith process status badge
      // smithRes.running: true=running, false=confirmed stopped, null=unknown (old server / no endpoint)
      // Only show red "stopped" when a scan is actively running AND Smith is confirmed stopped.
      // Without an active scan, Smith being "idle" is expected — show it as running/ready, not broken.
      const processEl = document.getElementById('cmd-smith-process-status');
      const scanActive = ['running', 'intervention_required'].includes(sessionRes?.status);
      if (processEl) {
        const confirmedStopped = smithRes.running === false && scanActive;
        if (smithRes.running === true || !scanActive) {
          // Running, OR no active scan (idle is fine — not an error state).
          // A post-complete triage relaunch reports adjudicating=true — label it
          // as such so it reads as intended work, not a hung/stuck scan.
          processEl.textContent = (smithRes.running === true && smithRes.adjudicating) ? 'adjudicating'
                                : smithRes.running === true ? 'running' : 'idle';
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
        // Only assert the "keep testing" hint while the scan is actually running.
        // On a stopped scan, renderCmdCenter owns the hint (post-scan triage
        // guidance) — don't clobber it here on the 10s poll.
        if (hint && scanActive) hint.textContent = 'Only you can end the scan — Smith will keep testing until you do.';
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
        if (fb)  fb.textContent = '✓ Scan marked complete';
        if (btn) btn.textContent = '✓ Completed';
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

  // Hard stop — flips the session terminal, cancels triage, AND kills the live
  // Smith process (POST /api/force-stop). Unlike Complete Scan it doesn't leave
  // a mid-adjudication Smith running. Two-step inline confirm (destructive).
  let _forceStopConfirmExpires = 0;
  function _fsSet(btn, fb, btnText, fbText) {
    if (btn && btnText != null) btn.textContent = btnText;
    if (fb  && fbText  != null) fb.textContent  = fbText;
  }
  async function forceStop() {
    const btn = document.getElementById('cmd-force-stop-btn');
    const fb  = document.getElementById('cmd-smith-feedback');
    const now = Date.now();
    if (now > _forceStopConfirmExpires) {           // first click arms the confirm
      _forceStopConfirmExpires = now + 5000;
      _fsSet(btn, fb, '⚠ Click again to force stop',
             'Click again within 5 s — kills Smith and ends the scan (findings are kept).');
      setTimeout(() => {
        if (Date.now() >= _forceStopConfirmExpires && btn && !btn.disabled) btn.textContent = '✕ Force stop';
      }, 5000);
      return;
    }
    _forceStopConfirmExpires = 0;
    if (btn) btn.disabled = true;
    _fsSet(btn, fb, null, 'Stopping Smith…');
    try {
      const res = await (await fetch('/api/force-stop', { method: 'POST' })).json();
      if (res.ok) {
        _fsSet(btn, fb, '✓ Stopped',
               '✓ Smith stopped' + (res.killed ? ' (pid ' + res.pid + ' killed)' : ''));
        pollSession(); pollFindings(); pollIntervention(); _pollSmithStatus();
        return;
      }
      _fsSet(btn, fb, '✕ Force stop', '✗ Failed: ' + (res.error || 'unknown'));
    } catch (e) {
      _fsSet(btn, fb, '✕ Force stop', '✗ Request failed');
    }
    if (btn) btn.disabled = false;
  }

  // Operator-triggered triage (adjudication) pass — wakes Smith to record a
  // verdict on every un-adjudicated high/critical finding WITHOUT completing
  // the scan. Independent of completeScan() by design.
  async function triageFindings() {
    const btn = document.getElementById('cmd-triage-btn');
    const fb  = document.getElementById('cmd-smith-feedback');
    if (btn) { btn.disabled = true; btn.textContent = '⏳ Triaging…'; }
    if (fb)  fb.textContent = 'Requesting triage pass…';
    try {
      const r = await fetch('/api/triage', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({}),
      });
      const res = await r.json();
      if (res.ok && res.status === 'triaging') {
        const spawnedNote = res.smith_spawned ? ' — Smith relaunched to review' : '';
        if (fb) fb.textContent = '⏳ Triaging ' + (res.pending_adjudication || '') + ' finding(s)…' + spawnedNote;
        _showAdjudicationBanner(true);
      } else if (res.ok && res.status === 'nothing_to_triage') {
        if (fb) fb.textContent = 'Nothing to triage — no findings awaiting a verdict.';
      } else {
        if (fb) fb.textContent = '✗ Failed: ' + (res.error || 'unknown');
      }
      pollSession();
      pollFindings();
      _pollSmithStatus();
    } catch(e) {
      if (fb) fb.textContent = '✗ Request failed';
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = '⚖ Triage findings'; }
    }
  }

  function _showAdjudicationBanner(show) {
    const banner = document.getElementById('adjudication-banner');
    if (banner) banner.style.display = show ? '' : 'none';
  }

  // How long the triage pass may go without a new verdict before the banner
  // flips to the "stalled" warning. Progress-based (triage_idle_s) so a slow-
  // but-advancing pass never trips it; the MCP heartbeat (_smithStatus.idle) is
  // a secondary trigger for when Smith dies outright.
  const _TRIAGE_STALL_S = 90;

  // Stateful triage banner: hidden when no pass is in flight; "in progress"
  // while Smith is actively recording verdicts; and a steady red "stalled"
  // warning when the pass stops advancing with verdicts still pending (Smith
  // likely stopped to ask what's next, or wandered off to other testing).
  // Always carries Re-nudge / Dismiss actions so the operator is never stuck
  // staring at a banner that won't clear.
  function _renderTriageBanner(s) {
    const banner = document.getElementById('adjudication-banner');
    const msg    = document.getElementById('adjudication-banner-msg');
    if (!banner) return;
    // A triage pass is in flight whenever the flag is set — on a running scan
    // (legacy mid-scan triage) OR on a stopped scan (post-scan triage). The flag
    // is cleared by the /api/session self-heal once every finding has a verdict.
    const active = !!(s && s.triage_requested);
    if (!active) { banner.style.display = 'none'; banner.classList.remove('adjudication-banner-stalled'); return; }
    banner.style.display = '';
    const pend    = (typeof s.pending_adjudication === 'number') ? s.pending_adjudication : null;
    const pendTxt = pend === null ? '' : (pend + ' finding' + (pend === 1 ? '' : 's'));
    // Stalled if no verdict has landed for a while (server-tracked progress
    // clock) OR Smith's process heartbeat has gone cold. The progress clock is
    // the reliable one — it isn't reset by Smith staying busy on other work.
    const noProgress = (typeof s.triage_idle_s === 'number') && s.triage_idle_s >= _TRIAGE_STALL_S;
    const heartCold  = !!(_smithStatus && _smithStatus.idle);
    if (noProgress || heartCold) {
      banner.classList.add('adjudication-banner-stalled');
      if (msg) msg.innerHTML = '⚠ Triage stalled — Smith stopped recording verdicts' +
        (pendTxt ? ' with ' + pendTxt + ' still awaiting one' : '') +
        '. It may be waiting on you — re-nudge it, or dismiss to clear.';
    } else {
      banner.classList.remove('adjudication-banner-stalled');
      if (msg) msg.innerHTML = '⏳ Triage in progress — Smith is recording verdicts' +
        (pendTxt ? ' (' + pendTxt + ' left)' : '') + '…';
    }
  }

  async function reNudgeTriage() {
    const fb = document.getElementById('cmd-smith-feedback');
    if (fb) fb.textContent = 'Re-nudging Smith to resume triage…';
    try {
      await fetch('/api/triage', { method: 'POST', headers: {'Content-Type':'application/json'}, body: '{}' });
    } catch (e) { if (fb) fb.textContent = '✗ Re-nudge failed'; }
    pollSession();
    _pollSmithStatus();
  }

  async function cancelTriage() {
    const fb = document.getElementById('cmd-smith-feedback');
    try {
      await fetch('/api/triage-cancel', { method: 'POST' });
      if (fb) fb.textContent = 'Triage dismissed.';
    } catch (e) { if (fb) fb.textContent = '✗ Dismiss failed'; }
    _showAdjudicationBanner(false);
    pollSession();
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

    // Complete vs Triage button visibility.
    // While the scan runs, the operator can only Complete it. Triage is a
    // POST-scan action: once the scan is stopped the Complete button is retired
    // and the Triage button appears — clicking it (re)spawns Smith to adjudicate
    // the findings (see triageFindings / POST /api/triage). Mutually exclusive so
    // the operator is never offered both at once.
    const terminal      = _isTerminalStatus(session.status);
    const completeBtn   = document.getElementById('cmd-complete-btn');
    const triageBtn     = document.getElementById('cmd-triage-btn');
    const triageHint    = document.getElementById('cmd-smith-status-hint');
    if (completeBtn) completeBtn.style.display = terminal ? 'none' : '';
    if (triageBtn)   triageBtn.style.display   = terminal ? '' : 'none';
    if (triageHint && terminal && !session.triage_requested) {
      triageHint.textContent = 'Scan stopped. Run triage to relaunch Smith and have it adjudicate the findings.';
    }
  }

  // Terminal (stopped) scan states — anything that is not actively running and
  // not paused for human intervention.
  function _isTerminalStatus(st) {
    return ['complete', 'incomplete_with_unresolved_blockers', 'limit_reached'].includes(st);
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

      // Stateful triage banner (progress / stalled) with operator actions.
      _renderTriageBanner(s);

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

      // Self-heal the completion latch. scanDone is one-way — set true on
      // 'complete' (below) and otherwise only cleared by the manual Clear
      // button — so after ANY completion or force-stop, every scanDone-gated
      // poller (logs, skills, threat-model, the findings re-render) stayed
      // frozen until a hard refresh, even once a new or watchdog-resumed scan
      // was running again. Clear it whenever the scan is active so the dashboard
      // recovers on its own instead of needing a manual reload.
      if (scanDone && s.status !== 'complete') {
        scanDone = false;
        if (s.status === 'running') {
          document.getElementById('status').innerHTML =
            '<span class="dot"></span>Live · refreshes every 5 s';
        }
      }

      if (s.status === 'complete' && !scanDone) {
        scanDone = true;
        _showAdjudicationBanner(false);
        document.getElementById('status').innerHTML =
          '<span class="dot" style="background:#6e7681;animation:none"></span>Scan complete';
        const statusEl = document.getElementById('cmd-scan-status');
        if (statusEl) { statusEl.textContent = 'complete'; statusEl.className = 'cmd-scan-status complete'; }
        // Refresh findings to pick up adjudication verdicts written before close.
        pollFindings();
        _notify('Scan complete', 'Smith has finished — check the Findings tab.', 'normal');
        setTimeout(_clearNotif, 8000);  // restore plain title after 8s
      }
    } catch { /* session may not exist yet */ }
  }

  // ── Findings tab ──────────────────────────────────────────────────────────