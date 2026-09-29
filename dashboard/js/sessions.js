// ── Sessions tab (issue #187) ─────────────────────────────────────────────────
// Lists every scan session (operator / watchdog-respawned / implicit) from
// /api/sessions, badges auto-started ones, highlights sessions new since the
// operator last VIEWED this tab, toasts a brand-new auto-started session, and
// links each row to its Session Log replay. FLAT classic script sharing the
// global dashboard scope (NOT an IIFE) — identifiers are prefixed to avoid
// colliding with other tab scripts.

let _sessionsSeen = null;        // Set<id> the operator has already looked at (localStorage-backed)
let _sessionsInit = false;       // first pollSessions has run (so we don't toast the backlog)

function _sessEsc(s) {
  return String(s == null ? '' : s).replace(/[&<>"]/g,
    c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

function _sessLoadSeen() {
  if (_sessionsSeen) return _sessionsSeen;
  try { _sessionsSeen = new Set(JSON.parse(localStorage.getItem('smith_sessions_seen') || '[]')); }
  catch (e) { _sessionsSeen = new Set(); }
  return _sessionsSeen;
}

function _sessSaveSeen(seen) {
  try { localStorage.setItem('smith_sessions_seen', JSON.stringify(Array.from(seen).slice(-300))); }
  catch (e) { /* private mode / blocked storage — highlight just won't persist */ }
}

// Row click → replay that session's reasoning in the Session Log tab (issue #186).
function openSessionInLog(id) {
  try { _selectedSessionId = id; } catch (e) { /* session-log.js may not be loaded yet */ }
  try { switchTab('session-log'); } catch (e) { return; }
  const sel = document.getElementById('session-log-select');
  if (sel) sel.value = id;
  try { pollSessionLog(); } catch (e) { /* refresh will catch up */ }
}

async function pollSessions() {
  let data;
  try {
    const r = await fetch('/api/sessions?_=' + Date.now());
    if (!r.ok) return;
    data = await r.json();
  } catch (e) { return; }

  const rows = data.sessions || [];
  const seen = _sessLoadSeen();
  const out = document.getElementById('sessions-output');
  const summary = document.getElementById('sessions-summary');

  // Toast a brand-new auto-started session (acceptance #4) — only after the first
  // load, so a fresh browser doesn't toast the whole backlog at once.
  if (_sessionsInit) {
    for (const s of rows) {
      if (s.auto_started && !seen.has(s.id) && typeof _notify === 'function') {
        _notify('Auto-started session', `${s.origin} · ${s.target || s.id.slice(0, 8)}`);
      }
    }
  }
  _sessionsInit = true;

  if (summary) {
    const auto = rows.filter(s => s.auto_started).length;
    summary.textContent =
      `${rows.length} session${rows.length === 1 ? '' : 's'} · ${auto} auto-started · ` +
      `current: ${data.current ? data.current.slice(0, 8) : 'none'}`;
  }

  if (!rows.length) {
    if (out) out.innerHTML = '<div class="empty-placeholder">No sessions yet.</div>';
    return;
  }

  const body = rows.map(s => {
    const isNew = !seen.has(s.id);
    const badge = s.auto_started
      ? `<span class="badge-auto">${_sessEsc((s.origin || 'auto').toUpperCase())}</span>`
      : '<span class="badge-op">OPERATOR</span>';
    const cur = s.id === data.current ? ' <span class="badge-cur">CURRENT</span>' : '';
    const started = s.started ? new Date(s.started).toLocaleString() : '—';
    return `<tr class="sess-row${isNew ? ' sess-new' : ''}" onclick="openSessionInLog('${_sessEsc(s.id)}')" title="Replay this session's reasoning">
      <td>${badge}${cur}</td>
      <td>${_sessEsc(s.target || '—')}</td>
      <td><span class="sess-status sess-${_sessEsc(s.status)}">${_sessEsc(s.status)}</span></td>
      <td style="text-align:right">${_sessEsc(s.findings)}</td>
      <td>${_sessEsc(started)}</td>
      <td class="sess-id">${_sessEsc(s.id.slice(0, 8))}</td>
    </tr>`;
  }).join('');

  if (out) {
    out.innerHTML = `<table class="sessions-table">
      <thead><tr><th>Origin</th><th>Target</th><th>Status</th><th style="text-align:right">Findings</th><th>Started</th><th>ID</th></tr></thead>
      <tbody>${body}</tbody></table>`;
  }

  // "New since last looked": only clear the highlight when the operator is actually
  // VIEWING this tab, so sessions that appear in the background stay highlighted
  // until seen.
  if (typeof _activeTab !== 'undefined' && _activeTab === 'sessions') {
    for (const s of rows) seen.add(s.id);
    _sessSaveSeen(seen);
  }
}
