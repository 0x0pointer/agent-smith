// ── Session Log tab (issue #186) ──────────────────────────────────────────────
// Read-only replay of one session's reasoning stream from /api/session-log.
// FLAT classic script sharing the global dashboard scope (NOT an IIFE) — top-level
// identifiers are prefixed to avoid colliding with other tab scripts.

let _selectedSessionId = '';
let _sessionLogEvents  = [];

// Event-type -> {label, color} for the typed cards.
const _SL_TYPE = {
  note:                { label: 'NOTE',       color: '#a78bfa' },
  decision:            { label: 'DECISION',   color: '#60a5fa' },
  action:              { label: 'ACTION',     color: '#94a3b8' },
  result:              { label: 'RESULT',     color: '#34d399' },
  finding:             { label: 'FINDING',    color: '#f97316' },
  coverage_transition: { label: 'COVERAGE',   color: '#facc15' },
};

async function pollSessionLog() {
  // Deliberately NOT gated on scanDone here: the whole point is reviewing a session
  // AFTER it finishes. The recurring auto-refresh in main.js is what stops when done.
  try {
    const sid = _selectedSessionId ? `&session=${encodeURIComponent(_selectedSessionId)}` : '';
    const r = await fetch(`/api/session-log?_=${Date.now()}${sid}`);
    if (!r.ok) return;
    const data = await r.json();

    // Rebuild the session dropdown. Keep it on the "newest session" placeholder ('')
    // while in newest mode so it always agrees with what the server actually returned
    // (which rotates to a new scan's id) — only pin a concrete id the user chose.
    const sel = document.getElementById('session-log-select');
    if (sel) {
      while (sel.options.length > 1) sel.remove(1);
      for (const s of (data.sessions || [])) {
        const opt = document.createElement('option');
        opt.value = s.id;
        const bits = [];
        if (s.target)  bits.push(s.target);
        if (s.started) bits.push(new Date(s.started).toLocaleString());
        opt.textContent = bits.length ? `${bits.join(' · ')}  (${s.id.slice(0, 8)})` : s.id;
        sel.appendChild(opt);
      }
      sel.value = _selectedSessionId || '';   // '' = the placeholder (newest)
    }

    _sessionLogEvents = data.events || [];      // assign BEFORE reading the count

    const meta = document.getElementById('session-log-meta');
    if (meta) {
      const shown = _sessionLogEvents.length;
      const which = data.session ? ` · ${data.session.slice(0, 8)}` : '';
      meta.textContent = data.count != null
        ? `${data.count} event(s)${data.truncated ? ` — showing latest ${shown}` : ''}${which}`
        : '';
    }

    renderSessionLog();
  } catch { /* ignore — fail-soft, like the other tabs */ }
}

function onSessionLogChange() {
  const sel = document.getElementById('session-log-select');
  _selectedSessionId = sel ? sel.value : '';
  pollSessionLog();
}

// Flatten one event into a single raw console line of reasoning/action text.
function _slFlat(ev) {
  const p = ev.payload || {};
  switch (ev.event_type) {
    case 'note':
      return p.message || '';
    case 'decision':
      return [p.goal, p.hypothesis && `hyp: ${p.hypothesis}`, p.technique,
              p.chosen_tool && `tool: ${p.chosen_tool}`, p.explanation && `why: ${p.explanation}`]
              .filter(Boolean).join('  ·  ');
    case 'action': {
      const loc = p.params ? (p.params.url || p.params.target || '') : '';
      const m   = p.params ? (p.params.method || '') : '';
      return [`${p.tool || ''} ${p.operation || ''}`.trim(), `${m} ${loc}`.trim()]
              .filter(Boolean).join('  ');
    }
    case 'result': {
      const o = p.observed || {};
      const st = (o.execution_status || o.result_class) ? `[${o.execution_status || '?'}/${o.result_class || '?'}]` : '';
      return [p.summary || '', st].filter(Boolean).join('  ');
    }
    case 'finding':
      return `[${(p.severity || '').toUpperCase()}] ${p.title || ''}${p.target ? ' @ ' + p.target : ''}`;
    case 'coverage_transition':
      return `${p.cell_id || ''} → ${p.status || ''}${p.finding_id ? ' (' + p.finding_id + ')' : ''}`;
    default:
      return JSON.stringify(p);
  }
}

function renderSessionLog() {
  const out = document.getElementById('session-log-output');
  if (!out) return;
  const q = (document.getElementById('session-log-filter')?.value || '').toLowerCase();

  let events = _sessionLogEvents;
  if (q) events = events.filter(ev => (ev.event_type + ' ' + _slFlat(ev)).toLowerCase().includes(q));
  if (!events.length) {
    out.innerHTML = '<div class="empty-placeholder">No reasoning events for this session.</div>';
    return;
  }

  // One raw line per event: "HH:MM:SS  NNN  TYPE      <flattened reasoning/action text>"
  out.innerHTML = events.map(ev => {
    const t   = _SL_TYPE[ev.event_type] || { label: (ev.event_type || '').toUpperCase(), color: '#94a3b8' };
    const ts  = ev.occurred_at ? new Date(ev.occurred_at).toLocaleTimeString('en-GB') : '--:--:--';
    const seq = ev.sequence != null ? String(ev.sequence).padStart(3, '0') : '···';
    const tag = t.label.padEnd(9);
    const cls = 'sl-' + (ev.event_type || 'unknown').replace(/_/g, '-');
    return `<div class="sl-line ${cls}">` +
             `<span class="sl-gutter">${esc(ts)}  ${esc(seq)}  </span>` +
             `<span class="sl-tag" style="color:${t.color}">${esc(tag)}</span>` +
             `<span class="sl-text">${esc(_slFlat(ev))}</span>` +
           `</div>`;
  }).join('');
}

window.pollSessionLog   = pollSessionLog;
window.onSessionLogChange = onSessionLogChange;
window.renderSessionLog = renderSessionLog;
