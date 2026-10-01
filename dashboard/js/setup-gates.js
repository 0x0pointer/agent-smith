  // ── Manual Setup Gates tab ─────────────────────────────────────────────────
  // Renders capabilities.yaml prerequisites from session.json's `setup_gates`.
  // Three-state election (now/defer/skip) + ordered runbook with per-step copy
  // buttons + a "Verify setup" recheck that runs the readiness probe server-side.

  function _sgEsc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  const _SG_STATUS = {
    pending_election: ['needs election', '#f59e0b'],
    deferred:         ['deferred',       '#38bdf8'],
    elected_now:      ['elected — verify', '#22d3ee'],
    satisfied:        ['satisfied',      '#4ade80'],
    failed:           ['probe failed',   '#f87171'],
    skipped:          ['skipped',        '#9b98b8'],
  };
  const _SG_CAT_COLOR = {
    device: '#a78bfa', hardware: '#f472b6', network: '#38bdf8', other: '#9b98b8',
  };

  async function _sgCopy(text, btn) {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = document.createElement('textarea');
      ta.value = text; document.body.appendChild(ta); ta.select();
      try { document.execCommand('copy'); } catch { /* ignore */ }
      document.body.removeChild(ta);
    }
    if (btn) { const o = btn.textContent; btn.textContent = 'copied'; setTimeout(() => { btn.textContent = o; }, 1200); }
  }

  function _buildSetupGateCard(g) {
    const cat = g.category || 'other';
    const catColor = _SG_CAT_COLOR[cat] || '#9b98b8';
    const [statusLabel, statusColor] = _SG_STATUS[g.status] || [g.status, '#9b98b8'];
    const el = document.createElement('div');
    el.style.cssText = `background:var(--bg-card);border:1px solid var(--border);border-left:3px solid ${catColor};border-radius:6px;padding:0.7rem 0.9rem;margin-bottom:0.6rem;font-size:0.82rem;`;

    let html = `
      <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:0.3rem;">
        <span style="color:${catColor};font-weight:600;font-family:'IBM Plex Mono',monospace;font-size:0.8rem;">${_sgEsc(g.id)}</span>
        <span style="color:${statusColor};font-size:0.74rem;font-weight:600;">${_sgEsc(statusLabel)}</span>
      </div>
      <div style="color:var(--text-dim);font-size:0.72rem;font-family:'IBM Plex Mono',monospace;margin-bottom:0.3rem;">
        ${_sgEsc(cat)}${g.requires_host ? ' · requires host (explicit opt-in)' : ''}${g.skill ? ' · ' + _sgEsc(g.skill) : ''}
      </div>`;
    if (g.description) html += `<div style="color:var(--text);line-height:1.5;margin-bottom:0.4rem;">${_sgEsc(g.description)}</div>`;

    const steps = g.runbook || [];
    if (steps.length) {
      html += `<div style="color:var(--text-dim);font-size:0.74rem;margin:0.2rem 0;">Runbook:</div><ol style="margin:0 0 0.4rem;padding-left:1.2rem;color:var(--text);font-size:0.8rem;line-height:1.6;">`;
      steps.forEach((s, i) => {
        html += `<li>${_sgEsc(s.step || '')}`;
        if (s.command) {
          html += `<div style="display:flex;gap:0.4rem;align-items:center;margin:0.2rem 0;">
            <code data-sg-cmd="${i}" style="flex:1;background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:0.2rem 0.4rem;font-size:0.72rem;overflow-wrap:anywhere;">${_sgEsc(s.command)}</code>
            <button data-sg-copy="${i}" style="padding:0.2rem 0.5rem;border:1px solid var(--border);border-radius:4px;background:transparent;color:var(--text-dim);font-size:0.7rem;cursor:pointer;white-space:nowrap;">copy</button>
          </div>`;
        }
        if (s.expected) html += `<div style="color:var(--text-dim);font-size:0.72rem;">expect: ${_sgEsc(s.expected)}</div>`;
        html += `</li>`;
      });
      html += `</ol>`;
    }

    const probe = g.readiness_probe || {};
    if (probe.verb) {
      html += `<div style="color:var(--text-dim);font-size:0.72rem;font-family:'IBM Plex Mono',monospace;margin-bottom:0.3rem;">probe: ${_sgEsc(probe.run_on || 'host')} · ${_sgEsc(probe.verb)} ${_sgEsc((probe.args || []).join(' '))}</div>`;
    }
    const pr = g.probe_result;
    if (pr) {
      const ok = pr.ok;
      html += `<div style="margin:0.3rem 0;padding:0.3rem 0.5rem;border-radius:4px;font-size:0.74rem;background:${ok ? 'rgba(74,222,128,0.08)' : 'rgba(248,113,113,0.08)'};color:${ok ? '#86efac' : '#fca5a5'};">
        last probe: ${ok ? 'PASS' : 'FAIL'}${pr.at ? ' · ' + _sgEsc(new Date(pr.at).toLocaleTimeString()) : ''}${pr.stdout_excerpt ? '<br><span style="color:var(--text-dim);">' + _sgEsc(pr.stdout_excerpt.slice(0, 160)) + '</span>' : ''}
      </div>`;
    }
    el.innerHTML = html;

    // wire copy buttons
    el.querySelectorAll('[data-sg-copy]').forEach(btn => {
      const idx = btn.getAttribute('data-sg-copy');
      const code = el.querySelector(`[data-sg-cmd="${idx}"]`);
      btn.addEventListener('click', () => _sgCopy(code ? code.textContent : '', btn));
    });

    // action bar: election + recheck
    const bar = document.createElement('div');
    bar.style.cssText = 'display:flex;gap:0.4rem;margin-top:0.5rem;flex-wrap:wrap;';
    const mk = (label, bg, fn) => {
      const b = document.createElement('button');
      b.textContent = label;
      b.style.cssText = `padding:0.3rem 0.7rem;border:none;border-radius:4px;background:${bg};color:#fff;font-size:0.74rem;cursor:pointer;`;
      b.addEventListener('click', () => fn(b));
      return b;
    };
    bar.appendChild(mk('Set up now', '#7c3aed', b => _electSetupGate(g.id, 'now', b)));
    bar.appendChild(mk('Defer',      '#0369a1', b => _electSetupGate(g.id, 'defer', b)));
    bar.appendChild(mk('Skip',       '#6b7280', b => _electSetupGate(g.id, 'skip', b)));
    if (probe.verb) bar.appendChild(mk('Verify setup', '#16a34a', b => _recheckSetupGate(g.id, b)));
    el.appendChild(bar);
    return el;
  }

  function renderSetupGates(gates) {
    const wrap = document.getElementById('setup-gates-wrap');
    if (!wrap) return;
    if (!gates || !gates.length) {
      wrap.innerHTML = '<div class="empty-placeholder">No manual-setup gates. Skills that ship a <code>capabilities.yaml</code> open them here when invoked.</div>';
      return;
    }
    wrap.innerHTML = '';
    gates.forEach(g => wrap.appendChild(_buildSetupGateCard(g)));
  }

  // ── Resource requests (agent→operator wishlist) ────────────────────────────
  // Moved here from the Activity feed (issue #181): the wishlist is the other
  // "Smith needs something from you" signal, so it belongs next to the setup
  // gates under Operator Actions, with a shared unread badge (see _oaUpdateBadge).

  const _WISH_CAT_COLOR = {
    credentials: '#f87171', scope: '#fbbf24', rate_limit: '#a78bfa',
    tooling: '#38bdf8', access: '#f472b6', environment: '#34d399', other: '#9b98b8',
  };
  const _WISH_STATUS = {
    open: ['OPEN', '#38bdf8'], fulfilled: ['FULFILLED', '#4ade80'], dismissed: ['DISMISSED', '#9b98b8'],
  };

  function _buildWishlistCard(it, withActions) {
    const color = _WISH_CAT_COLOR[it.category] || '#38bdf8';
    const [statusLabel, statusColor] = _WISH_STATUS[it.status] || [it.status, '#9b98b8'];
    const ts = it.ts ? new Date(it.ts).toLocaleTimeString() : '';
    const cells = it.blocking_cell_ids || [];
    const el = document.createElement('div');
    el.style.cssText = `background:var(--bg-card);border:1px solid var(--border);border-left:3px solid ${color};border-radius:6px;padding:0.6rem 0.85rem;margin-bottom:0.5rem;font-size:0.82rem;`;
    let html = `
      <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:0.25rem;">
        <span style="color:${color};font-weight:600;font-family:'IBM Plex Mono',monospace;font-size:0.74rem;">${_sgEsc(it.category || 'other')}</span>
        <span style="color:${statusColor};font-size:0.72rem;">${_sgEsc(statusLabel)} &nbsp; ${_sgEsc(ts)}</span>
      </div>
      <div style="color:var(--text);font-size:0.82rem;line-height:1.5;margin-bottom:0.2rem;overflow-wrap:anywhere;">${_sgEsc(it.need || '')}</div>`;
    if (it.rationale) html += `<div style="color:var(--text-dim);font-size:0.74rem;margin-bottom:0.2rem;">${_sgEsc(it.rationale)}</div>`;
    if (cells.length) html += `<div style="color:var(--text-dim);font-size:0.72rem;font-family:'IBM Plex Mono',monospace;">blocks ${cells.length} cell(s): ${_sgEsc(cells.slice(0, 6).join(', '))}${cells.length > 6 ? '…' : ''}</div>`;
    if (it.resolution_note) html += `<div style="margin-top:0.3rem;padding:0.3rem 0.5rem;background:rgba(74,222,128,0.08);border-radius:4px;color:#86efac;font-size:0.75rem;">Operator: ${_sgEsc(it.resolution_note)}</div>`;
    el.innerHTML = html;
    if (withActions) {
      const bar = document.createElement('div');
      bar.style.cssText = 'display:flex;gap:0.4rem;margin-top:0.5rem;';
      const mk = (label, bg, action) => {
        const b = document.createElement('button');
        b.textContent = label;
        b.style.cssText = `padding:0.3rem 0.7rem;border:none;border-radius:4px;background:${bg};color:#fff;font-size:0.74rem;cursor:pointer;`;
        b.addEventListener('click', () => _resolveWishlist(it.id, action, b));
        return b;
      };
      bar.appendChild(mk('Fulfil', '#16a34a', 'fulfill'));
      bar.appendChild(mk('Dismiss', '#6b7280', 'dismiss'));
      el.appendChild(bar);
    }
    return el;
  }

  function _renderWishlist(items) {
    const openWrap = document.getElementById('wishlist-open-wrap');
    const histWrap = document.getElementById('wishlist-history-wrap');
    if (!openWrap || !histWrap) return;
    const open = items.filter(i => i.status === 'open');
    const resolved = items.filter(i => i.status !== 'open');
    if (!open.length) {
      openWrap.innerHTML = '<div class="empty-placeholder">No open requests — Smith has everything it asked for.</div>';
    } else {
      openWrap.innerHTML = '';
      open.forEach(it => openWrap.appendChild(_buildWishlistCard(it, true)));
    }
    if (!resolved.length) {
      histWrap.innerHTML = '<div class="empty-placeholder">No resolved wishlist items yet.</div>';
    } else {
      histWrap.innerHTML = '';
      resolved.forEach(it => histWrap.appendChild(_buildWishlistCard(it, false)));
    }
  }

  async function _resolveWishlist(id, action, btn) {
    const msg = action === 'fulfill'
      ? 'What are you giving Smith? (e.g. "creds analyst/Pw123", "scope now includes staging.api") — sent to Smith as a steering directive:'
      : 'Reason for dismissing (optional — leave blank and press OK, or Cancel to abort):';
    const note = window.prompt(msg);
    if (note === null) return;   // Cancel/Escape aborts either action (symmetric)
    if (btn) { btn.disabled = true; btn.textContent = '…'; }
    try {
      const r = await fetch(`/api/wishlist/${encodeURIComponent(id)}/${action}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note: note || '' }),
      });
      if (!r.ok) throw new Error('Failed: ' + r.status);
      pollSetupGates();
    } catch (e) {
      alert(e && e.message ? e.message : 'Request failed');
      if (btn) {
        btn.disabled = false;
        btn.textContent = action === 'fulfill' ? 'Fulfil' : 'Dismiss';
      }
    }
  }

  // ── Unread badge + notifications (issue #181) ───────────────────────────────
  // One count on the "Operator Actions" tab for everything awaiting the operator:
  // open resource requests + gates still needing an election. Two independent
  // bits of state, deliberately NOT merged:
  //   _oaSeen    — localStorage, drives the "new since you last looked" pulse;
  //                cleared when the operator opens the tab.
  //   _oaToasted — in-memory, dedupes the OS/title toast so each new request
  //                notifies exactly once (NOT every poll). Keeping it separate
  //                from _oaSeen is what lets the toast fire while the pulse also
  //                stays lit until the tab is actually viewed.

  let _oaGates    = [];        // last good setup gates (kept across a failed poll)
  let _oaWishAll  = [];        // last good full wishlist (kept across a failed poll)
  let _oaWishOpen = [];        // derived: open items only
  let _oaSeen     = null;      // Set<"w:<id>"/"g:<id>"> the operator has viewed
  let _oaToasted  = new Set(); // Set<"w:<id>"> already notified this page-load
  let _oaInit     = false;     // first poll done — seeds _oaToasted so the backlog is silent
  let _oaBusy     = false;     // reentrancy guard — one poll in flight at a time
  let _oaRenderSig = null;     // signature of the last-rendered data (skip no-op re-renders)

  function _oaLoadSeen() {
    if (_oaSeen) return _oaSeen;
    try { _oaSeen = new Set(JSON.parse(localStorage.getItem('smith_operator_actions_seen') || '[]')); }
    catch (e) { _oaSeen = new Set(); }
    return _oaSeen;
  }
  function _oaSaveSeen(seen) {
    try { localStorage.setItem('smith_operator_actions_seen', JSON.stringify(Array.from(seen).slice(-300))); }
    catch (e) { /* private mode / blocked storage — highlight just won't persist */ }
  }

  // Actionable keys: open requests (with an id) + gates awaiting election.
  function _oaKeys() {
    return [
      ..._oaWishOpen.filter(i => i && i.id).map(i => 'w:' + i.id),
      ..._oaGates.filter(g => g && g.id && g.status === 'pending_election').map(g => 'g:' + g.id),
    ];
  }

  function _oaUpdateBadge() {
    const btn = document.getElementById('tab-btn-setup-gates');
    if (!btn) return;
    const keys = _oaKeys();
    const active = (typeof _activeTab !== 'undefined' && _activeTab === 'setup-gates');
    const seen = _oaLoadSeen();
    if (active) {                 // operator is looking → everything here is now seen
      let changed = false;
      keys.forEach(k => { if (!seen.has(k)) { seen.add(k); changed = true; } });
      if (changed) _oaSaveSeen(seen);
    }
    const unseen = keys.filter(k => !seen.has(k)).length;
    btn.textContent = keys.length ? `Operator Actions (${keys.length})` : 'Operator Actions';
    btn.classList.toggle('oa-unseen', unseen > 0 && !active);
  }

  // Fire a one-shot toast for each OPEN request not yet notified this page-load.
  // Independent of _oaSeen so the toast and the pulse don't cancel each other.
  function _oaToastNew(active) {
    for (const it of _oaWishOpen) {
      if (!it || !it.id) continue;
      const k = 'w:' + it.id;
      if (_oaToasted.has(k)) continue;
      _oaToasted.add(k);                      // mark first, so a failed/again poll can't re-fire
      if (!active && typeof _notify === 'function') {
        _notify('Smith needs a resource', (it.need || '').slice(0, 120), 'normal');
      }
    }
  }

  // Cheap structural signature — only the fields the cards render — so the
  // background poll re-renders ONLY when something actually changed (no 5s
  // flicker, and no wiping an in-flight "probing…" / disabled button).
  function _oaSig() {
    return JSON.stringify([
      _oaGates.map(g => [g && g.id, g && g.status, g && g.probe_result && g.probe_result.ok]),
      _oaWishAll.map(i => [i && i.id, i && i.status, (i && i.resolution_note) || '']),
    ]);
  }

  async function pollSetupGates() {
    if (_oaBusy) return;          // don't let a slow poll overlap itself (toast/render amplification)
    _oaBusy = true;
    try {
      // Gates ride along on the session blob pollSession() already fetches and
      // caches — no second /api/session request just for setup_gates.
      const cachedGates = (typeof _sessionData !== 'undefined' && _sessionData && _sessionData.setup_gates) || null;
      if (cachedGates) _oaGates = cachedGates;

      // The wishlist is this feature's only genuinely-new fetch. On any failure
      // (non-200, or a half-written session.json racing a JSON parse) keep the
      // last good data rather than blanking the tab and the badge.
      let fetchOk = false;
      try {
        const r = await fetch(`/api/wishlist?_=${Date.now()}`);
        if (r.ok) { _oaWishAll = (await r.json()).items || []; fetchOk = true; }
      } catch { /* keep last good _oaWishAll */ }
      _oaWishOpen = _oaWishAll.filter(i => i && i.status === 'open');

      const active = (typeof _activeTab !== 'undefined' && _activeTab === 'setup-gates');

      // Arm the toaster only after a SUCCESSFUL first fetch, seeding it with the
      // current backlog so a reload is silent; thereafter each new request toasts
      // exactly once. A failed first fetch leaves it disarmed (no backlog storm).
      if (!_oaInit) {
        if (fetchOk) {
          for (const it of _oaWishOpen) { if (it && it.id) _oaToasted.add('w:' + it.id); }
          _oaInit = true;
        }
      } else {
        _oaToastNew(active);
      }

      // Render the cards only while the operator is on the tab, and only when the
      // data actually changed — the background cadence just keeps the badge live.
      if (active) {
        const sig = _oaSig();
        if (sig !== _oaRenderSig) {
          renderSetupGates(_oaGates);
          _renderWishlist(_oaWishAll);
          _oaRenderSig = sig;
        }
      }

      _oaUpdateBadge();
    } finally {
      _oaBusy = false;
    }
  }

  async function _electSetupGate(id, choice, btn) {
    if (btn) { btn.disabled = true; }
    try {
      const r = await fetch(`/api/setup-gates/${encodeURIComponent(id)}/elect`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ choice }),
      });
      if (!r.ok) alert('Election failed: ' + r.status);
    } catch { alert('Request failed'); }
    pollSetupGates();
  }

  async function _recheckSetupGate(id, btn) {
    const orig = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = 'probing…'; }
    try {
      const r = await fetch(`/api/setup-gates/${encodeURIComponent(id)}/recheck`, { method: 'POST' });
      const data = await r.json().catch(() => ({}));
      if (!r.ok || !data.ok) {
        alert('Recheck failed: ' + (data.error || r.status));
      } else if (data.status === 'ok') {
        alert('Setup verified — readiness probe passed.' + (data.smith_woken ? ' Smith resumed.' : ''));
      } else {
        const reason = (data.probe && data.probe.error) || 'success criterion not met';
        alert('Not ready yet: ' + reason);
      }
    } catch { alert('Request failed'); }
    if (btn) { btn.disabled = false; btn.textContent = orig; }
    pollSetupGates();
  }

  // Expose globals referenced by common.js switchTab + inline handlers.
  window.pollSetupGates = pollSetupGates;
  window.renderSetupGates = renderSetupGates;
