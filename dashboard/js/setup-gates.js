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

  async function pollSetupGates() {
    try {
      const r = await fetch(`/api/session?_=${Date.now()}`);
      if (!r.ok) return;
      const sess = await r.json();
      renderSetupGates(sess.setup_gates || []);
    } catch { /* ignore */ }
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
