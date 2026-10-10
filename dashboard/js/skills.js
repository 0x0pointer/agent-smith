  async function pollSkills() {
    if (scanDone) return;
    try {
      const r = await fetch(`/api/session?_=${Date.now()}`);
      if (!r.ok) return;
      _skillsSession = await r.json();
      // PR-E: per-skill USAGE metric (invocation count + per-instance covered/discovered/
      // pending) from the Surface-Coverage Ledger. Best-effort — the /api/skill-usage route
      // exists only once the ledger backend is present; if absent the card still shows the
      // invocation count derived from skill_history.
      try {
        const ru = await fetch(`/api/skill-usage?_=${Date.now()}`);
        _skillsSession._skillUsage = ru.ok ? await ru.json() : null;
      } catch { _skillsSession._skillUsage = null; }
      renderSkills();
      // Update tab badge
      const history = _skillsSession.skill_history || [];
      const invokedNames = new Set(history.map(h => h.skill).filter(Boolean));
      const btn = document.getElementById('tab-btn-skills');
      if (btn) btn.textContent = `Skills (${invokedNames.size}/${SKILLS_CATALOG.length})`;
    } catch { /* ignore */ }
  }

  function renderSkills() {
    const wrap   = document.getElementById('skills-wrap');
    const sumWrap = document.getElementById('skills-summary');
    const s = _skillsSession;

    if (!s || !s.target) {
      wrap.innerHTML = '<div class="empty-placeholder">No active scan session — start a scan to track skill usage.</div>';
      sumWrap.innerHTML = '';
      return;
    }

    // Build invoked-skills map: name → first history entry
    // pentester is always shown as invoked since all scans flow through it
    const history = s.skill_history || [];
    const invokedMap = { pentester: { skill: 'pentester', reason: 'default orchestrator' } };
    for (const h of history) {
      if (h.skill && !invokedMap[h.skill]) invokedMap[h.skill] = h;
    }

    // Build required-skills map: name → gate info
    const requiredMap = {};
    for (const gate of (s.gates || [])) {
      if (gate.status === 'pending') {
        for (const skill of (gate.required_skills || [])) {
          if (!requiredMap[skill]) requiredMap[skill] = gate;
        }
      }
    }

    const invokedCount  = Object.keys(invokedMap).length;
    const requiredCount = Object.keys(requiredMap).length;

    sumWrap.innerHTML = [
      `<span class="cov-stat cov-tested">${invokedCount} / ${SKILLS_CATALOG.length} invoked</span>`,
      requiredCount
        ? `<span class="cov-stat cov-vulnerable">${requiredCount} gate-required</span>`
        : '',
      `<span style="font-size:.8rem;color:#6e7681;align-self:center">active skill: <strong style="color:#f0f6fc">${s.skill ? '/'+s.skill : '—'}</strong></span>`,
    ].join('');

    // Group skills
    const groups = {};
    for (const sk of SKILLS_CATALOG) {
      if (!groups[sk.group]) groups[sk.group] = [];
      groups[sk.group].push(sk);
    }

    let html = '<div class="skills-grid">';
    for (const [groupName, skills] of Object.entries(groups)) {
      html += `<div class="skills-group-header">${esc(groupName)}</div>`;
      for (const sk of skills) {
        const inv  = invokedMap[sk.name];
        const req  = requiredMap[sk.name];
        const isActive = s.skill === sk.name;
        let cardClass = 'skill-card';
        if (inv)  cardClass += ' invoked';
        if (req && !inv) cardClass += ' required';

        const statusIcon = inv
          ? '<span class="skill-status" style="color:#3fb950">&#10003;</span>'
          : req
            ? '<span class="skill-status" style="color:#d29922">&#9888;</span>'
            : '<span class="skill-status" style="color:#30363d">&#9711;</span>';

        const nameClass = inv ? 'skill-name invoked-name' : 'skill-name';
        const activeDot = isActive ? ' <span style="font-size:.65rem;color:#58a6ff;background:rgba(88,166,255,.15);padding:.1rem .3rem;border-radius:3px;font-style:normal">ACTIVE</span>' : '';

        // PR-E: how many times this skill ran (count all skill_history entries, not just the first)
        const runs = history.filter(h => h.skill === sk.name).length + (sk.name === 'pentester' ? 1 : 0);

        let meta = '';
        if (inv) {
          const ts = inv.timestamp ? new Date(inv.timestamp).toLocaleTimeString() : '';
          const chainedFrom = inv.chained_from ? `<div class="skill-chained">chained from /${esc(inv.chained_from)}</div>` : '';
          const reason = inv.reason && inv.reason !== 'session start'
            ? `<div class="skill-reason">${esc(inv.reason)}</div>`
            : '';
          const ranLabel = runs > 1 ? ` · ran ${runs}×` : '';
          meta = `<div class="skill-invoked-at">Invoked${ts ? ' at ' + ts : ''}${ranLabel}</div>${reason}${chainedFrom}`;
        } else if (req) {
          meta = `<div><span class="skill-required-badge">GATE REQUIRED</span></div>
                  <div class="skill-gate-reason">${esc(req.trigger)}</div>`;
        }

        // PR-E: WHERE the skill was used — per-instance coverage from the ledger. Each
        // discovered surface instance is a chip: ✓ covered (green) / ✗ uncovered (amber).
        // Surfaces the re-invocation gap visually (e.g. ai-redteam covered 1/2 AI endpoints).
        let usageHtml = '';
        const u = s._skillUsage && s._skillUsage[sk.name];
        if (u && ((u.discovered || []).length || (u.covered || []).length)) {
          const covered = new Set(u.covered || []);
          const discovered = u.discovered || [];
          const unit = esc(u.unit || 'instance');
          const nCov = covered.size, nDisc = discovered.length;
          const nPend = (u.pending || []).length;
          const chips = discovered.map(k => {
            const done = covered.has(k);
            const short = k.length > 30 ? k.slice(0, 29) + '…' : k;
            return `<span title="${esc(k)}" style="font-size:.62rem;padding:.08rem .3rem;border-radius:3px;`
              + `background:${done ? 'rgba(63,185,80,.14)' : 'rgba(210,153,34,.14)'};`
              + `color:${done ? '#3fb950' : '#d29922'}">${done ? '✓' : '✗'} ${esc(short)}</span>`;
          }).join('');
          usageHtml = `<div style="margin-top:.4rem">`
            + `<span style="font-size:.7rem;color:#3fb950">${nCov}/${nDisc} ${unit} covered</span>`
            + (nPend ? `<span style="font-size:.7rem;color:#d29922;margin-left:.45rem">${nPend} uncovered</span>` : '')
            + `<div style="margin-top:.25rem;display:flex;flex-wrap:wrap;gap:.25rem">${chips}</div></div>`;
        }

        html += `<div class="${cardClass}">
          ${statusIcon}
          <div class="skill-body">
            <div class="${nameClass}">/${esc(sk.name)}${activeDot}</div>
            <div class="skill-desc">${esc(sk.desc)}</div>
            ${meta}
            ${usageHtml}
          </div>
        </div>`;
      }
    }
    html += '</div>';
    wrap.innerHTML = html;
  }

  // ── QA Agent tab ──────────────────────────────────────────────────────────
  let _qaData = null;

  const QL_ICONS = { SKILL: '🎯', TOOL: '🔧', SPIDER: '🕷', FINDING: '🔍', COVERAGE: '📋', QA_REPLY: '💬' };
  const QL_LABELS = { SKILL: 'SKILL', TOOL: 'TOOL', SPIDER: 'SPIDER', FINDING: 'FINDING', COVERAGE: 'COVERAGE', QA_REPLY: 'QA_REPLY' };

  function _qlTime(ts) {
    try { return new Date(ts).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'}); }
    catch { return ''; }
  }

  function _qlDesc(e) {
    if (e.type === 'SKILL')    return `<span class="ql-type SKILL">${esc(e.name)}</span>${e.reason ? ' — ' + esc(e.reason) : ''}`;
    if (e.type === 'TOOL') {
      // kali entries now carry the actual command + outcome; others keep the target.
      const detail = e.command
        ? ` <code class="ql-cmd" title="${esc(e.command)}">${esc(e.command)}</code>`
        : (e.target ? ' → ' + esc(e.target) : '');
      const to  = e.timed_out ? ' <span class="ql-timeout" title="a request hit its time bound — possible time-based-blind / SSRF / slow endpoint">⏱ timed out</span>' : '';
      const dur = e.duration_s != null ? ' (' + e.duration_s + 's)' : '';
      return `<span class="ql-type TOOL">${esc(e.name)}</span>${detail}${to}${dur}`;
    }
    if (e.type === 'SPIDER')   return `<span class="ql-type SPIDER">SPIDER</span> ${e.endpoints_found ?? '?'} endpoints found${e.target ? ' — ' + esc(e.target) : ''}`;
    if (e.type === 'FINDING')  return `<span class="ql-type FINDING">${esc(e.severity?.toUpperCase() || 'FINDING')}</span> ${esc(e.title || '')}`;
    if (e.type === 'COVERAGE') return `<span class="ql-type COVERAGE">COVERAGE</span> ${e.registered ?? '?'} endpoints · ${e.tested ?? 0} tested · ${e.pending ?? 0} pending`;
    if (e.type === 'QA_REPLY') {
      const msg = (e.message || '').slice(0, 180);
      return `<span class="ql-type COVERAGE">QA_REPLY</span> ${esc(msg)}${(e.message || '').length > 180 ? '…' : ''}`;
    }
    return esc(JSON.stringify(e));
  }
