  async function pollSkills() {
    if (scanDone) return;
    try {
      const r = await fetch(`/api/session?_=${Date.now()}`);
      if (!r.ok) return;
      _skillsSession = await r.json();
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

        let meta = '';
        if (inv) {
          const ts = inv.timestamp ? new Date(inv.timestamp).toLocaleTimeString() : '';
          const chainedFrom = inv.chained_from ? `<div class="skill-chained">chained from /${esc(inv.chained_from)}</div>` : '';
          const reason = inv.reason && inv.reason !== 'session start'
            ? `<div class="skill-reason">${esc(inv.reason)}</div>`
            : '';
          meta = `<div class="skill-invoked-at">Invoked${ts ? ' at ' + ts : ''}</div>${reason}${chainedFrom}`;
        } else if (req) {
          meta = `<div><span class="skill-required-badge">GATE REQUIRED</span></div>
                  <div class="skill-gate-reason">${esc(req.trigger)}</div>`;
        }

        html += `<div class="${cardClass}">
          ${statusIcon}
          <div class="skill-body">
            <div class="${nameClass}">/${esc(sk.name)}${activeDot}</div>
            <div class="skill-desc">${esc(sk.desc)}</div>
            ${meta}
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
    if (e.type === 'TOOL')     return `<span class="ql-type TOOL">${esc(e.name)}</span>${e.target ? ' → ' + esc(e.target) : ''}${e.duration_s != null ? ' (' + e.duration_s + 's)' : ''}`;
    if (e.type === 'SPIDER')   return `<span class="ql-type SPIDER">SPIDER</span> ${e.endpoints_found ?? '?'} endpoints found${e.target ? ' — ' + esc(e.target) : ''}`;
    if (e.type === 'FINDING')  return `<span class="ql-type FINDING">${esc(e.severity?.toUpperCase() || 'FINDING')}</span> ${esc(e.title || '')}`;
    if (e.type === 'COVERAGE') return `<span class="ql-type COVERAGE">COVERAGE</span> ${e.registered ?? '?'} endpoints · ${e.tested ?? 0} tested · ${e.pending ?? 0} pending`;
    if (e.type === 'QA_REPLY') {
      const msg = (e.message || '').slice(0, 180);
      return `<span class="ql-type COVERAGE">QA_REPLY</span> ${esc(msg)}${(e.message || '').length > 180 ? '…' : ''}`;
    }
    return esc(JSON.stringify(e));
  }
