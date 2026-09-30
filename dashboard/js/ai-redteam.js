  // ============================================================================
  //  ai-redteam.js — the AI Red Team tab.
  //  Layout: KPI tiles (at-a-glance) + sub-tabs (Overview / Attacks / garak /
  //  Defenses). Reads /api/ai-redteam (garak rates, filter map, calibration,
  //  attacks) + /api/coverage (OWASP grid) + /api/findings (counts). All
  //  scan-derived strings pass through esc() before innerHTML.
  // ============================================================================
  let _aiData = null;
  let _aiSub = 'overview';
  // Which transcripts the user has expanded — persisted across the 5s re-render
  // so an open <details> doesn't snap shut on the next poll (keyed by attack ts).
  const _airOpenTx = new Set();
  // Which OWASP ledger rows the user has expanded to see linked findings.
  const _airOpenCat = new Set();

  const _AI_LLM_LABELS = {
    prompt_injection: ['LLM01', 'Prompt Injection'], jailbreak: ['LLM01', 'Jailbreak'],
    sensitive_info_disclosure: ['LLM02', 'Sensitive Info'], improper_output_handling: ['LLM05', 'Output Handling'],
    excessive_agency: ['LLM06', 'Excessive Agency'], system_prompt_leak: ['LLM07', 'System-Prompt Leak'],
    rag_poisoning: ['LLM08', 'RAG Poisoning'], embedding_manipulation: ['LLM08', 'Embedding'],
    misinformation: ['LLM09', 'Misinformation'], unbounded_consumption: ['LLM10', 'Unbounded Consumption'],
    model_extraction: ['AITG', 'Model Extraction'], content_bias: ['AITG', 'Content Bias'],
    membership_inference: ['AITG', 'Membership Inf.'], cot_forgery: ['—', 'CoT Forgery'],
    role_prefix_spoofing: ['—', 'Role-Prefix Spoof'],
  };
  const _MCP_LABELS = {
    mcp_command_injection: ['MCP05', 'Command Injection'], mcp_token_exposure: ['MCP01', 'Token Exposure'],
    mcp_scope_creep: ['MCP02', 'Scope Creep'], mcp_tool_poisoning: ['MCP03', 'Tool Poisoning'],
    mcp_intent_subversion: ['MCP06', 'Intent Subversion'], mcp_auth: ['MCP07', 'Auth / AuthZ'],
    mcp_context_oversharing: ['MCP10', 'Context Over-Sharing'],
  };

  // Canonical OWASP checklists — always shown so coverage GAPS are visible, not
  // just whatever cells happened to register. Codes join to the label maps above.
  const _OWASP_LLM = [
    ['LLM01', 'Prompt Injection'], ['LLM02', 'Sensitive Info Disclosure'],
    ['LLM03', 'Supply Chain'], ['LLM04', 'Data & Model Poisoning'],
    ['LLM05', 'Improper Output Handling'], ['LLM06', 'Excessive Agency'],
    ['LLM07', 'System-Prompt Leakage'], ['LLM08', 'Vector & Embedding Weakness'],
    ['LLM09', 'Misinformation'], ['LLM10', 'Unbounded Consumption'],
  ];
  const _OWASP_MCP = [
    ['MCP01', 'Token / Credential Exposure'], ['MCP02', 'Privilege Escalation / Scope Creep'],
    ['MCP03', 'Tool Poisoning'], ['MCP04', 'Supply Chain / Dependency Tampering'],
    ['MCP05', 'Command Injection'], ['MCP06', 'Intent-Flow Subversion'],
    ['MCP07', 'Authentication & AuthZ'], ['MCP08', 'Audit & Telemetry Gap'],
    ['MCP09', 'Shadow / Rogue Servers'], ['MCP10', 'Context Over-Sharing'],
  ];
  const _LLM_CODES = new Set(_OWASP_LLM.map(r => r[0]));
  const _MCP_CODES = new Set(_OWASP_MCP.map(r => r[0]));
  const _AI_STATUS = {
    vulnerable:    { c: '#f85149', t: 'VULNERABLE' },
    in_progress:   { c: '#58a6ff', t: 'IN PROGRESS' },
    tested_clean:  { c: '#3fb950', t: 'CLEAN' },
    pending:       { c: '#6e7681', t: 'PENDING' },
    skipped:       { c: '#d29922', t: 'SKIPPED' },
    not_applicable:{ c: '#8b949e', t: 'N/A' },
  };
  const _AI_RANK = ['vulnerable', 'in_progress', 'pending', 'skipped', 'tested_clean', 'not_applicable'];

  function switchAiSub(name) {
    _aiSub = name;
    document.querySelectorAll('#tab-ai-redteam .air-subbtn').forEach(b =>
      b.classList.toggle('active', b.dataset.sub === name));
    document.querySelectorAll('#tab-ai-redteam .air-sub').forEach(s =>
      s.hidden = (s.id !== 'air-sub-' + name));
  }
  window.switchAiSub = switchAiSub;

  async function pollAiRedteam() {
    try {
      const [ai, cov, fin] = await Promise.all([
        fetch('/api/ai-redteam?_=' + Date.now()).then(r => r.ok ? r.json() : null).catch(() => null),
        fetch('/api/coverage?_=' + Date.now()).then(r => r.ok ? r.json() : null).catch(() => null),
        fetch('/api/findings?_=' + Date.now()).then(r => r.ok ? r.json() : null).catch(() => null),
      ]);
      _aiData = ai || {};
      renderAiRedteam(_aiData, cov || {}, fin || {});
    } catch (_) { /* ignore */ }
  }

  function _aiAgg(statuses) {
    for (const s of _AI_RANK) if (statuses.includes(s)) return s;
    return 'pending';
  }
  function _tile(value, label, color, sub) {
    return `<div class="air-tile"><div class="air-tile-val" style="color:${color}">${value}</div>`
      + `<div class="air-tile-label">${esc(label)}</div>`
      + (sub ? `<div class="air-tile-sub">${esc(sub)}</div>` : '') + `</div>`;
  }

  function _garakBarRow(g) {
    const pct = Math.round((g.attack_success_rate || 0) * 100);
    const col = pct >= 20 ? '#f85149' : pct > 0 ? '#d29922' : '#3fb950';
    return `<div class="air-bar-row"><span class="air-bar-label">${esc(g.probe)}<span class="air-sub-note">/${esc(g.detector)}</span></span>`
      + `<div class="air-meter"><div class="air-meter-fill" style="width:${pct}%;background:${col}"></div></div>`
      + `<span class="air-bar-val" style="color:${col}">${pct}% <span class="air-sub-note">${g.fails}/${g.total}</span></span></div>`;
  }

  function renderAiRedteam(ai, cov, fin) {
    const cells = (cov.matrix || []).filter(c =>
      (c.injection_type in _AI_LLM_LABELS) || (c.injection_type in _MCP_LABELS) || String(c.injection_type).startsWith('mcp_'));
    const findings = (fin.findings || []);
    const garak = ai.garak || [];
    const attacks = ai.attacks || [];
    const rd = ai.readiness;

    // ── KPI tiles ─────────────────────────────────────────────────────────
    const byCat = {};
    cells.forEach(c => (byCat[c.injection_type] = byCat[c.injection_type] || []).push(c.status || 'pending'));
    const cats = Object.keys(byCat);
    const vulnCats = cats.filter(t => _aiAgg(byCat[t]) === 'vulnerable').length;
    const crit = findings.filter(f => (f.severity || '').toLowerCase() === 'critical').length;
    const maxAsr = garak.length ? Math.round(Math.max(...garak.map(g => g.attack_success_rate || 0)) * 100) : null;
    const bypasses = (ai.filter && ai.filter.bypass || []).length;
    const jb = attacks.filter(a => a.jailbroken).length;

    document.getElementById('air-kpis').innerHTML = [
      _tile(`${vulnCats}<span class="air-tile-of">/${cats.length || 0}</span>`, 'OWASP cells vulnerable',
            vulnCats ? '#f85149' : '#3fb950'),
      _tile(findings.length, 'Findings', findings.length ? '#e6edf3' : '#6e7681',
            crit ? `${crit} critical` : ''),
      _tile(jb, 'Jailbroken attacks', jb ? '#f85149' : '#3fb950', `${attacks.length} run`),
      _tile(maxAsr == null ? '—' : maxAsr + '%', 'Max garak success',
            maxAsr == null ? '#6e7681' : (maxAsr >= 20 ? '#f85149' : '#d29922')),
      _tile(rd ? (rd.ready ? '✓' : '✗') : '—', 'Toolchain ready',
            rd ? (rd.ready ? '#3fb950' : '#f85149') : '#6e7681',
            rd ? `${rd.components.filter(c => c.ok).length}/${rd.components.length} components` : ''),
      _tile(bypasses, 'Filter bypasses', bypasses ? '#f85149' : '#3fb950'),
    ].join('');

    // tab badge
    const btn = document.getElementById('tab-btn-ai-redteam');
    if (btn) btn.textContent = vulnCats ? `AI Red Team (${vulnCats})` : 'AI Red Team';

    // ── Overview: calibration + OWASP grid ────────────────────────────────
    const rdWrap = document.getElementById('air-readiness');
    if (rd && rd.components) {
      const c = rd.ready ? '#3fb950' : '#f85149';
      const rows = rd.components.map(comp => {
        const warn = !comp.ok && comp.name === 'garak image';   // garak absence is non-blocking
        const cc = comp.ok ? '#3fb950' : (warn ? '#d29922' : '#f85149');
        const ic = comp.ok ? '✓' : (warn ? '○' : '✗');
        return `<div class="air-ready-row"><span class="air-ready-ic" style="color:${cc}">${ic}</span>`
          + `<span class="air-ready-name">${esc(comp.name)}</span>`
          + `<span class="air-sub-note">${esc(comp.detail)}</span></div>`;
      }).join('');
      rdWrap.innerHTML = `<div class="air-banner" style="border-left-color:${c}">`
        + `<span class="air-cal-dot" style="background:${c}"></span>`
        + `<div style="flex:1;min-width:0"><b style="color:${c}">AI Red Team toolchain ${rd.ready ? 'ready' : 'NOT ready'}</b>`
        + `<span class="air-sub-note"> — engines, garak, and the MCP tools that power the assessment</span>`
        + `<div class="air-ready-list">${rows}</div></div></div>`;
    } else {
      rdWrap.innerHTML = `<div class="air-banner" style="border-left-color:#6e7681">`
        + `<span class="air-cal-dot" style="background:#6e7681"></span>`
        + `<span class="air-sub-note">Toolchain status unavailable.</span></div>`;
    }

    // ── OWASP coverage ledger — canonical categories, each a progress row ───
    const gridWrap = document.getElementById('air-grid');
    // Aggregate cell statuses by OWASP code (several injection types map to one code).
    const byCode = {};
    Object.keys(byCat).forEach(t => {
      const lab = _AI_LLM_LABELS[t] || _MCP_LABELS[t];
      if (lab) (byCode[lab[0]] = byCode[lab[0]] || []).push(...byCat[t]);
    });
    // Findings linked to each OWASP code (via the cell's finding_id) — powers the
    // click-through from a ledger row to the finding dossier.
    const finById = {};
    findings.forEach(f => { finById[f.id] = f; });
    const findByCode = {};
    cells.forEach(c => {
      if (!c.finding_id) return;
      const lab = _AI_LLM_LABELS[c.injection_type] || _MCP_LABELS[c.injection_type];
      const f = lab && finById[c.finding_id];
      if (f) (findByCode[lab[0]] = findByCode[lab[0]] || []).push(f);
    });
    Object.keys(findByCode).forEach(c => {              // dedup by finding id
      const seen = new Set();
      findByCode[c] = findByCode[c].filter(f => !seen.has(f.id) && seen.add(f.id));
    });
    const owaspRow = (code, name, statuses) => {
      const total = statuses.length;
      const closed = statuses.filter(s => s !== 'pending' && s !== 'in_progress').length;
      const vuln = statuses.filter(s => s === 'vulnerable').length;
      const agg = total ? _aiAgg(statuses) : null;
      const st = agg ? (_AI_STATUS[agg] || _AI_STATUS.pending) : { c: '#586069', t: 'NOT STARTED' };
      const pct = total ? Math.round(closed / total * 100) : 0;
      const fnds = findByCode[code] || [];
      const clickable = fnds.length > 0;
      const open = clickable && _airOpenCat.has(code);
      const chev = clickable
        ? `<span class="air-ow-chev"><span class="air-ow-arw">▸</span>${fnds.length}</span>` : '';
      const cls = 'air-ow' + (total ? '' : ' air-ow-idle') + (clickable ? ' air-ow-click' : '') + (open ? ' air-ow-open' : '');
      const tip = clickable ? `click to see ${fnds.length} linked finding(s)`
                            : `${esc(name)} — ${total ? closed + '/' + total + ' cells closed' : 'no cells yet'}`;
      let html = `<div class="${cls}"${clickable ? ` data-code="${esc(code)}"` : ''} title="${tip}">`
        + `<span class="air-ow-code" style="color:${st.c}">${esc(code)}</span>`
        + `<span class="air-ow-name">${esc(name)}</span>`
        + `<div class="air-ow-bar"><div class="air-ow-fill" style="width:${pct}%;background:${st.c}"></div></div>`
        + `<span class="air-ow-frac">${total ? `${closed}/${total}` : '—'}${vuln ? ` <span class="air-ow-vuln">${vuln}⚠</span>` : ''}</span>`
        + `<span class="air-ow-end"><span class="air-pill" style="color:${st.c};border-color:${st.c}">${st.t}</span>${chev}</span>`
        + `</div>`;
      if (clickable) {
        html += `<div class="air-ow-detail" data-detail="${esc(code)}"${open ? '' : ' hidden'}>`
          + fnds.map(f => `<a class="air-ow-find" href="/finding/${encodeURIComponent(f.id)}" title="Open finding ${esc(f.id)}">`
              + `<span class="badge badge-${esc(f.severity)}"><span class="sev-dot"></span>${esc(f.severity)}</span>`
              + `<span class="air-ow-find-title">${esc(f.title)}</span>`
              + (f.tool_used ? `<span class="meta-chip chip-tool">${esc(f.tool_used)}</span>` : '')
              + `<span class="air-ow-find-go">open ›</span></a>`).join('')
          + `</div>`;
      }
      return html;
    };
    const extras = (labels, codeSet) => Object.keys(byCat)
      .filter(t => labels[t] && !codeSet.has(labels[t][0])).sort()
      .map(t => owaspRow(labels[t][0] || '·', labels[t][1], byCat[t])).join('');
    const section = (title, done, of, rows) =>
      `<div class="air-ow-sec"><div class="air-grid-title">${title}`
      + ` <span class="air-sub-note">${done}/${of} exercised · click a red row to see its findings</span></div>${rows}</div>`;
    const llmRows = _OWASP_LLM.map(([c, n]) => owaspRow(c, n, byCode[c] || [])).join('') + extras(_AI_LLM_LABELS, _LLM_CODES);
    const mcpRows = _OWASP_MCP.map(([c, n]) => owaspRow(c, n, byCode[c] || [])).join('') + extras(_MCP_LABELS, _MCP_CODES);
    const llmDone = _OWASP_LLM.filter(([c]) => (byCode[c] || []).length).length;
    const mcpDone = _OWASP_MCP.filter(([c]) => (byCode[c] || []).length).length;
    gridWrap.innerHTML =
      (llmDone + mcpDone === 0 ? '<div class="air-sub-note" style="margin-bottom:12px">No cells tested yet — run /ai-redteam to start closing these.</div>' : '')
      + section('OWASP LLM Top 10 (2025)', llmDone, 10, llmRows)
      + section('OWASP Agentic / MCP Top 10', mcpDone, _OWASP_MCP.length, mcpRows);
    // Row click → toggle the linked-findings drawer (persisted across polls).
    gridWrap.querySelectorAll('.air-ow-click').forEach(el => {
      el.addEventListener('click', () => {
        const code = el.getAttribute('data-code');
        const d = gridWrap.querySelector(`.air-ow-detail[data-detail="${code}"]`);
        if (!d) return;
        if (d.hasAttribute('hidden')) { d.removeAttribute('hidden'); el.classList.add('air-ow-open'); _airOpenCat.add(code); }
        else { d.setAttribute('hidden', ''); el.classList.remove('air-ow-open'); _airOpenCat.delete(code); }
      });
    });


    // ── Attacks: reproducibility + transcripts ────────────────────────────
    const reproWrap = document.getElementById('air-repro');
    const reproAttacks = attacks.filter(a => a.reproducibility);
    reproWrap.innerHTML = reproAttacks.length ? reproAttacks.map(a => {
      const rp = a.reproducibility || {}, rate = typeof rp.rate === 'number' ? rp.rate : 0;
      const pct = Math.round(rate * 100), col = rate >= 0.5 ? '#f85149' : rate > 0 ? '#d29922' : '#3fb950';
      return `<div class="air-repro-row"><span class="air-kn" style="color:${col};border-color:${col}">${rp.k}/${rp.n}</span>`
        + `<div class="air-meter"><div class="air-meter-fill" style="width:${pct}%;background:${col}"></div></div>`
        + `<span class="air-row-label">${esc((a.goal || '').slice(0, 72))}</span></div>`;
    }).join('') : '<div class="empty-placeholder">No reproduced attacks yet — feedback_attack with reproduce_n&gt;0.</div>';

    const txWrap = document.getElementById('air-transcripts');
    if (attacks.length) {
      txWrap.innerHTML = attacks.slice().reverse().map((a, i) => {
        const id = String(a.ts || a.goal || i);           // stable key across re-renders
        const col = a.jailbroken ? '#f85149' : '#3fb950';
        const turns = (a.transcript || []).map((t, ti) => {
          const complied = (typeof t.score === 'number' && t.score >= 0.6);
          const vcol = complied ? '#f85149' : '#3fb950';
          const vlabel = complied ? 'complied' : (t.label || 'resisted');
          const tag = `${esc(t.technique || 'attack')}${t.transform ? ' + ' + esc(t.transform) : ''}`;
          const sent = t.sent ? esc(t.sent) : `<span class="air-sub-note">(${tag} payload)</span>`;
          return `<div class="air-xchg"><div class="air-xchg-n">turn ${ti + 1} · phase ${t.phase || '-'}</div>`
            // attacker's move
            + `<div class="air-msg air-msg-atk"><div class="air-msg-head">`
            + `<span class="air-who air-who-atk">🗡 ATTACKER</span><span class="air-tech">${tag}</span></div>`
            + `<div class="air-msg-body">${sent}</div></div>`
            // AI app's reply
            + `<div class="air-msg air-msg-ai"><div class="air-msg-head">`
            + `<span class="air-who air-who-ai">🤖 AI APP</span>`
            + `<span class="air-verdict" style="color:${vcol}">${vlabel} · score ${t.score}</span></div>`
            + `<div class="air-msg-body">${esc((t.resp || '').slice(0, 240))}</div></div></div>`;
        }).join('');
        return `<details class="air-tx" data-txid="${esc(id)}"${_airOpenTx.has(id) ? ' open' : ''}>`
          + `<summary><span class="air-pill" style="color:${col};border-color:${col}">`
          + `${a.jailbroken ? 'JAILBROKEN' : 'resisted'}</span> `
          + `<span class="air-sub-note">${a.attempts} attempts</span> `
          + `<span class="air-row-label">${esc((a.goal || '').slice(0, 80))}</span></summary>`
          + `<div class="air-tx-body">${turns || '<span class="air-sub-note">no transcript</span>'}</div></details>`;
      }).join('');
      // Persist the user's open/closed choice so the next poll doesn't reset it.
      txWrap.querySelectorAll('details[data-txid]').forEach(el => {
        el.addEventListener('toggle', () => {
          const id = el.getAttribute('data-txid');
          if (el.open) _airOpenTx.add(id); else _airOpenTx.delete(id);
        });
      });
    } else {
      txWrap.innerHTML = '<div class="empty-placeholder">No feedback attacks yet — redteam(action="feedback_attack").</div>';
    }

    // ── garak ─────────────────────────────────────────────────────────────
    const garakWrap = document.getElementById('air-garak');
    garakWrap.innerHTML = garak.length
      ? garak.slice(-40).reverse().map(_garakBarRow).join('')
      : '<div class="empty-placeholder">No garak runs yet — scan(tool="garak", ...).</div>';

    // ── Defenses: input-filter bypass map ─────────────────────────────────
    const filterWrap = document.getElementById('air-filter');
    const flt = ai.filter;
    if (flt && flt.detail) {
      const bypass = Object.keys(flt.detail).filter(t => flt.detail[t] && t !== 'direct').sort();
      const blocked = Object.keys(flt.detail).filter(t => !flt.detail[t]).sort();
      const total = bypass.length + blocked.length;
      const chip = (t, ok) => `<span class="air-fchip" style="border-color:${ok ? '#f85149' : '#3fb950'};color:${ok ? '#f85149' : '#3fb950'}">${esc(t)}</span>`;
      const scol = bypass.length ? '#f85149' : '#3fb950';
      const posture = flt.plaintext_blocked ? 'blocks plaintext keywords' : 'does not even block plaintext keywords';
      const assess = bypass.length === 0
        ? 'No encodings bypass it — input is normalized before filtering. Strong posture.'
        : `${bypass.length} of ${total} tested encodings evade it — the filter matches raw text only, so obfuscated payloads reach the model. Recommend Unicode-normalized + semantic filtering, not keyword matching.`;
      filterWrap.innerHTML =
        `<div class="air-banner" style="border-left-color:${scol}"><span class="air-cal-dot" style="background:${scol}"></span>`
        + `<div><b style="color:${scol}">Input filter ${posture}</b> · `
        + `<b style="color:#f85149">${bypass.length}</b> bypass · <b style="color:#3fb950">${blocked.length}</b> blocked<br>`
        + `<span class="air-sub-note">${esc(assess)}</span></div></div>`
        + `<div class="air-def-cols">`
        + `<div class="air-def-col"><div class="air-def-col-title" style="color:#f85149">↯ Bypasses the filter (${bypass.length})</div>`
        + `<div class="air-fchips">${bypass.map(t => chip(t, true)).join('') || '<span class="air-sub-note">none</span>'}</div></div>`
        + `<div class="air-def-col"><div class="air-def-col-title" style="color:#3fb950">⛔ Blocked (${blocked.length})</div>`
        + `<div class="air-fchips">${blocked.map(t => chip(t, false)).join('') || '<span class="air-sub-note">none</span>'}</div></div>`
        + `</div>`;
    } else {
      filterWrap.innerHTML = '<div class="empty-placeholder">No filter probe yet — redteam(action="filter_probe").</div>';
    }

    // ── Overview: surface the top garak results so output is visible without
    //    switching sub-tabs (the #1 "I only see findings" complaint) ─────────
    const liteWrap = document.getElementById('air-garak-lite');
    if (liteWrap) {
      const top = garak.slice().sort((a, b) => (b.attack_success_rate || 0) - (a.attack_success_rate || 0)).slice(0, 8);
      liteWrap.innerHTML = top.length
        ? top.map(_garakBarRow).join('')
          + (garak.length > 8 ? `<div class="air-sub-note" style="margin-top:6px">+${garak.length - 8} more under “Automated (garak)” →</div>` : '')
        : '<div class="empty-placeholder">No garak runs yet — scan(tool="garak", ...).</div>';
    }

    // ── Sub-tab badges: show where the data is, so it isn't hidden ───────────
    const subCount = { garak: garak.length, attacks: attacks.length, defenses: bypasses };
    document.querySelectorAll('.air-subbtn').forEach(btn => {
      const base = btn.getAttribute('data-label')
        || btn.textContent.replace(/\s*\(\d+\)\s*$/, '').trim();
      btn.setAttribute('data-label', base);            // remember the clean label across polls
      const n = subCount[btn.getAttribute('data-sub')];
      btn.textContent = n ? `${base} (${n})` : base;
    });
  }

  window.pollAiRedteam = pollAiRedteam;
