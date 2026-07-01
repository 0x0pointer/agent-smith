  function toggleCovEndpoint(epId) {
    if (_openCovEndpoints.has(epId)) _openCovEndpoints.delete(epId);
    else _openCovEndpoints.add(epId);
    renderCoverage();
  }

  async function pollCoverage() {
    try {
      const r = await fetch(`/api/coverage?_=${Date.now()}`);
      if (!r.ok) return;
      _covData = await r.json();
      renderCoverage();
      // Update tab badge
      const meta = _covData.meta || {};
      const btn = document.getElementById('tab-btn-coverage');
      const total = meta.total_cells || 0;
      const tested = meta.tested || 0;
      if (btn && total > 0) {
        btn.textContent = `Coverage (${tested}/${total})`;
      }
    } catch { /* ignore */ }
  }

  function renderCoverage() {
    const wrap = document.getElementById('coverage-wrap');
    const sumWrap = document.getElementById('coverage-summary');
    if (!_covData || !_covData.endpoints || !_covData.endpoints.length) {
      wrap.innerHTML = '<div class="empty-placeholder">No coverage data yet — run a scan with web-exploit.</div>';
      sumWrap.innerHTML = '';
      return;
    }

    const meta = _covData.meta || {};
    const total = meta.total_cells || 0;
    const tested = meta.tested || 0;
    const vuln = meta.vulnerable || 0;
    const na = meta.not_applicable || 0;
    const skipped = meta.skipped || 0;
    const inProg = meta.in_progress || 0;
    const pending = total - tested - na - skipped - inProg;

    sumWrap.innerHTML = [
      `<span class="cov-stat cov-tested">TESTED ${tested}</span>`,
      `<span class="cov-stat cov-vulnerable">VULNERABLE ${vuln}</span>`,
      inProg ? `<span class="cov-stat" style="background:rgba(31,111,235,.15);border-color:#1f6feb;color:#58a6ff">IN PROGRESS ${inProg}</span>` : '',
      `<span class="cov-stat cov-na">N/A ${na}</span>`,
      `<span class="cov-stat cov-skipped">SKIPPED ${skipped}</span>`,
      `<span class="cov-stat cov-pending">PENDING ${pending}</span>`,
      `<span style="font-size:.8rem;color:#6e7681;align-self:center">${_covData.endpoints.length} endpoints · ${total} cells</span>`,
    ].join('');

    // Collect all injection types that have at least one cell
    const injTypes = new Set();
    (_covData.matrix || []).forEach(c => injTypes.add(c.injection_type));
    const cols = [...injTypes].sort();

    // Build endpoint→param→injection_type map
    const epMap = {};
    _covData.endpoints.forEach(ep => { epMap[ep.id] = ep; });
    const cellMap = {};  // key: "ep_id|param|inj_type" → cell
    (_covData.matrix || []).forEach(c => {
      cellMap[`${c.endpoint_id}|${c.param}|${c.injection_type}`] = c;
    });

    // Group rows by endpoint
    const epGroups = {};
    _covData.endpoints.forEach(ep => {
      const params = new Set();
      (_covData.matrix || []).forEach(c => {
        if (c.endpoint_id === ep.id) params.add(c.param);
      });
      epGroups[ep.id] = { ep, params: [...params].sort() };
    });

    // Per-endpoint summary: count statuses
    function epSummary(epId) {
      const cells = (_covData.matrix || []).filter(c => c.endpoint_id === epId);
      const counts = { pending: 0, in_progress: 0, tested_clean: 0, vulnerable: 0, not_applicable: 0, skipped: 0 };
      cells.forEach(c => { if (counts[c.status] !== undefined) counts[c.status]++; });
      return counts;
    }

    // Render table
    const colHeaders = cols.map(c =>
      `<th class="cov-col-header">${esc(c)}</th>`
    ).join('');

    function cellHtml(epId, param, inj, ep) {
      const key = `${epId}|${param}|${inj}`;
      const cell = cellMap[key];
      if (!cell) return '<td></td>';
      return `<td><span class="cov-cell ${cell.status}"
        data-cell-id="${cell.id}"
        data-ep-path="${esc(ep.path)}"
        data-ep-method="${esc(ep.method)}"
        data-param="${esc(param)}"
        data-inj="${esc(inj)}"
        data-status="${cell.status}"
        data-notes="${esc(cell.notes || '')}"
        data-finding="${cell.finding_id || ''}"
        data-tested="${cell.tested_at || ''}"
        onmouseenter="showCovTooltip(event,this)"
        onmouseleave="hideCovTooltip()"
      ></span></td>`;
    }

    let bodyRows = '';
    Object.values(epGroups).forEach(({ ep, params }) => {
      const s = epSummary(ep.id);
      const totalCells = s.pending + s.in_progress + s.tested_clean + s.vulnerable + s.not_applicable + s.skipped;
      const doneCells = s.tested_clean + s.vulnerable + s.not_applicable + s.skipped;
      const vulnBadge = s.vulnerable ? `<span style="color:#ff4d4f;margin-left:.5rem">${s.vulnerable} vuln</span>` : '';
      const progBadge = s.in_progress ? `<span style="color:#58a6ff;margin-left:.5rem">${s.in_progress} in progress</span>` : '';
      const isOpen = _openCovEndpoints.has(ep.id);
      const arrow = isOpen ? '&#9660;' : '&#9654;';

      // Endpoint header row (clickable)
      bodyRows += `<tr class="cov-ep-header" data-id="${esc(ep.id)}" onclick="toggleCovEndpoint(this.dataset.id)" style="cursor:pointer">
        <td style="font-weight:600;color:#f0f6fc">
          <span style="margin-right:.4rem;font-size:.7rem">${arrow}</span>
          ${esc(ep.method)} ${esc(ep.path)}
          <span style="color:#6e7681;font-weight:400;margin-left:.5rem">${doneCells}/${totalCells}</span>
          ${vulnBadge}${progBadge}
        </td>
        ${cols.map(() => '<td></td>').join('')}
      </tr>`;

      // Param rows (collapsible)
      if (isOpen) {
        params.forEach(p => {
          const label = p === '_endpoint'
            ? '<span style="color:#6e7681;padding-left:1.2rem">endpoint-level</span>'
            : `<span style="padding-left:1.2rem">${esc(p)} <span style="color:#6e7681;font-size:.75rem">(${(_covData.matrix||[]).find(c=>c.endpoint_id===ep.id&&c.param===p)?.param_type||''})</span></span>`;
          const cells = cols.map(inj => cellHtml(ep.id, p, inj, ep)).join('');
          bodyRows += `<tr><td>${label}</td>${cells}</tr>`;
        });
      }
    });

    wrap.innerHTML = `<div style="overflow-x:auto"><table class="cov-matrix">
      <thead><tr><th>Endpoint / Param</th>${colHeaders}</tr></thead>
      <tbody>${bodyRows}</tbody>
    </table></div>`;
  }

  function showCovTooltip(e, el) {
    const tt = document.getElementById('cov-tooltip');
    const statusColors = {
      pending: '#8b949e', in_progress: '#58a6ff', tested_clean: '#3fb950', vulnerable: '#ff4d4f',
      not_applicable: '#6e7681', skipped: '#d2a922'
    };
    const status = el.dataset.status || '';
    const color = statusColors[status] || '#8b949e';

    // Build with DOM nodes + textContent — NOT innerHTML. The dataset values
    // (endpoint path, param, notes) originate from scan-target bytes; assigning
    // them via textContent means they are never parsed as HTML, so a stored
    // `<img onerror=…>` renders as inert text instead of executing (AS-05).
    const row = (style) => { const d = document.createElement('div'); if (style) d.style.cssText = style; return d; };
    const strong = (text) => { const s = document.createElement('strong'); s.textContent = text; return s; };
    tt.textContent = '';

    const head = row('');
    head.appendChild(strong(`${el.dataset.epMethod || ''} ${el.dataset.epPath || ''}`));
    tt.appendChild(head);

    const paramRow = row('margin-top:.2rem');
    paramRow.append('Param: ', strong(el.dataset.param === '_endpoint' ? '(endpoint-level)' : (el.dataset.param || '')));
    tt.appendChild(paramRow);

    const testRow = row('margin-top:.2rem');
    testRow.append('Test: ', strong(el.dataset.inj || ''));
    tt.appendChild(testRow);

    const statusRow = row('margin-top:.3rem');
    const statusSpan = document.createElement('span');
    statusSpan.className = 'cov-tt-status';
    statusSpan.style.color = color;
    statusSpan.textContent = status.replace('_', ' ');
    statusRow.appendChild(statusSpan);
    tt.appendChild(statusRow);

    if (el.dataset.notes) {
      const n = row('margin-top:.3rem;color:#8b949e'); n.textContent = el.dataset.notes; tt.appendChild(n);
    }
    if (el.dataset.finding) {
      const f = row('margin-top:.2rem;color:#58a6ff'); f.textContent = `Finding: ${el.dataset.finding}`; tt.appendChild(f);
    }
    if (el.dataset.tested) {
      const d = row('margin-top:.2rem;color:#6e7681;font-size:.72rem');
      d.textContent = new Date(el.dataset.tested).toLocaleString(); tt.appendChild(d);
    }

    tt.style.display = 'block';
    tt.style.left = (e.clientX + 12) + 'px';
    tt.style.top = (e.clientY + 12) + 'px';
  }

  function hideCovTooltip() {
    document.getElementById('cov-tooltip').style.display = 'none';
  }

  // ── Threat Model tab ──────────────────────────────────────────────────────
  let _tmCurrentFile    = '';
  let _tmCurrentContent = '';
