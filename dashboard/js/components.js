  function renderComponentMap(findings) {
    const wrap = document.getElementById('components-wrap');
    if (!findings.length) {
      wrap.innerHTML = '<div class="empty-placeholder">No findings yet — run a scan.</div>';
      return;
    }
    const groups = {};
    for (const f of findings) {
      const { icon, name } = _inferComponent(f);
      if (!groups[name]) groups[name] = { icon, name, findings: [] };
      groups[name].findings.push(f);
    }
    const sorted = Object.values(groups).sort((a, b) => {
      const worstA = Math.min(...a.findings.map(f => _SEV_SORT[f.severity] ?? 5));
      const worstB = Math.min(...b.findings.map(f => _SEV_SORT[f.severity] ?? 5));
      return worstA - worstB;
    });
    sorted.forEach(g => g.findings.sort((a, b) =>
      (_SEV_SORT[a.severity] ?? 5) - (_SEV_SORT[b.severity] ?? 5)
    ));
    const total = findings.length;
    const header = `<div style="font-size:.82rem;color:#6e7681;margin-bottom:1rem">
      ${sorted.length} component${sorted.length!==1?'s':''} · ${total} finding${total!==1?'s':''}
    </div>`;
    const cards = sorted.map(g => {
      const vulns = g.findings.map(f => `
        <div class="comp-vuln">
          <span class="badge badge-${f.severity}">${f.severity}</span>
          <span class="comp-vuln-title">${esc(f.title)}</span>
        </div>`).join('');
      return `<div class="comp-card">
        <div class="comp-header">
          <span class="comp-icon">${g.icon}</span>
          <span class="comp-name">${esc(g.name)}</span>
          <span class="comp-count">${g.findings.length} finding${g.findings.length!==1?'s':''}</span>
        </div>
        ${vulns}
      </div>`;
    }).join('');
    wrap.innerHTML = header + `<div class="comp-grid">${cards}</div>`;
  }

  // ── Coverage tab ─────────────────────────────────────────────────────────
  let _covData = null;
  const _openCovEndpoints = new Set();
