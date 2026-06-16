  async function pollMetrics() {
    try {
      const r = await fetch(`/api/metrics?_=${Date.now()}`);
      if (!r.ok) return;
      _metricsData = await r.json();
      if (_activeTab === 'metrics') renderMetrics();
      const btn = document.getElementById('tab-btn-metrics');
      if (btn) btn.textContent = _metricsData.length ? `Metrics (${_metricsData.length})` : 'Metrics';
      const upd = document.getElementById('metrics-updated');
      if (upd && _metricsData.length) upd.textContent = `${_metricsData.length} run(s) recorded`;
    } catch { /* ignore */ }
  }

  function renderMetrics() {
    const wrap = document.getElementById('metrics-wrap');
    if (!wrap) return;
    if (!_metricsData || !_metricsData.length) {
      wrap.innerHTML = '<div class="empty-placeholder">No completed scans yet — metrics appear after session(action=\'complete\').</div>';
      return;
    }

    // Show newest first
    const rows = [..._metricsData].reverse();

    const sev = (r, s) => r[`findings_${s}`] ?? 0;
    const fmt = v => v == null ? '—' : v;
    const pct = v => v == null ? '—' : `${v}%`;
    const dur = v => v == null ? '—' : `${v}m`;
    const usd = v => v == null ? '—' : `$${v.toFixed(4)}`;

    const cols = [
      { label: 'Run ID',        fn: r => `<span title="${r.run_id || ''}" style="font-family:monospace;font-size:0.7rem">${(r.run_id || '—').slice(0, 8)}</span>` },
      { label: 'Target',        fn: r => `<span style="max-width:140px;display:inline-block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${r.target || ''}">${r.target || '—'}</span>` },
      { label: 'Depth',         fn: r => fmt(r.depth) },
      { label: 'Status',        fn: r => {
        const s = r.status || 'complete';
        const color = s === 'complete' ? 'var(--green)' : s === 'limit_reached' ? 'var(--warning)' : 'var(--red)';
        return `<span style="color:${color}">${s}</span>`;
      }},
      { label: 'Duration',      fn: r => dur(r.duration_minutes) },
      { label: 'Cost',          fn: r => usd(r.total_cost_usd) },
      { label: '$/finding',     fn: r => fmt(r.cost_per_finding == null ? null : `$${r.cost_per_finding.toFixed(4)}`) },
      { label: 'Calls',         fn: r => fmt(r.tool_calls_total) },
      { label: 'Coverage%',     fn: r => pct(r.coverage_rate_pct) },
      { label: 'Crit',          fn: r => `<span style="color:var(--red)">${sev(r,'critical')}</span>` },
      { label: 'High',          fn: r => `<span style="color:var(--orange)">${sev(r,'high')}</span>` },
      { label: 'Med',           fn: r => `<span style="color:var(--warning)">${sev(r,'medium')}</span>` },
      { label: 'Low',           fn: r => sev(r,'low') },
      { label: 'PoC%',          fn: r => pct(r.poc_coverage_rate_pct) },
      { label: 'FP',            fn: r => fmt(r.false_positive_count) },
      { label: 'Resumes',       fn: r => {
        const v = r.resume_events ?? 0;
        return `<span style="color:${v > 0 ? 'var(--warning)' : 'inherit'}">${v}</span>`;
      }},
      { label: 'Dups',          fn: r => {
        const v = r.duplicate_tool_calls ?? 0;
        return `<span style="color:${v > 0 ? 'var(--warning)' : 'inherit'}">${v}</span>`;
      }},
      { label: 'Steers',        fn: r => fmt(r.steering_interventions) },
      { label: 'Skills',        fn: r => fmt(r.skill_chain_depth) },
    ];

    const thead = `<thead><tr>${cols.map(c => `<th>${c.label}</th>`).join('')}</tr></thead>`;
    const tbody = `<tbody>${rows.map(r =>
      `<tr>${cols.map(c => `<td>${c.fn(r)}</td>`).join('')}</tr>`
    ).join('')}</tbody>`;

    wrap.innerHTML = `
      <div style="overflow-x:auto">
        <table class="metrics-table">${thead}${tbody}</table>
      </div>
      ${rows.length > 1 ? _renderMetricsTrend(rows) : ''}
    `;
  }

  function _renderMetricsTrend(rows) {
    // Simple sparkline-style text summary comparing last 2 runs
    const [latest, prev] = rows;
    const delta = (a, b, higherIsBetter) => {
      if (a == null || b == null) return '';
      const d = a - b;
      if (Math.abs(d) < 0.001) return '<span style="color:var(--text-dim)">→</span>';
      const better = higherIsBetter ? d > 0 : d < 0;
      const arrow = d > 0 ? '▲' : '▼';
      const color = better ? 'var(--green)' : 'var(--red)';
      return `<span style="color:${color}">${arrow} ${Math.abs(d).toFixed(2)}</span>`;
    };
    return `
      <div style="margin-top:1rem;padding:0.75rem 1rem;background:var(--bg-card);border-radius:6px;border:1px solid var(--border);font-size:0.78rem">
        <strong>vs previous run:</strong>
        cost ${delta(latest.total_cost_usd, prev.total_cost_usd, false)} &nbsp;
        coverage ${delta(latest.coverage_rate_pct, prev.coverage_rate_pct, true)} &nbsp;
        duration ${delta(latest.duration_minutes, prev.duration_minutes, false)} &nbsp;
        findings ${delta(latest.findings_total, prev.findings_total, true)} &nbsp;
        resumes ${delta(latest.resume_events, prev.resume_events, false)}
      </div>
    `;
  }

  // ── Stuck Events log ──────────────────────────────────────────────────────