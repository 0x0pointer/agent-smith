  async function renderTopology(diagrams) {
    const wrap = document.getElementById('diagrams-wrap');
    if (!diagrams.length) {
      wrap.innerHTML = '<div class="empty-placeholder">No diagrams yet — Claude calls report_diagram during a scan.</div>';
      return;
    }
    // Clear placeholder if it's still there
    const placeholder = wrap.querySelector('.empty-placeholder');
    if (placeholder) placeholder.remove();
    const existing = new Set([...wrap.querySelectorAll('[data-diag-id]')].map(el => el.dataset.diagId));
    for (const d of diagrams) {
      if (existing.has(d.id)) continue;
      const card = document.createElement('div');
      card.className = 'diagram-card';
      card.dataset.diagId = d.id;
      card.innerHTML = `<h3>${esc(d.title)}</h3><span class="ts">${new Date(d.timestamp).toLocaleTimeString()}</span>`;

      // Wrap in zoomable container
      const zoomWrap = document.createElement('div');
      zoomWrap.className = 'diagram-zoom-wrap';
      const zoomInner = document.createElement('div');
      zoomInner.className = 'diagram-zoom-inner';

      if (d.svg) {
        // Use server-rendered SVG (matches threat model theme)
        zoomInner.innerHTML = d.svg;
        const svgEl = zoomInner.querySelector('svg');
        if (svgEl) { svgEl.style.maxWidth = '100%'; svgEl.style.height = 'auto'; }
      } else {
        // Fallback to client-side rendering
        const mermaidEl = document.createElement('div');
        mermaidEl.className = 'mermaid';
        mermaidEl.textContent = d.mermaid;
        zoomInner.appendChild(mermaidEl);
        try {
          await mermaid.run({ nodes: [mermaidEl] });
        } catch (err) {
          mermaidEl.innerHTML = `<div style="color:#ff4d4f;font-size:.8rem;margin-bottom:.5rem">
            ⚠ Mermaid render error: ${esc(String(err?.message||err))}</div>
            <pre style="background:#010409;color:#7ee787;padding:.6rem;border-radius:4px;
                        font-size:.75rem;white-space:pre-wrap;word-break:break-all;
                        border:1px solid #21262d;max-height:400px;overflow-y:auto">${esc(d.mermaid)}</pre>`;
        }
      }

      zoomWrap.appendChild(zoomInner);
      zoomWrap.insertAdjacentHTML('beforeend', `<div class="diagram-zoom-controls">
        <button onclick="diagramZoom(this,1.3)" title="Zoom in">+</button>
        <button onclick="diagramZoom(this,0.7)" title="Zoom out">&minus;</button>
        <button onclick="diagramReset(this)" title="Reset view">&#8634;</button>
      </div>`);
      initDiagramPanZoom(zoomWrap);
      card.appendChild(zoomWrap);
      wrap.appendChild(card);
    }
  }

  // ── Diagram pan/zoom ─────────────────────────────────────────────────────
  function initDiagramPanZoom(wrap) {
    let scale = 1, tx = 0, ty = 0, dragging = false, sx = 0, sy = 0;
    const inner = wrap.querySelector('.diagram-zoom-inner');
    const apply = () => { inner.style.transform = `translate(${tx}px,${ty}px) scale(${scale})`; };

    wrap.addEventListener('wheel', e => {
      e.preventDefault();
      const factor = e.deltaY < 0 ? 1.15 : 0.87;
      scale = Math.max(0.1, Math.min(10, scale * factor));
      apply();
    }, { passive: false });

    wrap.addEventListener('mousedown', e => {
      if (e.target.closest('.diagram-zoom-controls')) return;
      dragging = true; sx = e.clientX - tx; sy = e.clientY - ty;
    });
    wrap.addEventListener('mousemove', e => {
      if (!dragging) return;
      tx = e.clientX - sx; ty = e.clientY - sy; apply();
    });
    wrap.addEventListener('mouseup', () => { dragging = false; });
    wrap.addEventListener('mouseleave', () => { dragging = false; });

    wrap._pz = { reset() { scale = 1; tx = 0; ty = 0; apply(); }, zoom(f) { scale = Math.max(0.1, Math.min(10, scale * f)); apply(); } };
  }

  function diagramZoom(btn, factor) {
    const wrap = btn.closest('.diagram-zoom-wrap');
    if (wrap?._pz) wrap._pz.zoom(factor);
  }

  function diagramReset(btn) {
    const wrap = btn.closest('.diagram-zoom-wrap');
    if (wrap?._pz) wrap._pz.reset();
  }

  // ── Components tab ────────────────────────────────────────────────────────
  const _COMP_RULES = [
    [/ftp|sftp/i,                                           '📂', 'FTP Server'],
    [/smtp|email|\bmail\b/i,                                '📧', 'Mail Server'],
    [/\bssh\b/i,                                            '🔒', 'SSH Service'],
    [/admin|management panel|control panel|back.?office/i,  '⚙️',  'Admin Panel'],
    [/database|sql dump|mongo|redis|postgres|mysql|\bdb\b/i,'🗄️', 'Database'],
    [/prometheus|grafana|metric|monitor|observ/i,            '📊', 'Monitoring'],
    [/login|logout|auth|session|password|credential/i,       '🔑', 'Authentication'],
    [/api\b|rest\b|graphql|endpoint/i,                       '🔌', 'API'],
    [/cors|csp\b|clickjack|security.?header/i,               '🌐', 'Web Config'],
    [/docker|kubernetes|k8s|container/i,                     '🐳', 'Infrastructure'],
    [/aws|s3\b|azure|gcp|cloud/i,                            '☁️', 'Cloud Services'],
    [/upload|file.*upload/i,                                 '📤', 'File Upload'],
    [/\bsmb\b|samba|ldap|\brdp\b|\bvnc\b/i,                '🖧',  'Network Services'],
  ];

  function _inferComponent(f) {
    const t = `${f.title||''} ${f.description||''}`;
    for (const [pat, icon, name] of _COMP_RULES) {
      if (pat.test(t)) return { icon, name };
    }
    const tool = (f.tool_used||'').toLowerCase();
    if (tool === 'nmap' || tool === 'naabu')         return { icon: '🖧',  name: 'Network Services' };
    if (tool === 'trufflehog' || tool === 'semgrep') return { icon: '📝', name: 'Codebase' };
    return { icon: '🌐', name: 'Web Application' };
  }

  const _SEV_SORT = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
