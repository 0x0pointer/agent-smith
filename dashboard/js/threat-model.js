  function onTmFileChange() {
    const sel = document.getElementById('tm-file-select');
    _tmCurrentFile    = sel.value;
    _tmCurrentContent = ''; // force re-render
    pollThreatModel();
  }

  async function pollThreatModel() {
    if (scanDone) return;
    let data;
    try {
      const qs = _tmCurrentFile ? `&file=${encodeURIComponent(_tmCurrentFile)}` : '';
      const r  = await fetch(`/api/threat-model?_=${Date.now()}${qs}`);
      if (!r.ok) return;
      data = await r.json();
    } catch { return; }

    // Update file dropdown
    const files = data.files || [];
    const sel   = document.getElementById('tm-file-select');
    const prev  = sel.value || data.file || '';
    while (sel.options.length > 1) sel.remove(1);
    for (const f of files) {
      const opt = document.createElement('option');
      opt.value = f; opt.textContent = f;
      sel.appendChild(opt);
    }
    if (prev) sel.value = prev;

    // Mark tab when files exist
    if (files.length) {
      const btn = document.getElementById('tab-btn-threat-model');
      if (btn && !btn.textContent.includes('●')) btn.textContent = 'Threat Model ●';
    }

    if (!data.content) return;
    if (data.content === _tmCurrentContent) return; // no change
    _tmCurrentContent = data.content;

    // Update filename label
    const tsEl = document.getElementById('tm-file-ts');
    if (tsEl) tsEl.textContent = data.file || '';

    await renderThreatModel(data.content, data.svgs || {});
  }

  // Remap light pastel style colours to dark equivalents so diagrams
  // authored with light fills render correctly on the dark dashboard.
  const _TM_COLOR_MAP = {
    'fill:#f44': 'fill:#7a0000', 'fill:#f88': 'fill:#6b1a1a',
    'fill:#faa': 'fill:#5c1a1a', 'fill:#fcc': 'fill:#4d1a1a',
    'fill:#ffd': 'fill:#3d3000', 'fill:#ffa': 'fill:#3d3000',
    'fill:#ddf': 'fill:#1a2a4a', 'fill:#bbf': 'fill:#1a2040',
    'stroke:#c00': 'stroke:#ff6666', 'stroke:#a00': 'stroke:#ff5555',
    'stroke:#c44': 'stroke:#ff8888', 'stroke:#aa0': 'stroke:#ddcc00',
    'stroke:#44a': 'stroke:#6699ff',
  };
  function _remapMermaidColors(src) {
    for (const [light, dark] of Object.entries(_TM_COLOR_MAP))
      src = src.replaceAll(light, dark);
    return src;
  }

  async function renderThreatModel(content, svgs) {
    const wrap = document.getElementById('threat-model-wrap');
    wrap.classList.remove('empty');
    const html = (typeof marked !== 'undefined')
      ? marked.parse(content)
      : `<pre style="white-space:pre-wrap;word-break:break-all;font-size:.82rem;color:#c9d1d9">${esc(content)}</pre>`;
    wrap.innerHTML = `<div id="tm-content">${html}</div>`;

    // Replace mermaid code blocks with server-rendered SVGs when available,
    // fall back to client-side rendering only when server SVGs are missing.
    let idx = 0;
    const blocks = [...wrap.querySelectorAll('pre code.language-mermaid')];
    for (const block of blocks) {
      const pre = block.parentElement;
      const div = document.createElement('div');
      div.className = 'tm-mermaid-wrap diagram-zoom-wrap';
      const zoomInner = document.createElement('div');
      zoomInner.className = 'diagram-zoom-inner';

      const serverSvg = svgs[String(idx)];
      if (serverSvg) {
        // Use server-rendered SVG (reliable, uses mermaid-config.json theme)
        zoomInner.innerHTML = serverSvg;
        const svgEl = zoomInner.querySelector('svg');
        if (svgEl) { svgEl.style.maxWidth = '100%'; svgEl.style.height = 'auto'; }
      } else {
        // Fall back to client-side rendering
        const mermaidEl = document.createElement('div');
        mermaidEl.className = 'mermaid';
        mermaidEl.textContent = _remapMermaidColors(block.textContent);
        zoomInner.appendChild(mermaidEl);
        try {
          await mermaid.run({ nodes: [mermaidEl] });
        } catch (err) {
          mermaidEl.innerHTML = `<div style="color:#ff4d4f;font-size:.8rem;margin-bottom:.5rem">
            ⚠ Mermaid render error: ${esc(String(err?.message||err))}</div>
            <pre style="background:#010409;color:#7ee787;padding:.6rem;border-radius:4px;
                        font-size:.75rem;white-space:pre-wrap;word-break:break-all;
                        border:1px solid #21262d;max-height:400px;overflow-y:auto">${esc(block.textContent)}</pre>`;
        }
      }

      div.appendChild(zoomInner);
      div.insertAdjacentHTML('beforeend', `<div class="diagram-zoom-controls">
        <button onclick="diagramZoom(this,1.3)" title="Zoom in">+</button>
        <button onclick="diagramZoom(this,0.7)" title="Zoom out">&minus;</button>
        <button onclick="diagramReset(this)" title="Reset view">&#8634;</button>
      </div>`);
      initDiagramPanZoom(div);
      pre.replaceWith(div);
      idx++;
    }
  }

  // ── Logs tab ──────────────────────────────────────────────────────────────
  let _selectedLogFile = '';
