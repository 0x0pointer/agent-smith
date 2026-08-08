  // ============================================================================
  //  shared.js — security-critical core shared by the dashboard shell (index.html)
  //  and the standalone finding detail page (finding.html).
  //
  //  Loaded FIRST on both pages, before common.js / findings.js / finding.js.
  //  These definitions used to live in common.js; they were lifted here so the
  //  detail page (opened in a new browser tab) authenticates with the SAME token
  //  logic instead of a drifting copy. Keep this the only place they are defined.
  // ============================================================================

  // ── Dashboard auth: per-session bearer token ────────────────────────────────
  // The MCP server mints a random token when a scan starts and prints the
  // dashboard URL with it in the fragment (…/#k=<token>). Capture it into
  // sessionStorage (never sent to the server via the URL), strip it from the
  // address bar, and attach it as `Authorization: Bearer …` on every same-origin
  // API call. A finding detail page opened from a same-origin link inherits a
  // copy of this sessionStorage, so it authenticates without its own #k= fragment.
  (function initDashboardAuth() {
    const KEY = 'smith_dash_token';
    function token() {
      try { return sessionStorage.getItem(KEY) || ''; } catch (_) { return ''; }
    }
    try {
      const m = (location.hash || '').match(/[#&]k=([^&]+)/);
      if (m) {
        sessionStorage.setItem(KEY, decodeURIComponent(m[1]));
        history.replaceState(null, '', location.pathname + location.search);
      }
    } catch (_) { /* storage unavailable — wrapper simply no-ops */ }

    const _origFetch = window.fetch.bind(window);
    window.fetch = function (input, init) {
      let sameOrigin = true;
      try {
        const raw = (typeof input === 'string') ? input : (input && input.url) || '';
        sameOrigin = new URL(raw, location.href).origin === location.origin;
      } catch (_) { sameOrigin = true; }
      const t = token();
      if (sameOrigin && t) {
        init = init ? Object.assign({}, init) : {};
        const h = new Headers(init.headers || (typeof input !== 'string' && input && input.headers) || {});
        if (!h.has('Authorization')) h.set('Authorization', 'Bearer ' + t);
        init.headers = h;
      }
      return _origFetch(input, init);
    };

    // No token yet (bare URL / bookmark)? Ask once — the CLI prints the key with
    // the dashboard URL. Blank just leaves calls unauthenticated, which is fine
    // before a scan has started (nothing sensitive is served).
    try {
      if (!token()) {
        const pasted = window.prompt(
          'Dashboard key required.\nPaste the key printed with the dashboard URL ' +
          '(leave blank if no scan has started yet):'
        );
        if (pasted) sessionStorage.setItem(KEY, pasted.trim());
      }
    } catch (_) { /* non-interactive context */ }
  })();

  // ── HTML escape ─────────────────────────────────────────────────────────────
  // The single output-escaping primitive. All scan-derived strings pass through
  // this before hitting innerHTML.
  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  // ── HTML sanitizer for untrusted markdown (threat-model tab, remediation) ────
  // marked@9 passes raw HTML through, and scan-derived markdown embeds
  // attacker-influenced recon strings. Render marked's output through this
  // allow-list DOM sanitizer before innerHTML so injected tags / event handlers
  // / scripts / javascript: URLs cannot execute. Keeps <pre><code class=…> so the
  // mermaid post-processing still finds language-mermaid blocks.
  const _SANITIZE_ALLOWED_TAGS = new Set([
    'A','P','DIV','SPAN','BR','HR','PRE','CODE','BLOCKQUOTE','KBD','SMALL',
    'H1','H2','H3','H4','H5','H6','UL','OL','LI','STRONG','EM','B','I','U',
    'DEL','INS','SUP','SUB','TABLE','THEAD','TBODY','TFOOT','TR','TH','TD','DL','DT','DD','IMG',
  ]);
  const _SANITIZE_ALLOWED_ATTRS = new Set([
    'href','src','alt','title','class','colspan','rowspan','align','start',
  ]);
  const _SANITIZE_DROP_TAGS = new Set([
    'SCRIPT','STYLE','IFRAME','OBJECT','EMBED','FORM','LINK','META','BASE','SVG','MATH','TEMPLATE',
  ]);
  function sanitizeHtml(html) {
    const doc = new DOMParser().parseFromString(String(html), 'text/html');
    const walk = (root) => {
      [...root.children].forEach((el) => {
        const tag = el.tagName;
        if (!_SANITIZE_ALLOWED_TAGS.has(tag)) {
          if (_SANITIZE_DROP_TAGS.has(tag)) { el.remove(); return; }
          const span = doc.createElement('span');   // unwrap unknown tags to text
          span.textContent = el.textContent;
          el.replaceWith(span);
          return;
        }
        [...el.attributes].forEach((a) => {
          const name = a.name.toLowerCase();
          if (!_SANITIZE_ALLOWED_ATTRS.has(name)) { el.removeAttribute(a.name); return; }
          if (name === 'href' || name === 'src') {
            const v = (a.value || '').replace(/[\u0000-\u0020]+/g, '').toLowerCase();
            if (v.startsWith('javascript:') || v.startsWith('vbscript:') ||
                (v.startsWith('data:') && !v.startsWith('data:image/'))) {
              el.removeAttribute(a.name);
            }
          }
        });
        walk(el);
      });
    };
    walk(doc.body);
    return doc.body.innerHTML;
  }

  // ── Mermaid theme (matches the threat-model / topology dark rendering) ───────
  mermaid.initialize({
    startOnLoad: false,
    theme: 'base',
    themeVariables: {
      background: '#0d1117',
      primaryColor: '#1f2937',
      primaryTextColor: '#e5e7eb',
      primaryBorderColor: '#374151',
      secondaryColor: '#1e3a5f',
      secondaryTextColor: '#e5e7eb',
      secondaryBorderColor: '#2563eb',
      tertiaryColor: '#2d1f3d',
      tertiaryTextColor: '#e5e7eb',
      tertiaryBorderColor: '#7c3aed',
      lineColor: '#6b7280',
      textColor: '#e5e7eb',
      noteBkgColor: '#1e293b',
      noteTextColor: '#cbd5e1',
      noteBorderColor: '#334155',
      fontSize: '14px',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
    },
    flowchart: { curve: 'linear', htmlLabels: false },
  });
