# Dashboard Redesign Plan

A visual + structural redesign of the pentest dashboard that **keeps every colour
and the logo exactly as they are**, moves navigation to a **left sidebar**, makes
the whole thing easier to read, and adds a **click-through finding detail page that
opens in a new browser tab**.

---

## 1. Goals & hard constraints

**What you asked for**
1. Redesign the dashboard — better visual hierarchy, more readable, "visually pretty".
2. Keep all the colours and the logo.
3. Click a finding → open a richer detail view **in a new tab**.
4. Move the navigation menu to the **left side**.

**Fixed — do not touch**
- The palette. Every `:root` token stays: `--bg #13112e`, `--bg-card #1a1840`,
  `--bg-raised #2d2b55`, `--green #5bf29b`, `--purple #7b78ff`, and the severity
  colours (`#ff4d4f / #fa8c16 / #faad14 / green / purple`). No new hues.
- The logo (`/logo.png` → `FullLogo_Transparent.png`) and favicons.
- Every data contract and behaviour: 5 s polling, the Command Center (steer/complete/
  force-stop/triage), the HIR intervention panel, all 10 tabs, auth token flow, CSP.

**Interpretation of "new tab"** — a real **browser tab** serving a standalone
`/finding/<id>` page (not an 11th in-dashboard tab). This is the stronger UX: the URL
is deep-linkable and shareable, right-click / middle-click / ⌘-click work natively, and
the operator can keep the live scan open in one tab while reading a finding in another.
If you actually meant an in-app panel, the same detail markup drops into a tab instead —
say so and I'll pivot; everything else in this plan is unaffected.

---

## 2. Where things stand today (so scope is honest)

- **Frontend** lives in `dashboard/`: one `index.html` shell that Jinja `{% include %}`s
  10 tab partials from `dashboard/tabs/*.html`, styled by a single **985-line**
  `dashboard/css/dashboard.css`, driven by per-tab JS in `dashboard/js/*.js`
  (`common.js` is the shared core: auth shim, `esc()`, sanitizer, `switchTab`, polling).
- **Served** by FastAPI in `core/api_server/`: `dashboard_routes.py` renders `/` via
  Jinja2; `/static` is mounted at `dashboard/`; findings come from `GET /api/findings`
  (returns *all* findings + diagrams + chains, mermaid pre-rendered server-side).
- **Findings today** render as stacked cards in `findings.js::cardHTML()` with a
  severity left-border, badges, inline description, and expandable evidence + Replay/Fix/
  GH-issue buttons. There is **no per-finding route and no detail view** — every field is
  crammed into the card or hidden in a `<details>`.
- **Navigation today** is a horizontal `<nav class="tab-nav">` of 10 `.tab-btn`s below
  the Command Center; `switchTab(name)` toggles `.tab-content.active` and kicks the
  relevant poller.
- **Auth** (important for the new tab): a scan mints a bearer token delivered in the URL
  fragment `#k=…`; `common.js` stores it in `sessionStorage[smith_dash_token]` and a
  patched `window.fetch` attaches `Authorization: Bearer …` to same-origin `/api/*` calls.
  `sessionStorage` **is copied into a new tab opened from a same-origin link**, so a
  detail page opened via `target="_blank"` authenticates automatically — *provided it
  loads the same auth shim*.

The design system is almost entirely CSS + a few JS render functions. That makes this a
**low-risk, CSS-led redesign plus additive backend routes** — no change to how scans run.

---

## 3. Design language (refinement, not reinvention)

The brief pins the palette and logo, so craft goes into **typography rhythm, spacing,
hierarchy, and one signature element** — not new colours.

### 3.1 Keep the fonts, fix the scale
The existing trio is already characterful and stays: **Chakra Petch** (display/labels),
**Outfit** (body), **IBM Plex Mono** (data/evidence/metrics). Today everything is tiny and
flat (`h1` is 1.05 rem; most text 0.7–0.8 rem), which reads as cramped. Introduce a real
type scale as CSS variables:

| Role | Font | Size / weight | Use |
|---|---|---|---|
| Page title | Chakra Petch | 1.5 rem / 600 | header brand line |
| Section head | Chakra Petch | 1.0 rem / 600, +0.03em | tab titles, detail-page section labels |
| Card / finding title | Outfit | 0.95 rem / 600 | finding titles |
| Body | Outfit | 0.875 rem / 400 (**up from ~0.8**) | descriptions, impact |
| Label / eyebrow | IBM Plex Mono | 0.7 rem / 600 uppercase, +0.08em | field labels, meta |
| Data / evidence | IBM Plex Mono | 0.8 rem | `<pre>`, metrics, IDs |

### 3.2 Spacing on a 4 px grid
Add `--sp-1:4px … --sp-6:24px` and use them consistently. The current mix of
`0.3/0.4/0.55/0.75rem` ad-hoc gaps is what makes it feel noisy. One rhythm = calmer page.

### 3.3 Promote severity to shared tokens
Lift the severity colours (currently duplicated across `.stat-*`, `.badge-*`, `.sev-*`)
into `:root` so the list **and** the new detail page share one source of truth:

```css
:root{
  --sev-critical:#ff4d4f; --sev-high:#fa8c16; --sev-medium:#faad14;
  --sev-low:var(--green); --sev-info:var(--purple);
}
```

Severity becomes the primary organizing signal everywhere: a coloured **spine** (left
border), a filled badge, and a matching subtle glow — consistent between card and dossier.

### 3.4 Motion — restrained
Keep the existing live-`dot` pulse and HIR pulse. Add only: a hover *lift* on finding
cards (translateY-1px + border brighten), and a one-shot fade/slide-in for the detail
page masthead. Everything wrapped in `@media (prefers-reduced-motion: reduce)`.

**Signature element:** the per-finding **"dossier"** detail page (§6) — the one place we
spend boldness. The main dashboard stays quiet and disciplined around it.

---

## 4. New shell: left sidebar navigation

Replace the top `tab-nav` with a fixed **left rail**; the rest of the app moves into a
main column to its right.

```
┌──────────────┬─────────────────────────────────────────────────────────┐
│  [ LOGO ]     │  status: ● Live · target · scan/smith state   (sticky)  │
│  Pentest      │─────────────────────────────────────────────────────────│
│  Dashboard    │  ┌─── Command Center (steer / complete / triage) ────┐  │
│              │  │  target · phase · cov ▓▓▓░ · cost      Instruct… │  │
│ ▸ Findings  12│  └───────────────────────────────────────────────────┘  │
│   Topology    │  ┌─── HIR panel (only when scan paused) ─────────────┐  │
│   Components  │  └───────────────────────────────────────────────────┘  │
│   Coverage 73%│                                                          │
│   Skills      │   ── active tab content (Findings by default) ──        │
│   Activity    │   [ ALL 12 ][ CRIT 2 ][ HIGH 4 ]…   verify: …           │
│   Threat Model│   ┌───────────────────────────────────────────────┐    │
│   Metrics     │   │ finding card → opens detail in new tab ↗       │    │
│   Setup Gates⚠│   └───────────────────────────────────────────────┘    │
│   Logs        │                                                          │
│               │                                                          │
│  Cleanup ·    │                                                          │
│  Clear All    │                                                          │
└──────────────┴─────────────────────────────────────────────────────────┘
```

- **Rail** (~208 px): logo + brand at top, then the 10 nav items as a vertical list.
  Each item = icon glyph + label, with the active item marked by a green left-accent bar +
  raised background (`--bg-raised`). Nav items carry **live count/alert badges** driven by
  existing polled data: Findings count, Coverage %, and the `⚠` Setup-Gates alert that
  today hides in the Command Center. `Cleanup Tunnels` / `Clear All` move to the rail foot.
- **Main column**: a **sticky** slim status strip (the current `#status` line), then the
  Command Center, then the HIR panel (when active), then the active tab content.
- **Behaviour preserved**: `switchTab()` keeps its signature and pollers; only the button
  markup/container moves. `.tab-content.active` show/hide logic is unchanged.
- **Responsive**: < 1100 px the rail collapses to a 56 px **icon-only** rail (labels on
  hover-tooltip); < 720 px it becomes a top hamburger drawer. Content column is fluid.
- **A11y**: rail is a `<nav aria-label="Sections">` with `aria-current="page"` on the
  active item; full keyboard focus rings.

---

## 5. Findings list redesign (the default view)

Keep the filter bars (`#stats` severity + `#vstats` verification) — just restyle them as
quiet pill toggles. Rework the card into a **scannable summary row** and push the heavy
detail (full evidence, remediation diff, adjudication, trace, chain) to the new detail page.

```
┌─ sev spine ─────────────────────────────────────────────────────── ↗ ─┐
│ [CRITICAL]  ✓ CONFIRMED                                    14:32 · NEW │
│ SQL injection in /api/users?id                                         │
│ https://target/api/users   ·   sqlmap   ·   CVE-2024-1234             │
│ ⚠ Attacker can dump the full user table…            (2-line clamp)     │
│ [▶ Replay] [🔧 Fix] [⧉ GH Issue]                        Open detail ↗ │
└────────────────────────────────────────────────────────────────────────┘
```

- **Whole card is a click target** to `/finding/<id>` (`window.open(_,'_blank')`), and the
  **title is a real `<a target="_blank" rel="noopener">`** so native middle/⌘-click and
  right-click "open in new tab" work. A small `↗` affordance top-right signals it.
- Quick-action buttons (Replay/Fix/GH) stay on the card but call
  `event.stopPropagation()` so they don't trigger navigation; the inline evidence
  `<details>` is **removed from the card** (it lives on the detail page now) — this is what
  makes the list finally scannable.
- Description clamped to 2 lines; badges (severity, verification, triaged, false-positive)
  restyled to one consistent height/rhythm.
- `NEW` badge + fresh-id highlight behaviour preserved.

---

## 6. Signature: the Finding "Dossier" detail page  *(new browser tab)*

A standalone page that reads like a case file, reusing the exact same theme/tokens.

### 6.1 What it shows (maps every finding field the store can hold)
`id, timestamp, title, severity, target, tool_used, cve, description, evidence,
business_impact, verification_status, status, adjudication{reproducible, original/
revised_severity, rationale, artifact_id}, remediation{summary, effort, breaking_change,
diff, before, after, file/line/language, verification, references}, reproduction{command},
trace[{kind, file, line, scope, description}], escalation_leads[], poc_files[],
evidence_artifact_id`, plus any exploit **chain** that references this finding.

### 6.2 Layout

```
┌──────────────────────────────────────────────────────────────────────┐
│ [LOGO]                                                  ← back to list │
├─ sev spine ────────────────────────────────────────────────────────── │
│ [CRITICAL]  ✓ CONFIRMED   ⚖ Triaged                                   │
│ SQL injection in /api/users?id                                         │
│ target · tool · CVE · first seen 14:32                                 │
├───────────────────────────────────┬────────────────────────────────── │
│  NARRATIVE (main, ~2fr)           │  METADATA RAIL (~1fr)             │
│                                    │  Severity   CRITICAL              │
│  ⚠ Business impact                 │  Verify     ✓ confirmed_dynamic   │
│  Description (readable prose)      │  Target     …                     │
│                                    │  Tool       sqlmap                │
│  ── Data flow (trace) ──           │  CVE        CVE-2024-1234         │
│  ① entrypoint  file:line   ┐       │  Finding ID …  (copy)             │
│  │ propagation file:line   │ stepped│  First seen · Last update        │
│  ▼ sink        file:line   ┘ timeline│                                  │
│                                    │  ⚖ Senior review                  │
│  ── Evidence ──                    │   reproducible ✓ · sev orig→rev   │
│  <pre> … copy button …             │   rationale …                     │
│                                    │                                   │
│  ── Reproduction ──  [▶ copy cmd]  │  ▶ Reproduction command           │
│  ── Remediation ──  effort · diff  │  ⧉ GitHub issue  [copy]           │
│     before/after · verify · refs   │  PoC files: poc/…                 │
│                                    │                                   │
│  ── Exploit chain (if any) ──      │                                   │
│     server-rendered mermaid kill-  │                                   │
│     chain (MITRE-labelled)         │                                   │
└───────────────────────────────────┴────────────────────────────────── │
```

- **Masthead**: severity spine + big title (Chakra Petch), verification/triaged badges,
  compact meta line. One-shot fade/slide-in on load.
- **Trace → vertical stepped timeline**: entrypoint → propagation(s) → sink, each step a
  node with `file:line` in mono and a description. This is the white-box story made legible
  — a real differentiator over the current buried text.
- **Remediation**: reuse the existing `buildFixDetail` content (summary, effort badge,
  breaking-change flag, diff, before/after, verification, references) but as a first-class
  section, not a toggle.
- **Chain**: if a `chains[]` entry lists this finding in its steps, render its
  pre-rendered mermaid SVG (server already renders these in `/api/findings`).
- **Live**: polls `GET /api/findings/<id>` every 5 s (same cadence), so adjudication /
  remediation added mid-scan appear without a manual refresh. Falls back to a clean
  "finding not found / archived" state on 404.
- Same CSP, fonts, mermaid/marked includes, and **the same auth shim** as `index.html`.

---

## 7. Backend changes (small, additive)

1. **Page route** — `core/api_server/routes/dashboard_routes.py`:
   ```python
   @router.get("/finding/{finding_id}")
   async def finding_detail(request: Request, finding_id: str):
       return _api.templates.TemplateResponse(
           request, "finding.html", {"finding_id": finding_id})
   ```
   Ordering is safe (`/api/*` and `/static` don't collide). `finding_id` is echoed into a
   `data-finding-id` attribute (Jinja auto-escaped) so the JS knows what to fetch.

2. **JSON route** — `core/api_server/routes/findings_routes.py`:
   ```python
   @router.get("/api/findings/{finding_id}")
   async def api_finding(finding_id: str) -> JSONResponse:
       # look up one finding from _FINDINGS_FILE; 404 if missing;
       # attach any chains[] whose steps reference it; pre-render chain mermaid
       # via _render_mermaid_svgs (same as api_findings does today).
   ```
   Small payload instead of shipping the whole collection to the detail tab.

3. **New template** — `dashboard/tabs/` isn't right (those are includes); add a top-level
   `dashboard/finding.html` served as its own page. It reuses the same `<head>` block
   (CSP, favicons, fonts, mermaid, marked, `dashboard.css`).

4. **Share the security-critical core** — extract the **auth shim + `esc()` + sanitizer +
   mermaid/marked setup** out of `common.js` into a new `dashboard/js/shared.js`. Both
   `index.html` and `finding.html` load `shared.js` first. This avoids duplicating the
   bearer-token wrapper (a copy that drifts would be a security bug) and is what lets the
   new tab authenticate. `common.js` keeps everything dashboard-specific.

No change to `scan_tools`, session lifecycle, MCP tools, or the findings store schema.

---

## 8. Implementation phases (ordered, each independently shippable)

**Phase 0 — Design tokens (CSS only, zero behaviour change)**
Add the type scale, `--sp-*` spacing, and `--sev-*` tokens to `:root`; refactor existing
rules to consume them. Ship and eyeball — nothing else changes yet.

**Phase 1 — Left sidebar shell**
Move `.tab-nav` markup into a left `<nav>` rail; restructure `body` into rail + main grid;
make status strip sticky; add live count/alert badges (reuse polled data). `switchTab`
untouched. Add responsive collapse. This is the biggest visual change and is self-contained.

**Phase 2 — Findings list restyle + click-through**
Rework `cardHTML()`: summary row, clamped description, title as `target="_blank"` anchor,
whole-card click, `stopPropagation` on action buttons, remove inline evidence `<details>`.
Cards now link to `/finding/<id>` (page doesn't exist yet → 404 until Phase 3, so land 2+3
together or feature-flag the link).

**Phase 3 — Finding detail page** *(the headline feature)*
Extract `shared.js`; add `finding.html` + `finding.js` + a `.dossier-*` CSS block; add the
two backend routes. Wire trace timeline, remediation, adjudication, chain, live polling.

**Phase 4 — Chrome polish**
Restyle Command Center, HIR panel, filter pills, empty states, badges to the new scale/
spacing. Pure CSS. Verify HIR still pulses and all pollers paint.

**Verify each phase**: start the dashboard (`session(action='dashboard')` / `serve.py`),
run against an existing `findings.json`, click through, confirm the new tab authenticates
(token copied from opener), and that all 10 tabs + Command Center + HIR still work.

---

## 9. Files touched

| File | Change |
|---|---|
| `dashboard/css/dashboard.css` | tokens, type scale, sidebar, restyled cards, `.dossier-*` block |
| `dashboard/index.html` | sidebar rail markup, sticky status, load `shared.js` |
| `dashboard/js/common.js` | move auth/esc/sanitizer into `shared.js`; keep dashboard logic |
| `dashboard/js/shared.js` | **new** — auth shim, `esc`, sanitizer, mermaid/marked setup |
| `dashboard/js/findings.js` | summary-row card, click-through, drop inline evidence |
| `dashboard/finding.html` | **new** — standalone dossier page (reuses `<head>`) |
| `dashboard/js/finding.js` | **new** — fetch `/api/findings/<id>`, render dossier, poll |
| `core/api_server/routes/dashboard_routes.py` | **new route** `GET /finding/{id}` |
| `core/api_server/routes/findings_routes.py` | **new route** `GET /api/findings/{id}` |
| `docs/dashboard-api.md` | document the two new routes |

Nav badges may read existing `/api/coverage`, `/api/session`, `/api/findings` — no new
data plumbing required.

## 10. Risks, non-goals, open decision

**Risks & mitigations**
- *Auth in the new tab* — relies on `sessionStorage` copy-on-new-tab; guaranteed only when
  opened from a same-origin link (our case). Cold-loading `/finding/<id>` from a bookmark
  falls back to the existing key-prompt. Covered by loading `shared.js`.
- *CSP* — the detail page must carry the identical `<meta>` CSP; the mermaid CDN + inline
  handlers are already allow-listed. No new external origins introduced.
- *Sidebar regressions* — `switchTab` and `.tab-content.active` semantics are preserved;
  only the button container moves, keeping blast radius small.

**Non-goals** — no palette/logo change; no new scan features; no findings-schema change;
no touching MCP tools or session lifecycle; not auto-invoking `/report` or `/gh-export`.

**Open decision** — "new tab" is designed as a **new browser tab** (`/finding/<id>`). If
you meant an in-app tab instead, the same dossier markup slots into the tab system; tell me
and I'll adjust Phase 3 only.
