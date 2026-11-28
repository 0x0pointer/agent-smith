from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def test_sessions_tab_uses_runs_api_for_platform_run_management():
    script = (REPO_ROOT / "dashboard" / "js" / "sessions.js").read_text(encoding="utf-8")
    markup = (REPO_ROOT / "dashboard" / "tabs" / "sessions.html").read_text(encoding="utf-8")

    assert "/api/runs" in script
    assert "start-run-form" in markup
    assert "runs-output" in markup
    assert "selected-run-token" in script
    assert "/api/sessions" not in script


def test_sessions_tab_can_select_persisted_runs_without_cached_localstorage_tokens():
    script = (REPO_ROOT / "dashboard" / "js" / "sessions.js").read_text(encoding="utf-8")

    assert "api/runs/' + encodeURIComponent(runId) + '/token" in script
    assert "disabled" not in script


def test_new_scan_is_reachable_from_every_tab():
    index = (REPO_ROOT / "dashboard" / "index.html").read_text(encoding="utf-8")
    markup = (REPO_ROOT / "dashboard" / "tabs" / "sessions.html").read_text(encoding="utf-8")
    script = (REPO_ROOT / "dashboard" / "js" / "sessions.js").read_text(encoding="utf-8")

    # The rail button lives in the shell, not inside a tab.
    assert 'onclick="openNewScanDialog()"' in index
    assert "function openNewScanDialog" in script

    # The dialog must sit OUTSIDE the tab container: a <dialog> inside a hidden
    # (display:none) tab cannot render, so the rail button would do nothing.
    tab_end = markup.index("</div>\n\n<!-- New Scan wizard")
    assert markup.index('<dialog id="start-run-dialog"') > tab_end
    assert markup.index('id="start-run-form"') > markup.index('<dialog id="start-run-dialog"')


def test_scan_list_has_filter_controls_wired_to_the_script():
    markup = (REPO_ROOT / "dashboard" / "tabs" / "sessions.html").read_text(encoding="utf-8")
    script = (REPO_ROOT / "dashboard" / "js" / "sessions.js").read_text(encoding="utf-8")

    for control in ("runs-filter-q", "runs-filter-depth", "runs-filter-sort",
                    "runs-filter-clear", "runs-status-chips"):
        assert f'id="{control}"' in markup
        assert f"'{control}'" in script
    assert "function _applyRunFilters" in script


def test_run_ids_are_not_interpolated_into_inline_handlers():
    script = (REPO_ROOT / "dashboard" / "js" / "sessions.js").read_text(encoding="utf-8")

    assert "onclick=\"selectRun(" not in script
    assert "data-run-id" in script


def test_scan_bar_offers_switcher_and_new_scan_above_every_tab():
    index = (REPO_ROOT / "dashboard" / "index.html").read_text(encoding="utf-8")
    script = (REPO_ROOT / "dashboard" / "js" / "sessions.js").read_text(encoding="utf-8")

    bar = index[index.index('<div id="scan-bar"'):index.index('<div id="status">')]
    assert 'id="scan-switcher"' in bar
    assert 'onclick="openNewScanDialog()"' in bar
    # The bar must come before every tab partial so it is visible on all of them.
    assert index.index('<div id="scan-bar"') < index.index("{% include 'tabs/findings.html' %}")
    assert "function _renderScanSwitcher" in script


def test_scan_pages_are_gated_until_a_scan_is_open_but_platform_pages_are_not():
    script = (REPO_ROOT / "dashboard" / "js" / "sessions.js").read_text(encoding="utf-8")
    css = (REPO_ROOT / "dashboard" / "css" / "dashboard.css").read_text(encoding="utf-8")
    common = (REPO_ROOT / "dashboard" / "js" / "common.js").read_text(encoding="utf-8")

    # Gating is driven by one body class and enforced in switchTab; the pages
    # about all scans stay reachable, the pages of one scan fall back to Home.
    assert "'scan-gated'" in script
    assert "const _PLATFORM_TABS = ['home', 'sessions', 'all-findings', 'apps', 'knowledge'];" in script
    assert "if (_cpGated && !_isPlatformTab(name))" in script
    assert "body.scan-gated .main > *:not(#scan-bar):not(.tab-platform):not(dialog)" in css
    assert 'body.scan-gated .rail-section[data-group="primary"]' in css
    # Every platform page carries the class the gate exempts.
    for tab in ("home", "sessions", "all-findings", "apps", "knowledge"):
        markup = (REPO_ROOT / "dashboard" / "tabs" / f"{tab}.html").read_text(encoding="utf-8")
        assert f'<div id="tab-{tab}" class="tab-content tab-platform">' in markup
        assert f"'{tab}'" in common[common.index("const TAB_NAMES"):common.index("function switchTab")]
    # A platform page hides the open scan's command panel.
    assert "'on-platform-tab'" in common and "body.on-platform-tab #cmd-center" in css
    # Only platform mode gates; classic single-run dashboards stay open.
    assert "/api/control-plane" in script
    assert "if (!_platformMode()) {" in script


def test_stylesheet_stays_on_the_design_tokens():
    """Guard the consolidation pass: one type scale, one radius scale, no web fonts."""
    import re

    css = (REPO_ROOT / "dashboard" / "css" / "dashboard.css").read_text(encoding="utf-8")
    body = css[css.index("* { box-sizing"):]

    # The page CSP blocks remote fonts and the dashboard must work air-gapped.
    assert "fonts.googleapis.com" not in css
    # Every font size outside :root is a token (font-size: 0 hides icon-only labels).
    sizes = {m.strip() for m in re.findall(r"font-size:\s*([^;}]+)", body)}
    # `em` sizes are relative to a tokenised parent (inline code, sub/superscript).
    def on_scale(size: str) -> bool:
        return size.startswith("var(--fs-") or size == "0" or re.fullmatch(r"\d*\.?\d+em", size) is not None

    assert all(on_scale(s) for s in sizes), sorted(s for s in sizes if not on_scale(s))
    # Radii are tokens or a circle.
    radii = {m.strip() for m in re.findall(r"border-radius:\s*([^;}]+)", body)}
    assert all(r.startswith("var(--r-") or r == "50%" for r in radii), sorted(radii)


def test_command_panel_composer_is_collapsible():
    index = (REPO_ROOT / "dashboard" / "index.html").read_text(encoding="utf-8")
    common = (REPO_ROOT / "dashboard" / "js" / "common.js").read_text(encoding="utf-8")

    assert '<div id="cmd-composer" class="cmd-composer" hidden>' in index
    assert 'aria-controls="cmd-composer"' in index
    assert "function toggleCmdComposer" in common
    # An intervention must force the reply box open.
    assert "toggleCmdComposer(true);" in common


def _read(*parts: str) -> str:
    return (REPO_ROOT / "dashboard").joinpath(*parts).read_text(encoding="utf-8")


def test_new_scan_wizard_asks_for_target_then_depth_and_keeps_the_rest_optional():
    """Four short steps: only the target is required, depth has a safe default,
    and nothing starts until the operator confirms they are authorized."""
    markup = _read("tabs", "sessions.html")
    platform = _read("js", "platform.js")
    script = _read("js", "sessions.js")

    def step(n):
        start = markup.index(f'<section class="wiz-step" data-step="{n}"')
        return markup[start:markup.index("</section>", start)]

    assert 'id="start-run-target"' in step(1) and "required" in step(1)
    assert 'id="start-run-depth" name="depth" type="hidden" value="standard"' in step(2)
    assert [d for d in ("recon", "standard", "thorough", "danger") if f'data-depth="{d}"' in step(2)] == \
        ["recon", "standard", "thorough", "danger"]
    for optional in ("start-run-codebase", "start-run-notes", "start-run-scope", "start-run-out-of-scope",
                     "start-run-time-limit", "start-run-cost-limit", "start-run-source"):
        assert f'id="{optional}"' in step(3)
    assert 'id="wiz-review"' in step(4) and 'id="wiz-authorized"' in step(4)

    # The request is only sent from the last step with the box ticked.
    assert "function wizardCanSubmit" in platform and "function wizardReset" in platform
    assert "if (typeof wizardCanSubmit === 'function' && !wizardCanSubmit()) return;" in script
    for field in ("body.codebase", "body.notes", "body.max_time_minutes", "body.max_cost_usd"):
        assert field in script


def test_rail_has_platform_pages_then_the_open_scans_pages_and_tabs_switch_by_id():
    index = _read("index.html")
    common = _read("js", "common.js")
    platform = index[index.index('id="rail-items-platform"'):index.index('id="rail-scan"')]
    primary = index[index.index('id="rail-items-primary"'):index.index('data-group="more"')]

    # Pages about all scans come first...
    assert [t for t in ("home", "sessions", "all-findings", "apps", "knowledge") if f'id="tab-btn-{t}"' in platform] == \
        ["home", "sessions", "all-findings", "apps", "knowledge"]
    assert platform.count('class="tab-btn') == 5
    # ...then the three main pages of the open scan.
    assert [t for t in ("findings", "coverage", "activity") if f'id="tab-btn-{t}"' in primary] == \
        ["findings", "coverage", "activity"]
    assert primary.count('class="tab-btn') == 3
    assert index.index('id="rail-items-platform"') < index.index('id="rail-scan-name"') < index.index('id="rail-items-primary"')
    # Every tab partial still has a rail button (nothing became unreachable).
    for tab in ("topology", "components", "ai-redteam", "skills", "world-model", "threat-model",
                "metrics", "setup-gates", "logs", "session-log"):
        assert f'id="tab-btn-{tab}"' in index
    # Highlighting must not depend on DOM order now that the rail was reordered.
    assert "b.id === 'tab-btn-' + name" in common
    assert "TAB_NAMES[i] === name" not in common


def test_destructive_actions_use_the_named_confirmation_dialog():
    common = _read("js", "common.js")
    findings = _read("js", "findings.js")
    ux = _read("js", "ux.js")

    assert '<dialog id="confirm-dialog"' in _read("index.html")
    assert "function confirmAction" in ux and "function scanDisplayName" in ux
    for src in (common, findings):
        assert "await confirmAction({" in src
        assert "scanDisplayName()" in src
    # The click-twice pattern and the suppressible native dialog are gone.
    assert "Click again" not in common
    assert "confirm('Clear ALL" not in findings


def test_findings_summary_is_counts_by_severity_with_grouping_and_export():
    findings = _read("js", "findings.js")
    markup = _read("tabs", "findings.html")
    ux = _read("js", "ux.js")

    summary = findings[findings.index("function renderFindingsSummary"):findings.index("// Grouping + ordering")]
    assert "findings.length" in summary and "SEV_GROUPS.map" in summary
    assert "Worst issue" not in findings and "Fix first" not in findings
    for control in ("findings-group", "findings-sort", "findings-export-btn", "findings-legend"):
        assert f'id="{control}"' in markup
    assert "function findingEndpoint" in findings
    for fn in ("buildFindingsMarkdown", "buildFindingsCsv", "exportFindings", "copyScanLink"):
        assert f"function {fn}" in ux


def test_needs_you_inbox_and_progress_are_wired():
    index = _read("index.html")
    ux = _read("js", "ux.js")

    assert 'id="needs-you-btn"' in index and 'id="needs-you-panel"' in index
    assert 'id="scan-steps"' in index and 'id="scan-now"' in index
    assert "function _needsYouItems" in ux and "function renderScanProgress" in ux
    assert index.index("/static/js/ux.js") < index.index("/static/js/main.js")


def test_empty_states_do_not_tell_the_operator_which_tool_call_to_make():
    import re

    blobs = [p.read_text(encoding="utf-8") for p in (REPO_ROOT / "dashboard" / "tabs").glob("*.html")]
    blobs += [p.read_text(encoding="utf-8") for p in (REPO_ROOT / "dashboard" / "js").glob("*.js")]
    placeholders = re.findall(r'empty-placeholder"[^>]*>([^<]{0,160})', "\n".join(blobs))

    assert placeholders
    for text in placeholders:
        assert "action=" not in text and "scan(tool" not in text and "report_diagram" not in text, text


def test_remembered_scan_tokens_are_verified_before_use():
    script = _read("js", "sessions.js")
    token_fn = script[script.index("async function _tokenForRun"):script.index("// Scope the dashboard to one scan")]

    assert "_probeToken(cached)" in token_fn
    assert "_forgetRunToken(runId)" in token_fn


def test_platform_pages_read_cross_scan_data_with_the_operator_token():
    platform = _read("js", "platform.js")
    index = _read("index.html")

    for endpoint in ("/api/platform/overview", "/api/platform/findings"):
        assert endpoint in platform
    assert "/api/knowledge" in _read("js", "knowledge.js")
    # The page's default token may be scoped to the open scan.
    assert "_headersFor(_operatorToken())" in platform
    assert index.index("/static/js/sessions.js") < index.index("/static/js/platform.js") \
        < index.index("/static/js/knowledge.js") < index.index("/static/js/main.js")
    for include in ("tabs/home.html", "tabs/all-findings.html", "tabs/apps.html", "tabs/knowledge.html"):
        assert "{% include '" + include + "' %}" in index


def test_platform_pages_never_put_scan_or_note_text_into_markup_or_handlers_unescaped():
    import re

    platform = _read("js", "platform.js")
    knowledge = _read("js", "knowledge.js")

    # IDs travel in data-* attributes and clicks are delegated.
    assert "onclick=" not in platform and "onclick=" not in knowledge
    assert "data-pf-action" in platform and "document.addEventListener('click', _pfOnClick)" in platform
    assert "page.addEventListener('click', _kbOnClick)" in knowledge
    # Vault notes and AI answers are rendered as Markdown only through the sanitizer.
    assert "sanitizeHtml(marked.parse(String(text || '')))" in knowledge
    assert knowledge.count("marked.parse(") == 1
    assert not re.search(r"innerHTML\s*=\s*marked", platform + knowledge)
    platform = platform + knowledge
    # Every interpolation into a template literal's markup is escaped or a known-safe helper.
    unsafe = [m for m in re.findall(r"\$\{([^}]+)\}", platform)
              if re.match(r"\s*(f|r|a|h|s|n|run|x)\.(title|target|run_target|app|path|heading|text|name|url|cve|summary)\s*$", m)]
    assert unsafe == []


def test_all_findings_export_neutralises_spreadsheet_formulas():
    platform = _read("js", "platform.js")
    cell = platform[platform.index("function _pfCsvCell"):platform.index("function _pfExportFindings")]

    assert "/^[=+\\-@\\t\\r]/" in cell and '"\'" + s' in cell


def test_knowledge_page_is_a_workspace_with_notes_reader_map_and_brain():
    markup = _read("tabs", "knowledge.html")
    knowledge = _read("js", "knowledge.js")

    # Three columns: notes, reader/map, brain.
    for part in ('class="kb-col kb-nav"', 'class="kb-col kb-center"', 'class="kb-col kb-brain"'):
        assert part in markup
    assert markup.index("kb-col kb-nav") < markup.index("kb-col kb-center") < markup.index("kb-col kb-brain")
    for control in ("kb-tree", "kb-q", "kb-view", "kb-map-canvas", "kb-chat", "kb-ask-q", "kb-ask-note"):
        assert f'id="{control}"' in markup
    assert 'data-kb-view="read"' in markup and 'data-kb-view="map"' in markup
    for endpoint in ("'/notes'", "'/graph'", "'/ask'", "'/note?path='", "'/search?"):
        assert endpoint in knowledge
    # Answers cite their notes, and citations open the note they point at.
    assert "function _kbLinkCitations" in knowledge and "function _kbLinkNotes" in knowledge
    # A citation or note link is built with DOM calls, never by string concatenation into markup.
    cite = knowledge[knowledge.index("function _kbLinkCitations"):knowledge.index("function _kbSourcesHtml")]
    assert "innerHTML" not in cite and "document.createElement('button')" in cite


def test_wizard_takes_a_source_code_folder_through_a_server_side_folder_picker():
    """A web page cannot read a folder's path from the browser's own dialog, so
    the wizard browses folders on the platform's machine and checks the choice."""
    markup = _read("tabs", "sessions.html")
    platform = _read("js", "platform.js")

    start = markup.index('<section class="wiz-step" data-step="3"')
    details = markup[start:markup.index("</section>", start)]
    # The folder is the first thing asked in Details, with Browse next to it.
    assert details.index('id="start-run-codebase"') < details.index('id="start-run-notes"')
    for control in ("wiz-code-browse", "wiz-code-status", "wiz-browser", "wiz-browser-list", "wiz-browser-use"):
        assert f'id="{control}"' in details
    assert 'type="file"' not in details
    assert "/api/fs/folders" in platform
    # Leaving Details checks the folder; a bad one keeps the operator on the step.
    nxt = platform[platform.index("async function wizardNext"):platform.index("function wizardBack")]
    assert "if (!(await _wizCheckCode())) return;" in nxt
    assert "['Source code', _wizVal('start-run-codebase')" in platform
