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
    tab_end = markup.index("</div>\n\n<!-- New Scan dialog")
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


def test_landing_page_gates_other_tabs_until_a_scan_is_selected():
    markup = (REPO_ROOT / "dashboard" / "tabs" / "sessions.html").read_text(encoding="utf-8")
    script = (REPO_ROOT / "dashboard" / "js" / "sessions.js").read_text(encoding="utf-8")
    css = (REPO_ROOT / "dashboard" / "css" / "dashboard.css").read_text(encoding="utf-8")

    # Inline home for the start form on the landing page.
    assert 'id="start-run-inline-slot"' in markup
    assert "function _placeStartRunForm" in script
    # Gating is driven by one body class and enforced in switchTab.
    assert "'scan-gated'" in script
    assert "if (_cpGated && name !== 'sessions')" in script
    assert "body.scan-gated .main > *:not(#scan-bar):not(#tab-sessions):not(dialog)" in css
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


def test_start_form_keeps_target_and_depth_visible():
    """Target and depth are the two required choices; only scope is optional."""
    markup = _read("tabs", "sessions.html")
    advanced = markup[markup.index('<details class="scan-advanced">'):markup.index("</details>")]

    assert 'id="start-run-target"' not in advanced
    assert 'id="start-run-depth"' not in advanced
    assert markup.index('id="start-run-depth"') < markup.index('<details class="scan-advanced">')
    assert 'id="start-run-scope"' in advanced
    assert 'id="start-run-out-of-scope"' in advanced


def test_rail_has_four_primary_pages_and_tabs_switch_by_id():
    index = _read("index.html")
    common = _read("js", "common.js")
    primary = index[index.index('id="rail-items-primary"'):index.index('data-group="more"')]

    assert [t for t in ("findings", "coverage", "activity", "sessions") if f'id="tab-btn-{t}"' in primary] == \
        ["findings", "coverage", "activity", "sessions"]
    assert primary.count('class="tab-btn') == 4
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
