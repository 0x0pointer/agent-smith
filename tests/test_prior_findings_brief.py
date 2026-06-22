"""
Tests for the additive multi-run seed: _prior_findings_brief surfaces prior
findings for the same target (and excludes false_positives) at scan start.
"""
import core.findings
from mcp_server.session_tools import _prior_findings_brief


def _seed(findings_file, items):
    import json
    findings_file.write_text(json.dumps({"meta": {}, "findings": items, "diagrams": []}))


def test_empty_when_no_prior(findings_file):
    assert _prior_findings_brief("https://x.com") == ""


def test_lists_prior_for_same_target(findings_file):
    _seed(findings_file, [
        {"id": "1", "title": "Missing headers", "severity": "low", "target": "https://x.com"},
        {"id": "2", "title": "SQLi", "severity": "high", "target": "https://x.com/"},  # trailing slash
        {"id": "3", "title": "Other app", "severity": "high", "target": "https://other.com"},
    ])
    brief = _prior_findings_brief("https://x.com")
    assert "KNOWN FINDINGS" in brief
    assert "SQLi" in brief and "Missing headers" in brief
    assert "Other app" not in brief        # different target excluded
    # severity-ordered: HIGH before LOW
    assert brief.index("SQLi") < brief.index("Missing headers")


def test_excludes_false_positives(findings_file):
    _seed(findings_file, [
        {"id": "1", "title": "Was FP", "severity": "medium", "target": "https://x.com", "status": "false_positive"},
    ])
    assert _prior_findings_brief("https://x.com") == ""
