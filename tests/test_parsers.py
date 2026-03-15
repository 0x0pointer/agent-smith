"""
Tests for tools.semgrep._parse and tools.trufflehog._parse.
"""
import json
import pytest

from tools.semgrep import _parse as semgrep_parse
from tools.trufflehog import _parse as trufflehog_parse


# ---------------------------------------------------------------------------
# semgrep parser
# ---------------------------------------------------------------------------

def _semgrep_result(check_id="rule", path="app.py", line=42,
                    severity="ERROR", message="SQL injection", lines="cursor.execute(q)"):
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": line},
        "extra": {
            "severity": severity,
            "message": message,
            "lines": lines,
        },
    }


def _semgrep_output(results):
    return json.dumps({"results": results})


def test_semgrep_parse_returns_list():
    findings = semgrep_parse(_semgrep_output([]), "")
    assert isinstance(findings, list)


def test_semgrep_parse_empty_results():
    assert semgrep_parse(_semgrep_output([]), "") == []


def test_semgrep_parse_single_finding():
    findings = semgrep_parse(_semgrep_output([_semgrep_result()]), "")
    assert len(findings) == 1


def test_semgrep_parse_extracts_rule_id():
    findings = semgrep_parse(_semgrep_output([_semgrep_result(check_id="python.sqli.sqli")]), "")
    assert findings[0]["rule_id"] == "python.sqli.sqli"


def test_semgrep_parse_extracts_path():
    findings = semgrep_parse(_semgrep_output([_semgrep_result(path="src/db.py")]), "")
    assert findings[0]["path"] == "src/db.py"


def test_semgrep_parse_extracts_line_number():
    findings = semgrep_parse(_semgrep_output([_semgrep_result(line=99)]), "")
    assert findings[0]["line"] == 99


def test_semgrep_parse_maps_error_to_high():
    findings = semgrep_parse(_semgrep_output([_semgrep_result(severity="ERROR")]), "")
    assert findings[0]["severity"] == "high"


def test_semgrep_parse_maps_warning_to_medium():
    findings = semgrep_parse(_semgrep_output([_semgrep_result(severity="WARNING")]), "")
    assert findings[0]["severity"] == "medium"


def test_semgrep_parse_maps_info_to_info():
    findings = semgrep_parse(_semgrep_output([_semgrep_result(severity="INFO")]), "")
    assert findings[0]["severity"] == "info"


def test_semgrep_parse_unknown_severity_defaults_to_info():
    findings = semgrep_parse(_semgrep_output([_semgrep_result(severity="UNKNOWN")]), "")
    assert findings[0]["severity"] == "info"


def test_semgrep_parse_extracts_message():
    findings = semgrep_parse(_semgrep_output([_semgrep_result(message="Use parameterised queries")]), "")
    assert findings[0]["message"] == "Use parameterised queries"


def test_semgrep_parse_extracts_code():
    findings = semgrep_parse(_semgrep_output([_semgrep_result(lines="db.execute(user_input)")]), "")
    assert findings[0]["code"] == "db.execute(user_input)"


def test_semgrep_parse_invalid_json_returns_empty():
    findings = semgrep_parse("not valid json }{", "")
    assert findings == []


def test_semgrep_parse_multiple_findings():
    results = [_semgrep_result(check_id=f"rule.{i}") for i in range(5)]
    findings = semgrep_parse(_semgrep_output(results), "")
    assert len(findings) == 5


# ---------------------------------------------------------------------------
# trufflehog parser
# ---------------------------------------------------------------------------

def _th_line(detector="AWS", file_path="/app/.env", line=3,
             raw="AKIAIOSFODNN7EXAMPLE_full_key_here", verified=True):
    return json.dumps({
        "DetectorName": detector,
        "SourceMetadata": {
            "Data": {
                "Filesystem": {
                    "file": file_path,
                    "line": line,
                }
            }
        },
        "Raw": raw,
        "Verified": verified,
    })


def test_trufflehog_parse_returns_list():
    findings = trufflehog_parse("", "")
    assert isinstance(findings, list)


def test_trufflehog_parse_empty_input():
    assert trufflehog_parse("", "") == []


def test_trufflehog_parse_single_finding():
    findings = trufflehog_parse(_th_line(), "")
    assert len(findings) == 1


def test_trufflehog_parse_extracts_detector():
    findings = trufflehog_parse(_th_line(detector="GitHub"), "")
    assert findings[0]["detector"] == "GitHub"


def test_trufflehog_parse_extracts_file():
    findings = trufflehog_parse(_th_line(file_path="/repo/secrets.env"), "")
    assert findings[0]["file"] == "/repo/secrets.env"


def test_trufflehog_parse_extracts_line():
    findings = trufflehog_parse(_th_line(line=17), "")
    assert findings[0]["line"] == 17


def test_trufflehog_parse_extracts_verified():
    findings = trufflehog_parse(_th_line(verified=False), "")
    assert findings[0]["verified"] is False


def test_trufflehog_parse_truncates_raw_to_80_chars():
    long_secret = "A" * 200
    findings = trufflehog_parse(_th_line(raw=long_secret), "")
    assert len(findings[0]["raw"]) == 80


def test_trufflehog_parse_short_raw_kept_as_is():
    short_raw = "short_key"
    findings = trufflehog_parse(_th_line(raw=short_raw), "")
    assert findings[0]["raw"] == short_raw


def test_trufflehog_parse_skips_invalid_json_lines():
    stdout = "valid json missing\nnot json at all\n" + _th_line()
    findings = trufflehog_parse(stdout, "")
    assert len(findings) == 1


def test_trufflehog_parse_multiple_findings():
    lines = "\n".join(_th_line(detector=f"D{i}") for i in range(4))
    findings = trufflehog_parse(lines, "")
    assert len(findings) == 4


def test_trufflehog_parse_skips_blank_lines():
    stdout = "\n\n" + _th_line() + "\n\n"
    findings = trufflehog_parse(stdout, "")
    assert len(findings) == 1
