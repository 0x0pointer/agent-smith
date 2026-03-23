"""
Tests for tools.semgrep._parse, tools.trufflehog._parse, and tools.nuclei._parse.
"""
import json
import pytest

from tools.semgrep import _parse as semgrep_parse
from tools.trufflehog import _parse as trufflehog_parse
from tools.nuclei import _parse as nuclei_parse


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


# ---------------------------------------------------------------------------
# nuclei parser
# ---------------------------------------------------------------------------

def _nuclei_line(template_id="cve-2021-44228", severity="critical",
                 name="Log4Shell", matched_at="http://target.com:8080",
                 type_="http", host="target.com", cve_id="CVE-2021-44228"):
    obj = {
        "template-id": template_id,
        "info": {
            "severity": severity,
            "name": name,
            "classification": {"cve-id": cve_id} if cve_id else {},
        },
        "matched-at": matched_at,
        "type": type_,
        "host": host,
        # Verbose fields that should be stripped by the parser
        "template-url": "https://github.com/nuclei-templates/...",
        "curl-command": "curl -X GET http://target.com:8080",
        "matcher-name": "log4j-detect",
        "request": "GET / HTTP/1.1\r\nHost: target.com\r\n...",
        "response": "HTTP/1.1 200 OK\r\n...",
    }
    return json.dumps(obj)


def test_nuclei_parse_returns_list():
    assert isinstance(nuclei_parse(_nuclei_line(), ""), list)


def test_nuclei_parse_empty_input():
    assert nuclei_parse("", "") == []


def test_nuclei_parse_single_finding():
    findings = nuclei_parse(_nuclei_line(), "")
    assert len(findings) == 1


def test_nuclei_parse_extracts_template():
    findings = nuclei_parse(_nuclei_line(template_id="cve-2021-44228"), "")
    assert findings[0]["template"] == "cve-2021-44228"


def test_nuclei_parse_extracts_severity():
    findings = nuclei_parse(_nuclei_line(severity="high"), "")
    assert findings[0]["severity"] == "high"


def test_nuclei_parse_extracts_name():
    findings = nuclei_parse(_nuclei_line(name="Log4Shell RCE"), "")
    assert findings[0]["name"] == "Log4Shell RCE"


def test_nuclei_parse_extracts_matched():
    findings = nuclei_parse(_nuclei_line(matched_at="http://x.com/api"), "")
    assert findings[0]["matched"] == "http://x.com/api"


def test_nuclei_parse_extracts_host():
    findings = nuclei_parse(_nuclei_line(host="10.0.0.1"), "")
    assert findings[0]["host"] == "10.0.0.1"


def test_nuclei_parse_extracts_cve():
    findings = nuclei_parse(_nuclei_line(cve_id="CVE-2021-44228"), "")
    assert findings[0]["cve"] == "CVE-2021-44228"


def test_nuclei_parse_strips_verbose_fields():
    findings = nuclei_parse(_nuclei_line(), "")
    keys = set(findings[0].keys())
    assert "curl-command" not in keys
    assert "request" not in keys
    assert "response" not in keys
    assert "template-url" not in keys


def test_nuclei_parse_skips_invalid_json():
    stdout = "not json\n" + _nuclei_line() + "\ngarbage"
    findings = nuclei_parse(stdout, "")
    assert len(findings) == 1


def test_nuclei_parse_multiple_findings():
    lines = "\n".join(_nuclei_line(template_id=f"cve-{i}") for i in range(5))
    findings = nuclei_parse(lines, "")
    assert len(findings) == 5


def test_nuclei_parse_skips_blank_lines():
    stdout = "\n\n" + _nuclei_line() + "\n\n"
    findings = nuclei_parse(stdout, "")
    assert len(findings) == 1


def test_nuclei_parse_no_classification():
    findings = nuclei_parse(_nuclei_line(cve_id=None), "")
    assert findings[0]["cve"] == ""
