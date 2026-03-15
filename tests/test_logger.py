"""
Tests for core.logger — structured session logging helpers.
"""
import logging
import pytest
import core.logger


def _get_log_records(caplog, logger_name="pentest"):
    return [r for r in caplog.records if r.name == logger_name]


def test_tool_call_logs_info(caplog):
    with caplog.at_level(logging.INFO, logger="pentest"):
        core.logger.tool_call("nmap", {"target": "example.com"})
    records = _get_log_records(caplog)
    assert any("TOOL_CALL" in r.message and "nmap" in r.message for r in records)


def test_tool_call_serialises_kwargs(caplog):
    with caplog.at_level(logging.INFO, logger="pentest"):
        core.logger.tool_call("nuclei", {"target": "http://t.com", "templates": "cve"})
    assert any("http://t.com" in r.message for r in _get_log_records(caplog))


def test_tool_result_logs_info(caplog):
    with caplog.at_level(logging.INFO, logger="pentest"):
        core.logger.tool_result("httpx", "200 OK")
    records = _get_log_records(caplog)
    assert any("TOOL_RESULT" in r.message and "httpx" in r.message for r in records)


def test_tool_result_includes_output(caplog):
    with caplog.at_level(logging.INFO, logger="pentest"):
        core.logger.tool_result("nmap", "open port 80")
    assert any("open port 80" in r.message for r in _get_log_records(caplog))


def test_tool_result_verbose_logs_stdout(caplog):
    with caplog.at_level(logging.DEBUG, logger="pentest"):
        core.logger.tool_result_verbose("nmap", "raw stdout", "")
    assert any("RAW_STDOUT" in r.message for r in caplog.records if r.name == "pentest")


def test_tool_result_verbose_logs_stderr(caplog):
    with caplog.at_level(logging.DEBUG, logger="pentest"):
        core.logger.tool_result_verbose("nmap", "", "raw stderr")
    assert any("RAW_STDERR" in r.message for r in caplog.records if r.name == "pentest")


def test_tool_result_verbose_skips_empty_stdout(caplog):
    with caplog.at_level(logging.DEBUG, logger="pentest"):
        core.logger.tool_result_verbose("nmap", "", "")
    debug_records = [
        r for r in caplog.records
        if r.name == "pentest" and r.levelno == logging.DEBUG and "RAW_STDOUT" in r.message
    ]
    assert len(debug_records) == 0


def test_finding_logs_warning(caplog):
    with caplog.at_level(logging.WARNING, logger="pentest"):
        core.logger.finding("high", "SQL Injection", "http://example.com/login")
    records = _get_log_records(caplog)
    assert any(r.levelno == logging.WARNING for r in records)


def test_finding_includes_title_and_target(caplog):
    with caplog.at_level(logging.WARNING, logger="pentest"):
        core.logger.finding("critical", "RCE", "http://vuln.example.com")
    assert any("RCE" in r.message and "vuln.example.com" in r.message for r in _get_log_records(caplog))


def test_finding_severity_uppercased(caplog):
    with caplog.at_level(logging.WARNING, logger="pentest"):
        core.logger.finding("medium", "XSS", "http://t.com")
    assert any("MEDIUM" in r.message for r in _get_log_records(caplog))


def test_diagram_logs_info(caplog):
    with caplog.at_level(logging.INFO, logger="pentest"):
        core.logger.diagram("Network Topology")
    assert any("DIAGRAM" in r.message and "Network Topology" in r.message for r in _get_log_records(caplog))


def test_note_logs_info(caplog):
    with caplog.at_level(logging.INFO, logger="pentest"):
        core.logger.note("Starting reconnaissance phase")
    assert any("NOTE" in r.message and "reconnaissance" in r.message for r in _get_log_records(caplog))
