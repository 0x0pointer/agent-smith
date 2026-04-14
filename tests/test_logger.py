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


def test_skill_start_logs_info(caplog):
    with caplog.at_level(logging.INFO, logger="pentest"):
        core.logger.skill_start("pentester", reason="user requested full pentest")
    records = _get_log_records(caplog)
    assert any(r.levelno == logging.INFO for r in records)


def test_skill_start_uses_skill_start_tag(caplog):
    with caplog.at_level(logging.INFO, logger="pentest"):
        core.logger.skill_start("pentester", reason="initial skill")
    assert any("SKILL_START" in r.message for r in _get_log_records(caplog))


def test_skill_start_includes_skill_name(caplog):
    with caplog.at_level(logging.INFO, logger="pentest"):
        core.logger.skill_start("ai-redteam", reason="LLM target detected")
    assert any("ai-redteam" in r.message for r in _get_log_records(caplog))


def test_skill_start_includes_reason(caplog):
    with caplog.at_level(logging.INFO, logger="pentest"):
        core.logger.skill_start("osint", reason="passive recon phase")
    assert any("passive recon phase" in r.message for r in _get_log_records(caplog))


def test_skill_start_no_skill_start_tag_when_chaining(caplog):
    with caplog.at_level(logging.INFO, logger="pentest"):
        core.logger.skill_start("web-exploit", reason="endpoints found", chained_from="pentester")
    assert not any("SKILL_START" in r.message for r in _get_log_records(caplog))


def test_skill_chain_uses_skill_chain_tag(caplog):
    with caplog.at_level(logging.INFO, logger="pentest"):
        core.logger.skill_start("web-exploit", reason="endpoints found", chained_from="pentester")
    assert any("SKILL_CHAIN" in r.message for r in _get_log_records(caplog))


def test_skill_chain_includes_chained_from(caplog):
    with caplog.at_level(logging.INFO, logger="pentest"):
        core.logger.skill_start("credential-audit", reason="login form found", chained_from="web-exploit")
    assert any("web-exploit" in r.message for r in _get_log_records(caplog))


def test_skill_chain_includes_reason(caplog):
    with caplog.at_level(logging.INFO, logger="pentest"):
        core.logger.skill_start("post-exploit", reason="shell obtained", chained_from="metasploit")
    assert any("shell obtained" in r.message for r in _get_log_records(caplog))
