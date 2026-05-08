"""
Tests for core.quick_log — append-only JSONL event feed.
"""
import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import core.quick_log
from core.quick_log import QuickLog


@pytest.fixture(autouse=True)
def isolate_quick_log_lock(monkeypatch):
    monkeypatch.setattr(core.quick_log.quick_log, "_lock", asyncio.Lock())


@pytest.fixture
def log(tmp_path):
    return QuickLog(tmp_path / "quick_log.json")


# ---------------------------------------------------------------------------
# append
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_append_writes_jsonl_line_with_auto_ts(log):
    await log.append({"type": "TOOL", "name": "nmap"})
    lines = log._path.read_text().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["type"] == "TOOL"
    assert "ts" in entry


@pytest.mark.asyncio
async def test_append_uses_explicit_ts_when_provided(log):
    ts = "2024-01-01T00:00:00+00:00"
    await log.append({"type": "TOOL", "name": "nmap", "ts": ts})
    entry = json.loads(log._path.read_text().splitlines()[0])
    assert entry["ts"] == ts


@pytest.mark.asyncio
async def test_append_multiple_writes_multiple_lines(log):
    await log.append({"type": "TOOL", "name": "nmap"})
    await log.append({"type": "TOOL", "name": "httpx"})
    lines = log._path.read_text().splitlines()
    assert len(lines) == 2


# ---------------------------------------------------------------------------
# read_all
# ---------------------------------------------------------------------------

def test_read_all_returns_empty_list_when_file_missing(tmp_path):
    ql = QuickLog(tmp_path / "nonexistent.json")
    assert ql.read_all() == []


@pytest.mark.asyncio
async def test_read_all_returns_parsed_dicts_in_order(log):
    await log.append({"type": "TOOL", "name": "nmap", "ts": "2024-01-01T00:01:00+00:00"})
    await log.append({"type": "TOOL", "name": "httpx", "ts": "2024-01-01T00:02:00+00:00"})
    entries = log.read_all()
    assert len(entries) == 2
    assert entries[0]["name"] == "nmap"
    assert entries[1]["name"] == "httpx"


def test_read_all_skips_malformed_lines(tmp_path):
    path = tmp_path / "quick_log.json"
    path.write_text(
        '{"type": "TOOL", "name": "nmap"}\n'
        "NOT VALID JSON\n"
        '{"type": "SKILL", "name": "pentester"}\n'
    )
    ql = QuickLog(path)
    entries = ql.read_all()
    assert len(entries) == 2
    assert entries[0]["name"] == "nmap"
    assert entries[1]["name"] == "pentester"


# ---------------------------------------------------------------------------
# read_since
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_read_since_returns_only_entries_after_ts(log):
    await log.append({"type": "TOOL", "name": "nmap", "ts": "2024-01-01T00:01:00+00:00"})
    await log.append({"type": "TOOL", "name": "httpx", "ts": "2024-01-01T00:03:00+00:00"})
    results = log.read_since("2024-01-01T00:02:00+00:00")
    assert len(results) == 1
    assert results[0]["name"] == "httpx"


@pytest.mark.asyncio
async def test_read_since_returns_empty_when_ts_after_all_entries(log):
    await log.append({"type": "TOOL", "name": "nmap", "ts": "2024-01-01T00:01:00+00:00"})
    results = log.read_since("2025-01-01T00:00:00+00:00")
    assert results == []


# ---------------------------------------------------------------------------
# summarize — basic
# ---------------------------------------------------------------------------

def test_summarize_returns_no_activity_on_empty_log(log):
    assert log.summarize() == "No activity logged yet."


@pytest.mark.asyncio
async def test_summarize_includes_skills_line(log):
    await log.append({"type": "SKILL", "name": "pentester", "ts": _recent_ts()})
    summary = log.summarize()
    assert "Skills invoked: pentester" in summary


@pytest.mark.asyncio
async def test_summarize_includes_tools_run_last_15min(log):
    await log.append({"type": "TOOL", "name": "nmap", "ts": _recent_ts()})
    summary = log.summarize()
    assert "Tools run (last 15min)" in summary
    assert "nmap" in summary


@pytest.mark.asyncio
async def test_summarize_shows_none_for_tools_when_all_older_than_15min(log):
    old_ts = (datetime.now(timezone.utc) - timedelta(minutes=20)).isoformat()
    await log.append({"type": "TOOL", "name": "nmap", "ts": old_ts})
    summary = log.summarize()
    assert "Tools run (last 15min): none" in summary


@pytest.mark.asyncio
async def test_summarize_includes_endpoint_count_from_spider(log):
    await log.append({"type": "SPIDER", "name": "spider", "endpoints_found": 42, "mode": "active", "ts": _recent_ts()})
    summary = log.summarize()
    assert "Endpoints found: 42" in summary


@pytest.mark.asyncio
async def test_summarize_includes_coverage_stats(log):
    await log.append({
        "type": "COVERAGE",
        "pending": 10,
        "tested": 5,
        "registered": 15,
        "ts": _recent_ts(),
    })
    summary = log.summarize()
    assert "15 endpoints" in summary
    assert "5 tested" in summary
    assert "10 pending" in summary
    assert "33%" in summary


@pytest.mark.asyncio
async def test_summarize_emits_coverage_stall_warning(log):
    old_ts = (datetime.now(timezone.utc) - timedelta(minutes=35)).isoformat()
    await log.append({
        "type": "COVERAGE",
        "pending": 8,
        "tested": 2,
        "registered": 10,
        "ts": old_ts,
    })
    summary = log.summarize()
    assert "WARNING" in summary
    assert "8 cells still pending" in summary


@pytest.mark.asyncio
async def test_summarize_includes_finding_counts_by_severity(log):
    await log.append({"type": "FINDING", "severity": "critical", "ts": _recent_ts()})
    await log.append({"type": "FINDING", "severity": "high", "ts": _recent_ts()})
    await log.append({"type": "FINDING", "severity": "high", "ts": _recent_ts()})
    await log.append({"type": "FINDING", "severity": "medium", "ts": _recent_ts()})
    summary = log.summarize()
    assert "1 critical" in summary
    assert "2 high" in summary
    assert "1 medium" in summary


@pytest.mark.asyncio
async def test_summarize_includes_last_tool_call_elapsed(log):
    ts = (datetime.now(timezone.utc) - timedelta(minutes=3)).isoformat()
    await log.append({"type": "TOOL", "name": "nmap", "ts": ts})
    summary = log.summarize()
    assert "Last tool call:" in summary
    assert "nmap" in summary


# ---------------------------------------------------------------------------
# summarize — session.json integration
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_summarize_reads_pending_gates_from_session_json(tmp_path, monkeypatch):
    monkeypatch.setattr(core.quick_log, "_REPO_ROOT", tmp_path)
    triggered = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    session_data = {
        "target": "http://example.com",
        "gates": [
            {
                "id": "gate-recon",
                "status": "pending",
                "triggered_at": triggered,
                "required_skills": ["osint", "nmap"],
            }
        ],
    }
    (tmp_path / "session.json").write_text(json.dumps(session_data))
    log = QuickLog(tmp_path / "quick_log.json")
    await log.append({"type": "TOOL", "name": "nmap", "ts": _recent_ts()})
    summary = log.summarize()
    assert "gate-recon" in summary
    assert "osint, nmap" in summary


@pytest.mark.asyncio
async def test_summarize_includes_declared_target_from_session_json(tmp_path, monkeypatch):
    monkeypatch.setattr(core.quick_log, "_REPO_ROOT", tmp_path)
    (tmp_path / "session.json").write_text(json.dumps({"target": "http://target.example.com"}))
    log = QuickLog(tmp_path / "quick_log.json")
    await log.append({"type": "TOOL", "name": "nmap", "ts": _recent_ts()})
    summary = log.summarize()
    assert "Declared target: http://target.example.com" in summary


@pytest.mark.asyncio
async def test_summarize_detects_off_scope_targets(tmp_path, monkeypatch):
    monkeypatch.setattr(core.quick_log, "_REPO_ROOT", tmp_path)
    (tmp_path / "session.json").write_text(json.dumps({"target": "http://example.com"}))
    log = QuickLog(tmp_path / "quick_log.json")
    await log.append({"type": "TOOL", "name": "nmap", "target": "http://other.com", "ts": _recent_ts()})
    summary = log.summarize()
    assert "off-scope" in summary
    assert "http://other.com" in summary


@pytest.mark.asyncio
async def test_summarize_includes_poc_file_count(tmp_path, monkeypatch):
    monkeypatch.setattr(core.quick_log, "_REPO_ROOT", tmp_path)
    pocs_dir = tmp_path / "pocs"
    pocs_dir.mkdir()
    (pocs_dir / "sqli.http").write_text("GET / HTTP/1.1\r\n")
    (pocs_dir / "xss.http").write_text("GET / HTTP/1.1\r\n")
    log = QuickLog(tmp_path / "quick_log.json")
    await log.append({"type": "FINDING", "severity": "high", "ts": _recent_ts()})
    summary = log.summarize()
    assert "PoC files saved: 2" in summary
    assert "1 high/critical findings" in summary


@pytest.mark.asyncio
async def test_summarize_handles_missing_session_json_gracefully(tmp_path, monkeypatch):
    monkeypatch.setattr(core.quick_log, "_REPO_ROOT", tmp_path)
    log = QuickLog(tmp_path / "quick_log.json")
    await log.append({"type": "TOOL", "name": "nmap", "ts": _recent_ts()})
    summary = log.summarize()
    assert isinstance(summary, str)
    assert "nmap" in summary


@pytest.mark.asyncio
async def test_summarize_handles_missing_pocs_dir_gracefully(tmp_path, monkeypatch):
    monkeypatch.setattr(core.quick_log, "_REPO_ROOT", tmp_path)
    log = QuickLog(tmp_path / "quick_log.json")
    await log.append({"type": "FINDING", "severity": "critical", "ts": _recent_ts()})
    summary = log.summarize()
    assert "PoC files saved: 0" in summary


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _recent_ts() -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
