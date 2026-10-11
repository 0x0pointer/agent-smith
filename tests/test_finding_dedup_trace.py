"""
Tests for the report_tools finding hygiene layer:
- cross-run dedup (same target+title+severity), with the false_positive carve-out
- trace[] validation gate on create and update
"""
import pytest

import core.findings
from mcp_server.report_tools import _do_finding, _do_update_finding


def _f(severity="low", title="Missing security headers", target="https://x.com", **kw):
    return {"severity": severity, "title": title, "target": target,
            "description": kw.get("description", "d"), "evidence": kw.get("evidence", "e"), **kw}


@pytest.mark.asyncio
async def test_first_finding_logged(findings_file):
    assert "Finding logged" in await _do_finding(_f())


@pytest.mark.asyncio
async def test_exact_duplicate_deduped(findings_file):
    await _do_finding(_f())
    res = await _do_finding(_f(title="missing SECURITY headers", target="https://x.com/"))  # normalised dup
    assert "DUPLICATE" in res


@pytest.mark.asyncio
async def test_higher_severity_is_escalation_not_dup(findings_file):
    await _do_finding(_f(severity="low"))
    res = await _do_finding(_f(severity="high"))
    assert "Finding logged" in res


@pytest.mark.asyncio
async def test_distinct_title_allowed(findings_file):
    await _do_finding(_f(title="Missing security headers"))
    res = await _do_finding(_f(title="Open redirect on /go"))
    assert "Finding logged" in res


@pytest.mark.asyncio
async def test_false_positive_does_not_suppress_refile(findings_file):
    entry = await core.findings.add_finding(
        title="Open redirect on /go", severity="low", target="https://x.com",
        description="d", evidence="e",
    )
    await core.findings.update_finding(entry["id"], status="false_positive")
    res = await _do_finding(_f(title="Open redirect on /go"))
    assert "Finding logged" in res  # re-discovery of a was-FP issue is allowed


@pytest.mark.asyncio
async def test_invalid_trace_rejected_on_create(findings_file):
    res = await _do_finding(_f(title="SQLi in id", severity="medium",
                               trace=[{"kind": "sink", "file": "a.py", "line": 1, "scope": "q", "description": "x"}]))
    assert "REJECTED" in res and "trace" in res


@pytest.mark.asyncio
async def test_valid_trace_stored(findings_file):
    res = await _do_finding(_f(title="SQLi in name", severity="medium", trace=[
        {"kind": "entrypoint", "file": "a.py", "line": 1, "scope": "h", "description": "in"},
        {"kind": "sink", "file": "a.py", "line": 9, "scope": "q", "description": "out"},
    ]))
    assert "Finding logged" in res
    stored = [f for f in core.findings._load()["findings"] if f["title"] == "SQLi in name"]
    assert stored and stored[0].get("trace")


@pytest.mark.asyncio
async def test_invalid_trace_rejected_on_update(findings_file):
    entry = await core.findings.add_finding(
        title="T", severity="low", target="t", description="d", evidence="e")
    res = await _do_update_finding({"id": entry["id"], "trace": [{"kind": "sink"}]})
    assert "REJECTED" in res


# ── list_findings + chain-aware dedup + non-blocking near-duplicate hint ──────
from mcp_server.report_tools import _do_list_findings  # noqa: E402


@pytest.mark.asyncio
async def test_list_findings_returns_ids_and_titles(findings_file):
    await _do_finding(_f(severity="critical", title="SQL injection in /transfer to_account"))
    await _do_finding(_f(severity="high", title="XSS in /transfer description"))
    out = _do_list_findings({})
    assert "SQL injection in /transfer" in out
    assert "XSS in /transfer description" in out
    # ids are surfaced for direct use in chain/update
    assert "report(action='chain')" in out


@pytest.mark.asyncio
async def test_list_findings_severity_and_query_filters(findings_file):
    await _do_finding(_f(severity="critical", title="SQL injection in /transfer"))
    await _do_finding(_f(severity="low", title="Missing security headers"))
    crit = _do_list_findings({"severity": "critical"})
    assert "SQL injection" in crit and "Missing security headers" not in crit
    q = _do_list_findings({"query": "security headers"})
    assert "Missing security headers" in q and "SQL injection" not in q


@pytest.mark.asyncio
async def test_list_findings_empty(findings_file):
    assert "No findings on record" in _do_list_findings({})


@pytest.mark.asyncio
async def test_dedup_message_is_chain_aware(findings_file):
    await _do_finding(_f(title="Wildcard CORS on all responses"))
    res = await _do_finding(_f(title="Wildcard CORS on all responses"))
    assert "DUPLICATE" in res
    assert "chain" in res.lower()           # tells the agent it can chain with the existing id
    assert "list_findings" in res           # and how to discover ids


@pytest.mark.asyncio
async def test_near_duplicate_hint_fires_but_does_not_suppress(findings_file):
    await _do_finding(_f(severity="critical", target="https://app",
                         title="AI chat endpoint leaks full system prompt via prompt injection"))
    res = await _do_finding(_f(severity="critical", target="https://app",
                               title="AI chat endpoint exposes full system prompt including database"))
    # filed (never auto-suppressed) AND flagged as a possible duplicate
    assert "Finding logged" in res
    assert "POSSIBLE DUPLICATE" in res


@pytest.mark.asyncio
async def test_distinct_finding_has_no_near_duplicate_hint(findings_file):
    await _do_finding(_f(severity="critical", target="https://app",
                         title="AI chat endpoint leaks full system prompt via prompt injection"))
    res = await _do_finding(_f(severity="high", target="https://app",
                               title="Open redirect on /go to attacker domain"))
    assert "Finding logged" in res
    assert "POSSIBLE DUPLICATE" not in res
