"""
Tests for mcp_server.report_tools — update_finding, delete_finding, and finding actions.
"""
import json
import pytest
from unittest.mock import AsyncMock, patch

from mcp_server.report_tools import _do_update_finding, _do_delete_finding, _do_finding, report


# ── _do_update_finding ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_update_finding_missing_id():
    result = await _do_update_finding({})
    assert "Missing required field: id" in result


@pytest.mark.asyncio
async def test_update_finding_no_fields():
    result = await _do_update_finding({"id": "abc123"})
    assert "No fields to update" in result


@pytest.mark.asyncio
async def test_update_finding_success(findings_file):
    import core.findings
    entry = await core.findings.add_finding(
        title="T", severity="low", target="t", description="d", evidence="e"
    )
    result = await _do_update_finding({
        "id": entry["id"], "severity": "critical", "status": "confirmed"
    })
    assert "Finding updated" in result
    assert "severity" in result
    assert "status" in result


@pytest.mark.asyncio
async def test_update_finding_not_found(findings_file):
    result = await _do_update_finding({"id": "nonexistent", "severity": "high"})
    assert "Finding not found" in result


# ── _do_delete_finding ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_delete_finding_missing_id():
    result = await _do_delete_finding({})
    assert "Missing required field: id" in result


@pytest.mark.asyncio
async def test_delete_finding_success(findings_file):
    import core.findings
    entry = await core.findings.add_finding(
        title="FP", severity="low", target="t", description="d", evidence="e"
    )
    result = await _do_delete_finding({"id": entry["id"]})
    assert "Finding archived" in result
    data = json.loads(findings_file.read_text())
    assert len(data["findings"]) == 0
    assert len(data["archived"]) == 1


@pytest.mark.asyncio
async def test_delete_finding_not_found(findings_file):
    result = await _do_delete_finding({"id": "nonexistent"})
    assert "Finding not found" in result


# ── report() dispatcher ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_report_update_finding_action(findings_file):
    import core.findings
    entry = await core.findings.add_finding(
        title="T", severity="low", target="t", description="d", evidence="e"
    )
    result = await report("update_finding", {"id": entry["id"], "status": "confirmed"})
    assert "Finding updated" in result


@pytest.mark.asyncio
async def test_report_delete_finding_action(findings_file):
    import core.findings
    entry = await core.findings.add_finding(
        title="T", severity="low", target="t", description="d", evidence="e"
    )
    result = await report("delete_finding", {"id": entry["id"]})
    assert "Finding archived" in result


@pytest.mark.asyncio
async def test_report_unknown_action():
    result = await report("bogus_action", {})
    assert "Unknown action" in result
    assert "update_finding" in result
    assert "delete_finding" in result


# ── _do_finding — business_impact ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_do_finding_passes_business_impact(findings_file):
    import core.findings
    result = await _do_finding({
        "title": "SQLi in /search",
        "severity": "high",
        "target": "https://example.com/search",
        "description": "Blind time-based injection",
        "evidence": "sleep(5) triggered",
        "tool_used": "sqlmap",
        "business_impact": "Full database read access, including PII.",
    })
    assert "Finding logged" in result
    data = json.loads(findings_file.read_text())
    f = data["findings"][0]
    assert f["business_impact"] == "Full database read access, including PII."


@pytest.mark.asyncio
async def test_do_finding_without_business_impact_omits_field(findings_file):
    import core.findings
    await _do_finding({
        "title": "XSS",
        "severity": "medium",
        "target": "https://example.com",
        "description": "Reflected XSS",
        "evidence": "<script>alert(1)</script>",
    })
    data = json.loads(findings_file.read_text())
    assert "business_impact" not in data["findings"][0]


@pytest.mark.asyncio
async def test_do_finding_rejects_invalid_severity(findings_file):
    result = await _do_finding({
        "title": "T", "severity": "extreme", "target": "t",
        "description": "d", "evidence": "e",
    })
    assert "Invalid severity" in result


@pytest.mark.asyncio
async def test_report_finding_action_with_business_impact(findings_file):
    result = await report("finding", {
        "title": "IDOR",
        "severity": "high",
        "target": "https://api.example.com/users/123",
        "description": "Unauthenticated access to other user profiles",
        "evidence": "HTTP 200 returned profile of user 456",
        "business_impact": "Any user can read all other user profiles without authentication.",
    })
    assert "Finding logged" in result
    data = json.loads(findings_file.read_text())
    assert data["findings"][0]["business_impact"] == "Any user can read all other user profiles without authentication."
