"""
Tests for mcp_server.report_tools — update_finding, delete_finding, and finding actions.
"""
import json
import pytest
from unittest.mock import AsyncMock, patch

from mcp_server.report_tools import (
    _do_update_finding, _do_delete_finding, _do_finding, _do_dashboard, report,
    _DASHBOARD_CANONICAL_PORT, _LEGACY_DASHBOARD_PORTS,
)


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


# ── _do_dashboard port normalization ────────────────────────────────────────
#
# The skills submodule (skills/pentester*.md) hard-codes
# `report(action="dashboard", data={"port": 5000})` from an older convention.
# Every other reference in this repo — CLAUDE.md, the launchd plist, the
# install scripts, the api_server.serve() default — uses 7777. Until the
# skills submodule catches up (separate-repo PR), _do_dashboard normalizes
# legacy ports to the canonical one so Smith's call lands on the port the
# operator's browser is already pointed at.

@pytest.mark.asyncio
async def test_dashboard_normalizes_legacy_5000_to_canonical_port():
    with patch("core.api_server.serve",
                new_callable=AsyncMock,
                return_value="http://localhost:7777") as mock_serve:
        result = await _do_dashboard({"port": 5000})
    mock_serve.assert_awaited_once_with(_DASHBOARD_CANONICAL_PORT)
    assert "http://localhost:7777" in result


@pytest.mark.asyncio
async def test_dashboard_respects_non_legacy_explicit_port():
    """Custom ports the operator explicitly wants (e.g. 8765 because 7777
    is taken) are passed through verbatim — we only intercept the documented
    legacy aliases."""
    with patch("core.api_server.serve",
                new_callable=AsyncMock,
                return_value="http://localhost:8765") as mock_serve:
        await _do_dashboard({"port": 8765})
    mock_serve.assert_awaited_once_with(8765)


@pytest.mark.asyncio
async def test_dashboard_default_is_canonical_port():
    """No port argument → canonical default. Matches api_server.serve()."""
    with patch("core.api_server.serve",
                new_callable=AsyncMock,
                return_value="http://localhost:7777") as mock_serve:
        await _do_dashboard({})
    mock_serve.assert_awaited_once_with(_DASHBOARD_CANONICAL_PORT)


@pytest.mark.asyncio
@pytest.mark.parametrize("legacy_port", sorted(_LEGACY_DASHBOARD_PORTS))
async def test_dashboard_every_documented_legacy_port_normalizes(legacy_port):
    """Lock down the legacy-port set: every value in _LEGACY_DASHBOARD_PORTS
    must remap to the canonical port. Adding a new alias to the set without
    a corresponding test is a maintenance trap."""
    with patch("core.api_server.serve",
                new_callable=AsyncMock,
                return_value=f"http://localhost:{_DASHBOARD_CANONICAL_PORT}") as mock_serve:
        await _do_dashboard({"port": legacy_port})
    mock_serve.assert_awaited_once_with(_DASHBOARD_CANONICAL_PORT)


@pytest.mark.asyncio
async def test_dashboard_handles_serve_failure_gracefully():
    """A serve() failure must not propagate — return the error string so
    Smith can surface it instead of a tool-call exception."""
    with patch("core.api_server.serve",
                new_callable=AsyncMock,
                side_effect=OSError("address already in use")):
        result = await _do_dashboard({"port": 7777})
    assert "Dashboard failed" in result
    assert "address already in use" in result
