"""
Tests for mcp_server.report_tools — update_finding, delete_finding, and finding actions.
"""
import json
import pytest
from unittest.mock import AsyncMock, patch

from mcp_server.report_tools import (
    _do_update_finding, _do_delete_finding, _do_finding, _do_dashboard, _do_chain, report,
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


@pytest.mark.asyncio
async def test_adjudication_reproducible_requires_existing_artifact(findings_file, tmp_path, monkeypatch):
    """A reproducible=true verdict is rejected unless its artifact_id exists on disk."""
    import core.findings
    import mcp_server.scan_engine.artifacts as artifacts
    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.mkdir()
    monkeypatch.setattr(artifacts, "_ARTIFACTS_DIR", artifacts_dir)

    entry = await core.findings.add_finding(
        title="Blind SQLi", severity="high", target="t", description="d", evidence="e"
    )
    fid = entry["id"]

    # (a) reproducible=true, no artifact_id → rejected, not stored.
    res = await _do_update_finding({
        "id": fid, "adjudication": {"reproducible": True, "rationale": "it works"},
    })
    assert "REJECTED" in res and "no artifact_id was provided" in res
    stored = next(f for f in core.findings._load()["findings"] if f["id"] == fid)
    assert "adjudication" not in stored

    # (b) reproducible=true, artifact_id that does not exist → rejected.
    res = await _do_update_finding({
        "id": fid,
        "adjudication": {"reproducible": True, "rationale": "it works", "artifact_id": "ghost_1"},
    })
    assert "REJECTED" in res and "does not exist on disk" in res

    # (c) artifact exists on disk → accepted and stored.
    (artifacts_dir / "http_request_1_a.txt").write_text("HTTP/1.1 200 ... proof", encoding="utf-8")
    res = await _do_update_finding({
        "id": fid,
        "adjudication": {"reproducible": True, "rationale": "it works", "artifact_id": "http_request_1_a"},
    })
    assert "Finding updated" in res
    stored = next(f for f in core.findings._load()["findings"] if f["id"] == fid)
    assert stored["adjudication"]["artifact_id"] == "http_request_1_a"

    # (d) reproducible=false needs no artifact.
    res = await _do_update_finding({
        "id": fid, "adjudication": {"reproducible": False, "rationale": "could not reproduce"},
    })
    assert "Finding updated" in res


# ── _do_delete_finding ───────────────────────────────────────────────────────

# ── _do_chain (exploit-chain correlation) ────────────────────────────────────

@pytest.mark.asyncio
async def test_chain_requires_steps(findings_file):
    res = await _do_chain({"name": "empty"})
    assert "Missing/empty 'steps'" in res


@pytest.mark.asyncio
async def test_chain_rejects_unproven_transition(findings_file, tmp_path, monkeypatch):
    import mcp_server.scan_engine.artifacts as artifacts
    adir = tmp_path / "artifacts"
    adir.mkdir()
    monkeypatch.setattr(artifacts, "_ARTIFACTS_DIR", adir)
    res = await _do_chain({
        "name": "redir->oauth->ato",
        "steps": [
            {"from_finding_id": "a", "to_finding_id": "b",
             "transition_artifact_id": "ghost", "mitre_technique": "T1190"},
        ],
    })
    assert "REJECTED" in res and "unproven transition" in res


@pytest.mark.asyncio
async def test_chain_accepts_proven_transition_and_persists(findings_file, tmp_path, monkeypatch):
    import core.findings
    import mcp_server.scan_engine.artifacts as artifacts
    adir = tmp_path / "artifacts"
    adir.mkdir()
    monkeypatch.setattr(artifacts, "_ARTIFACTS_DIR", adir)
    (adir / "http_request_1_a.txt").write_text("code= captured at collector", encoding="utf-8")

    f1 = await core.findings.add_finding(title="Open redirect", severity="low", target="t", description="d", evidence="e")
    f2 = await core.findings.add_finding(title="OAuth code theft", severity="medium", target="t", description="d", evidence="e")

    res = await _do_chain({
        "name": "redir->oauth->ato",
        "steps": [
            {"from_finding_id": f1["id"], "to_finding_id": f2["id"],
             "transition_artifact_id": "http_request_1_a", "mitre_technique": "T1539"},
        ],
        "terminal_impact": "account takeover",
        "combined_severity": "Critical",
    })
    assert "Exploit chain saved" in res

    data = core.findings._load()
    assert len(data["chains"]) == 1
    chain = data["chains"][0]
    assert chain["combined_severity"] == "critical"
    assert chain["mermaid"].startswith("graph LR")
    assert "T1539" in chain["mermaid"]
    # Also rendered as a diagram for the dashboard.
    assert any("Exploit chain" in d.get("title", "") for d in data["diagrams"])


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
    # Only the exception type name is exposed — the raw message ("address
    # already in use") is intentionally NOT echoed back per S5145 (log
    # injection defense — see test_dashboard_does_not_log_user_controlled_data).
    assert "OSError" in result


@pytest.mark.asyncio
async def test_dashboard_does_not_log_user_controlled_data():
    """S5145 (sonar pythonsecurity): log lines that interpolate values
    derived from a tool call MUST NOT echo the raw value into the audit
    trail. Otherwise a malicious payload like

        report(action='dashboard', data={'port': '5000\\nFAKE LOG: pwned'})

    would let Smith forge dashboard.log entries by embedding control chars.
    Defense: _safe_port() coerces every input to a validated int (or the
    canonical default), so anything that reaches the log is type int and
    formats deterministically."""
    from mcp_server.report_tools import _safe_port

    # Newline-injection attempt → falls back to default, no echo of payload
    assert _safe_port("5000\nFAKE", 7777) == 7777
    # Non-numeric string → fallback
    assert _safe_port("not-a-port", 7777) == 7777
    # Negative / out-of-range → fallback
    assert _safe_port(-1, 7777) == 7777
    assert _safe_port(99999, 7777) == 7777
    # Valid integers pass through
    assert _safe_port(8000, 7777) == 8000
    assert _safe_port("8000", 7777) == 8000
    # None / missing → fallback
    assert _safe_port(None, 7777) == 7777


@pytest.mark.asyncio
async def test_dashboard_serves_canonical_on_malformed_port_input():
    """End-to-end S5145 defense: a malformed port reaches _do_dashboard via
    the data dict; _safe_port catches it and the dashboard serves on the
    canonical port without echoing the malformed value anywhere."""
    captured_args: list = []
    async def _capture_serve(p):
        captured_args.append(p)
        return "http://localhost:7777"
    with patch("core.api_server.serve", side_effect=_capture_serve):
        result = await _do_dashboard({"port": "5000\nINJECTED"})
    assert captured_args == [_DASHBOARD_CANONICAL_PORT]
    # The injected payload must NOT appear anywhere in what we return
    assert "INJECTED" not in result
    assert "\n" not in result
