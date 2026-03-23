"""
Tests for core.findings — async findings/diagram store.
"""
import json
import pytest
import core.findings


@pytest.mark.asyncio
async def test_add_finding_returns_entry_with_id(findings_file):
    entry = await core.findings.add_finding(
        title="SQLi", severity="high", target="http://example.com",
        description="Login bypass", evidence="' OR 1=1--",
    )
    assert "id" in entry
    assert len(entry["id"]) == 36


@pytest.mark.asyncio
async def test_add_finding_persists_to_file(findings_file):
    await core.findings.add_finding(
        title="XSS", severity="medium", target="http://example.com/search",
        description="Reflected XSS", evidence="<script>alert(1)</script>",
    )
    data = json.loads(findings_file.read_text())
    assert len(data["findings"]) == 1
    assert data["findings"][0]["title"] == "XSS"


@pytest.mark.asyncio
async def test_add_finding_stores_all_fields(findings_file):
    entry = await core.findings.add_finding(
        title="CVE Test", severity="critical", target="http://t.com",
        description="desc", evidence="proof", tool_used="nuclei", cve="CVE-2024-1234",
    )
    assert entry["tool_used"] == "nuclei"
    assert entry["cve"] == "CVE-2024-1234"
    assert entry["severity"] == "critical"


@pytest.mark.asyncio
async def test_add_finding_multiple_accumulates(findings_file):
    await core.findings.add_finding(
        title="A", severity="low", target="t", description="d", evidence="e"
    )
    await core.findings.add_finding(
        title="B", severity="low", target="t", description="d", evidence="e"
    )
    data = json.loads(findings_file.read_text())
    assert len(data["findings"]) == 2


@pytest.mark.asyncio
async def test_add_finding_default_tool_and_cve(findings_file):
    entry = await core.findings.add_finding(
        title="T", severity="low", target="t", description="d", evidence="e"
    )
    assert entry["tool_used"] == ""
    assert entry["cve"] == ""


@pytest.mark.asyncio
async def test_add_diagram_persists_mermaid(findings_file):
    entry = await core.findings.add_diagram(
        title="Topology", mermaid="flowchart TD\n  A --> B"
    )
    data = json.loads(findings_file.read_text())
    assert len(data["diagrams"]) == 1
    assert data["diagrams"][0]["mermaid"] == "flowchart TD\n  A --> B"
    assert entry["title"] == "Topology"


@pytest.mark.asyncio
async def test_add_diagram_returns_entry_with_id(findings_file):
    entry = await core.findings.add_diagram(title="T", mermaid="flowchart TD")
    assert "id" in entry
    assert len(entry["id"]) == 36


@pytest.mark.asyncio
async def test_update_finding_attaches_gh_issue(findings_file):
    entry = await core.findings.add_finding(
        title="SQLi", severity="high", target="t", description="d", evidence="e"
    )
    result = await core.findings.update_finding(entry["id"], gh_issue="## GitHub Issue\nFix this.")
    assert result is True
    data = json.loads(findings_file.read_text())
    assert data["findings"][0]["gh_issue"] == "## GitHub Issue\nFix this."


@pytest.mark.asyncio
async def test_update_finding_returns_false_for_missing_id(findings_file):
    result = await core.findings.update_finding("nonexistent-uuid", gh_issue="issue")
    assert result is False


@pytest.mark.asyncio
async def test_add_finding_with_reproduction(findings_file):
    repro = {"type": "http", "command": "curl http://target/?q=1' OR 1=1--", "expected": "returns all rows"}
    entry = await core.findings.add_finding(
        title="SQLi", severity="critical", target="t", description="d", evidence="e",
        reproduction=repro,
    )
    assert entry["reproduction"] == repro
    data = json.loads(findings_file.read_text())
    assert data["findings"][0]["reproduction"]["command"] == repro["command"]


@pytest.mark.asyncio
async def test_update_finding_remediation(findings_file):
    entry = await core.findings.add_finding(
        title="XSS", severity="high", target="t", description="d", evidence="e"
    )
    remediation = {"summary": "Add output encoding", "effort": "low", "fix_type": "code_patch"}
    result = await core.findings.update_finding(entry["id"], remediation=remediation)
    assert result is True
    data = json.loads(findings_file.read_text())
    assert data["findings"][0]["remediation"]["summary"] == "Add output encoding"


@pytest.mark.asyncio
async def test_update_finding_no_valid_fields(findings_file):
    entry = await core.findings.add_finding(
        title="T", severity="low", target="t", description="d", evidence="e"
    )
    result = await core.findings.update_finding(entry["id"], invalid_field="nope")
    assert result is False


@pytest.mark.asyncio
async def test_load_creates_empty_structure_when_file_missing(findings_file):
    """File doesn't exist yet — _load() should return an empty valid structure."""
    assert not findings_file.exists()
    entry = await core.findings.add_finding(
        title="T", severity="low", target="t", description="d", evidence="e"
    )
    # If _load() failed we'd get an exception; success means it handled missing file
    assert entry["title"] == "T"


@pytest.mark.asyncio
async def test_load_recovers_from_corrupted_json(findings_file):
    findings_file.write_text("not valid json {{")
    # Should not raise — _load() silently discards corrupt data
    entry = await core.findings.add_finding(
        title="T", severity="low", target="t", description="d", evidence="e"
    )
    assert entry["title"] == "T"


@pytest.mark.asyncio
async def test_findings_and_diagrams_coexist(findings_file):
    await core.findings.add_finding(
        title="Bug", severity="high", target="t", description="d", evidence="e"
    )
    await core.findings.add_diagram(title="Map", mermaid="flowchart TD")
    data = json.loads(findings_file.read_text())
    assert len(data["findings"]) == 1
    assert len(data["diagrams"]) == 1


# ---------------------------------------------------------------------------
# escalation_leads
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_add_finding_with_escalation_leads(findings_file):
    leads = [
        {"lead": "Crack admin hash", "status": "pending"},
        {"lead": "Try --os-shell for RCE", "status": "pending"},
    ]
    entry = await core.findings.add_finding(
        title="SQLi", severity="critical", target="t",
        description="d", evidence="e", escalation_leads=leads,
    )
    assert "escalation_leads" in entry
    assert len(entry["escalation_leads"]) == 2
    assert entry["escalation_leads"][0]["status"] == "pending"


@pytest.mark.asyncio
async def test_update_finding_escalation_leads(findings_file):
    leads = [{"lead": "Crack hash", "status": "pending"}]
    entry = await core.findings.add_finding(
        title="SQLi", severity="high", target="t",
        description="d", evidence="e", escalation_leads=leads,
    )
    updated_leads = [{"lead": "Crack hash", "status": "done", "result": "Password: admin123"}]
    ok = await core.findings.update_finding(entry["id"], escalation_leads=updated_leads)
    assert ok
    data = json.loads(findings_file.read_text())
    f = data["findings"][0]
    assert f["escalation_leads"][0]["status"] == "done"
    assert "admin123" in f["escalation_leads"][0]["result"]


@pytest.mark.asyncio
async def test_add_finding_without_escalation_leads(findings_file):
    entry = await core.findings.add_finding(
        title="XSS", severity="medium", target="t",
        description="d", evidence="e",
    )
    assert "escalation_leads" not in entry
