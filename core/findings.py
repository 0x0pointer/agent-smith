"""
Findings store
==============
Thread-safe read/write of findings.json.

Schema
------
{
  "meta":     { "created": "<ISO>", "target": "" },
  "findings": [ { id, timestamp, title, severity, target,
                   description, evidence, tool_used, cve,
                   status?, reproduction?, gh_issue?, remediation? } ],
  "diagrams": [ { id, timestamp, title, mermaid } ],
  "archived": [ ... same shape as findings, moved here on delete ... ]
}

Optional fields set via update_finding():
  severity:         "critical" | "high" | "medium" | "low" | "info"
  title:            updated title string
  description:      updated description string
  evidence:         updated evidence string
  status:           "confirmed" | "false_positive" | "draft"
  reproduction:     { type, command, expected, verified }
  gh_issue:         "<markdown block>"
  remediation:      { summary, fix_type, diff, before, after, file, line,
                      language, effort, breaking_change, references, verification }
  escalation_leads: [ { lead, status (pending|done|dismissed), result? } ]

Used exclusively by mcp_server.py; not a Tool registry entry.
"""
from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

FINDINGS_FILE = Path(__file__).parent.parent / "findings.json"

_lock = asyncio.Lock()


# ---------------------------------------------------------------------------
# Internal I/O
# ---------------------------------------------------------------------------

def _load() -> dict:
    if FINDINGS_FILE.exists():
        try:
            return json.loads(FINDINGS_FILE.read_text())
        except Exception:
            pass
    return {
        "meta":     {"created": datetime.now(timezone.utc).isoformat(), "target": ""},
        "findings": [],
        "diagrams": [],
    }


def _save(data: dict) -> None:
    FINDINGS_FILE.write_text(json.dumps(data, indent=2))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def add_finding(
    title:       str,
    severity:    str,
    target:      str,
    description: str,
    evidence:    str,
    tool_used:   str = "",
    cve:         str = "",
    reproduction: dict | None = None,
    escalation_leads: list[dict] | None = None,
    business_impact: str = "",
) -> dict:
    """Append a vulnerability finding. Returns the stored entry."""
    entry = {
        "id":          str(uuid.uuid4()),
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "title":       title,
        "severity":    severity,
        "target":      target,
        "description": description,
        "evidence":    evidence,
        "tool_used":   tool_used,
        "cve":         cve,
    }
    if business_impact:
        entry["business_impact"] = business_impact
    if reproduction:
        entry["reproduction"] = reproduction
    if escalation_leads:
        entry["escalation_leads"] = escalation_leads
    async with _lock:
        data = _load()
        data["findings"].append(entry)
        _save(data)
    return entry


_UPDATABLE_FIELDS = {
    "severity", "title", "description", "evidence", "status",
    "gh_issue", "remediation", "reproduction", "escalation_leads", "business_impact",
    "poc_files",
}


async def update_finding(finding_id: str, **fields) -> bool:
    """Update fields on an existing finding by id.

    Accepted fields: severity, title, description, evidence, status,
    gh_issue, remediation, reproduction, escalation_leads.
    Returns True if the finding was found and updated, False otherwise.
    """
    updates = {k: v for k, v in fields.items() if k in _UPDATABLE_FIELDS and v is not None}
    if not updates:
        return False
    async with _lock:
        data = _load()
        for entry in data["findings"]:
            if entry.get("id") == finding_id:
                entry.update(updates)
                _save(data)
                return True
    return False


async def link_poc(finding_id: str, filepath: str) -> bool:
    """Append a PoC file path to finding.poc_files[]. Creates the list if absent.

    Returns True if the finding was found and updated, False otherwise.
    """
    async with _lock:
        data = _load()
        for entry in data["findings"]:
            if entry.get("id") == finding_id:
                if "poc_files" not in entry:
                    entry["poc_files"] = []
                if filepath not in entry["poc_files"]:
                    entry["poc_files"].append(filepath)
                _save(data)
                return True
    return False


async def delete_finding(finding_id: str) -> bool:
    """Move a finding from findings[] to archived[].

    Returns True if the finding was found and archived, False otherwise.
    """
    async with _lock:
        data = _load()
        if "archived" not in data:
            data["archived"] = []
        for i, entry in enumerate(data["findings"]):
            if entry.get("id") == finding_id:
                entry["archived_at"] = datetime.now(timezone.utc).isoformat()
                data["archived"].append(entry)
                data["findings"].pop(i)
                _save(data)
                return True
    return False


async def add_diagram(title: str, mermaid: str) -> dict:
    """Append a Mermaid diagram. Returns the stored entry."""
    entry = {
        "id":        str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "title":     title,
        "mermaid":   mermaid,
    }
    async with _lock:
        data = _load()
        data["diagrams"].append(entry)
        _save(data)
    return entry
