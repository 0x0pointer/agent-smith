"""
Findings store
==============
Thread-safe read/write of findings.json.

Schema
------
{
  "meta":     { "created": "<ISO>", "target": "" },
  "findings": [ { id, timestamp, title, severity, target,
                   description, evidence, tool_used, cve } ],
  "diagrams": [ { id, timestamp, title, mermaid } ]
}

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
    async with _lock:
        data = _load()
        data["findings"].append(entry)
        _save(data)
    return entry


async def update_finding(finding_id: str, gh_issue: str) -> bool:
    """Attach a GitHub issue markdown block to an existing finding by id.
    Returns True if the finding was found and updated, False otherwise."""
    async with _lock:
        data = _load()
        for entry in data["findings"]:
            if entry.get("id") == finding_id:
                entry["gh_issue"] = gh_issue
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
