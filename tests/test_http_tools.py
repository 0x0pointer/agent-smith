"""http() tool — the skill-work recording hook, with aiohttp mocked (no network).

Regression coverage for the HTTP-only-skill stall: every other scanner tool
(kali/scan/nuclei/redteam) records itself as work by the active skill via
_record → scan_session.add_tool_called, but the http tool used to skip that hook.
A skill whose assessment is carried out purely over raw HTTP — business-logic
(financial/BOLA abuse), much of web-exploit — could therefore never satisfy its
skill-chain gate, so the gate stayed pending and the scan looped on it.
"""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import core.session
import mcp_server.http_tools as http_tools


def _mock_resp(status=200, body="{}", headers=None):
    resp = MagicMock()
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    resp.status = status
    resp.headers = headers or {"Content-Type": "application/json"}
    resp.text = AsyncMock(return_value=body)
    return resp


def _mock_session(resp):
    session = MagicMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    # _do_request uses `async with session.request(...) as resp`
    session.request = MagicMock(return_value=resp)
    return session


async def _fire_http(url, method="POST", body='{"amount": -500}'):
    resp = _mock_resp(status=200, body='{"new_balance": 3500}')
    session = _mock_session(resp)
    import aiohttp
    with patch.object(aiohttp, "ClientSession", return_value=session):
        return await http_tools.http(action="request", url=url, method=method, body=body)


@pytest.mark.asyncio
async def test_http_request_marks_active_skill_worked_and_clears_gate():
    core.session.start("http://target.example:30081")
    core.session.trigger_gate("financial_coverage", "transfer endpoint", ["business-logic"])
    core.session.set_skill("business-logic")
    # Before the probe: skill has done no attributable work, gate pending.
    assert core.session.skill_worked("business-logic") is False

    await _fire_http("http://target.example:30081/transfer")

    # The HTTP probe is business-logic work → skill_worked True AND the gate reconciled
    # immediately (no complete() call in between).
    assert core.session.skill_worked("business-logic") is True
    assert all(g["status"] == "satisfied"
               for g in core.session.get()["gates"] if g["id"] == "financial_coverage")


@pytest.mark.asyncio
async def test_http_request_records_tool_under_active_skill():
    core.session.start("http://target.example:30081")
    core.session.set_skill("business-logic")
    await _fire_http("http://target.example:30081/transfer")
    hist = {e["skill"]: e for e in core.session.get()["skill_history"]}
    assert hist["business-logic"]["worked"] is True
    assert "http" in (hist["business-logic"].get("tools") or [])


@pytest.mark.asyncio
async def test_http_request_without_active_skill_is_safe():
    """No active skill (e.g. ad-hoc recon http) — recording is a no-op, not an error."""
    core.session.start("http://target.example:30081")
    out = await _fire_http("http://target.example:30081/")
    assert "http" in (core.session.get().get("tools_called") or [])
    assert out  # tool still returns its envelope
