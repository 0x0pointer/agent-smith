from __future__ import annotations

import json

import pytest

from core import session as scan_session
from mcp_server.session_tools import session


def _registry(tmp_path):
    reg = tmp_path / "sources.yaml"
    reg.write_text(
        "sources:\n"
        "  prod-web: {url: http://127.0.0.1:7801}\n"
        "  other: {url: http://127.0.0.1:7802}\n",
        encoding="utf-8",
    )
    return reg


@pytest.mark.asyncio
async def test_start_binds_source_and_status_recovery_show_it(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SOURCE_REGISTRY", str(_registry(tmp_path)))
    out = await session("start", {"target": "http://t", "source": "prod-web"}, None)
    assert "Source: prod-web" in out
    persisted = json.loads((tmp_path / "session.json").read_text(encoding="utf-8"))
    assert persisted["source_instance"] == {"name": "prod-web", "url": "http://127.0.0.1:7801"}
    status = json.loads(await session("status", {}, None))
    recovery = json.loads(await session("recovery", {}, None))
    assert status["source_instance"] == persisted["source_instance"]
    assert recovery["source_instance"] == persisted["source_instance"]


@pytest.mark.asyncio
async def test_start_unknown_source_non_blocking(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SOURCE_REGISTRY", str(_registry(tmp_path)))
    out = await session("start", {"target": "http://t", "source": "missing"}, None)
    assert "Scan started." in out
    assert "Source: none bound." in out
    assert "Available valid names: other, prod-web." in out
    assert scan_session.get()["source_instance"] is None


@pytest.mark.asyncio
async def test_use_source_rebinds_and_clears(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SOURCE_REGISTRY", str(_registry(tmp_path)))
    await session("start", {"target": "http://t"}, None)
    rebound = await session("use_source", {"source": "other"}, None)
    assert "Source rebound: other" in rebound
    assert scan_session.get()["source_instance"] == {"name": "other", "url": "http://127.0.0.1:7802"}
    cleared = await session("use_source", {"source": ""}, None)
    assert cleared == "Source binding cleared."
    assert scan_session.get()["source_instance"] is None


@pytest.mark.asyncio
async def test_set_skill_source_methodology_full_medium_not_small(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SOURCE_REGISTRY", str(_registry(tmp_path)))

    calls: list[str] = []

    async def _fake_search(query, k=3, mode=None, path=None, tags=None):
        calls.append(query)
        return {
            "ok": True,
            "source": {"name": "prod-web", "url": "http://127.0.0.1:7801"},
            "items": [{"label": "notes.md", "snippet": "Do the thing carefully."}],
        }

    monkeypatch.setattr("mcp_server.session_tools.skills.source_client.search", _fake_search)

    for profile in ("full", "medium"):
        await session("start", {"target": "http://t", "source": "prod-web", "model_profile": profile, "force_restart": True}, None)
        out = await session("set_skill", {"skill": "web-exploit", "reason": "test"}, None)
        assert "Methodology from prod-web" in out

    await session("start", {"target": "http://t", "source": "prod-web", "model_profile": "small", "force_restart": True}, None)
    out = await session("set_skill", {"skill": "web-exploit", "reason": "test"}, None)
    assert "Methodology from prod-web" not in out
    assert len(calls) == 2
