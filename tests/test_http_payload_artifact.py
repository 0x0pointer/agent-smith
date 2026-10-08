"""http(payload_artifact_id=...) — deliver a stored transform payload by id (#252)."""
import json

import pytest

import mcp_server.http_tools as ht
import mcp_server.scan_engine.artifacts as arts


@pytest.fixture
def art(monkeypatch, tmp_path):
    monkeypatch.setattr(arts, "_ARTIFACTS_DIR", tmp_path)
    return arts.store_artifact("transform", 'pay"load\U000e0041')


def test_payload_becomes_body(art):
    body, err = ht._resolve_payload_artifact(None, art)
    assert err is None and body == 'pay"load\U000e0041'


def test_placeholders(art):
    body, err = ht._resolve_payload_artifact('{"m": "{{PAYLOAD_JSON}}"}', art)
    assert err is None and json.loads(body)["m"] == 'pay"load\U000e0041'
    body, _ = ht._resolve_payload_artifact("x={{PAYLOAD}}", art)
    assert body == 'x=pay"load\U000e0041'


@pytest.mark.asyncio
async def test_missing_artifact_errors(monkeypatch, tmp_path):
    monkeypatch.setattr(arts, "_ARTIFACTS_DIR", tmp_path)
    out = json.loads(await ht.http("request", "http://x", options={"payload_artifact_id": "nope_1_2"}))
    assert "not found" in out["error"]


@pytest.mark.asyncio
async def test_request_sends_artifact_body(art, monkeypatch):
    seen = {}

    async def fake(url, method, headers, body, opts):
        seen["body"] = body
        return "ok"
    monkeypatch.setattr(ht, "_do_request", fake)
    await ht.http("request", "http://x", method="POST", body='{"q": "{{PAYLOAD_JSON}}"}',
                  options={"payload_artifact_id": art})
    assert json.loads(seen["body"])["q"] == 'pay"load\U000e0041'
