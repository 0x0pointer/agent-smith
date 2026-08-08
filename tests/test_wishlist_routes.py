"""
Tests for the wishlist dashboard routes — fulfill injects a steering directive
(closing the loop back to Smith); dismiss resolves; unknown id → 404.
"""
import json
import pytest

import core.wishlist as wl
import core.steering as st
from core.wishlist import WishlistQueue
from core.steering import steering_queue
from core.api_server.routes import api_wishlist_fulfill, api_wishlist_dismiss, api_wishlist


class _FakeReq:
    def __init__(self, body):
        self._b = body

    async def json(self):
        return self._b


@pytest.fixture
def queues(tmp_path, monkeypatch):
    monkeypatch.setattr(wl, "_WISHLIST_FILE", tmp_path / "wishlist_queue.json")
    monkeypatch.setattr(st, "_STEERING_FILE", tmp_path / "steering_queue.json")
    return WishlistQueue()


def _body(resp):
    return json.loads(resp.body.decode())


@pytest.mark.asyncio
async def test_fulfill_injects_steering_with_cells(queues):
    item_id = queues.add("analyst creds", category="credentials", blocking_cell_ids=["c1", "c2"])
    resp = await api_wishlist_fulfill(item_id, _FakeReq({"note": "analyst/Pw123"}))
    assert _body(resp)["ok"] is True
    # a WISHLIST_FULFILLED directive was queued with the cells + note in the message
    active = [d for d in steering_queue.get_active() if d.trigger == "WISHLIST_FULFILLED"]
    assert active, "no steering directive injected"
    msg = active[0].message
    assert "analyst/Pw123" in msg and "c1" in msg and "c2" in msg
    assert not queues.list_open()


@pytest.mark.asyncio
async def test_fulfill_unknown_id_404(queues):
    resp = await api_wishlist_fulfill("nope", _FakeReq({"note": "x"}))
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_dismiss(queues):
    item_id = queues.add("expand scope")
    resp = await api_wishlist_dismiss(item_id, _FakeReq({"note": "out of scope"}))
    assert _body(resp)["ok"] is True
    assert not queues.list_open()


@pytest.mark.asyncio
async def test_list_returns_items(queues):
    queues.add("need nmap")
    resp = await api_wishlist()
    assert len(_body(resp)["items"]) == 1
