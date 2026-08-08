"""
Tests for the wishlist — core queue, session dispatch, and the auth-routing guard.
"""
import json
import pytest

import core.session
import core.wishlist as wl
from core.wishlist import WishlistQueue
from mcp_server.session_tools import _do_wishlist_add, _do_wishlist_list


@pytest.fixture
def wishlist_file(tmp_path, monkeypatch):
    path = tmp_path / "wishlist_queue.json"
    monkeypatch.setattr(wl, "_WISHLIST_FILE", path)
    return path


# ── core queue ──────────────────────────────────────────────────────────────────

def test_add_and_list_open(wishlist_file):
    q = WishlistQueue()
    i = q.add("analyst creds for /admin", category="credentials", blocking_cell_ids=["c1", "c2"])
    assert i and len(q.list_open()) == 1
    assert q.list_open()[0].blocking_cell_ids == ["c1", "c2"]


def test_open_dedup(wishlist_file):
    q = WishlistQueue()
    q.add("expand scope to staging")
    assert q.add("Expand  Scope  To Staging") is None  # normalised dup of open item
    assert len(q.list_open()) == 1


def test_fulfill_returns_blocking_cells(wishlist_file):
    q = WishlistQueue()
    i = q.add("need creds", category="credentials", blocking_cell_ids=["x"])
    item = q.fulfill(i, note="analyst/Pw")
    assert item and item["status"] == "fulfilled" and item["blocking_cell_ids"] == ["x"]
    assert not q.list_open()


def test_fulfilled_need_can_be_readded(wishlist_file):
    q = WishlistQueue()
    i = q.add("need X")
    q.fulfill(i)
    assert q.add("need X") is not None  # only OPEN items dedup


def test_bad_category_coerced(wishlist_file):
    q = WishlistQueue()
    q.add("a thing", category="bogus")
    assert q.list_open()[0].category == "other"


# ── session dispatch ──────────────────────────────────────────────────────────

def test_wishlist_add_requires_need(wishlist_file):
    assert "requires need" in _do_wishlist_add({})


def test_wishlist_add_and_list(wishlist_file, monkeypatch):
    monkeypatch.setattr(core.session, "_current", {"status": "running", "known_assets": {}})
    res = _do_wishlist_add({"need": "scope to staging", "category": "scope", "blocking_cell_ids": ["c9"]})
    assert "recorded" in res and "blocked cell" in res
    listed = json.loads(_do_wishlist_list())
    assert listed["open"] == 1 and listed["items"][0]["need"] == "scope to staging"


def test_auth_guard_blocks_when_creds_known(wishlist_file, monkeypatch):
    monkeypatch.setattr(core.session, "_current", {
        "status": "running",
        "known_assets": {"auth_tokens": [{"value": "eyJ..."}], "credentials": [], "auth_endpoints": []},
    })
    res = _do_wishlist_add({"need": "valid account / login as admin"})
    assert "NOT QUEUED" in res
    # nothing was queued
    assert json.loads(_do_wishlist_list())["open"] == 0


def test_auth_need_queued_when_no_assets(wishlist_file, monkeypatch):
    monkeypatch.setattr(core.session, "_current", {"status": "running", "known_assets": {}})
    res = _do_wishlist_add({"need": "valid admin password — none discovered yet"})
    assert "recorded" in res
