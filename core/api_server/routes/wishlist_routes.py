"""Wishlist routes: the agent→operator resource backlog."""
from __future__ import annotations

import logging

from fastapi import Request
from fastapi.responses import JSONResponse

import core.api_server as _api

from ._common import router

_log = logging.getLogger(__name__)


@router.get("/api/wishlist")
async def api_wishlist() -> JSONResponse:
    """The agent→operator resource backlog (open + resolved), newest first."""
    try:
        from core.wishlist import wishlist_queue
        return JSONResponse({"items": wishlist_queue.get_all()})
    except Exception:
        _log.exception("api_wishlist failed")
        return JSONResponse({"items": []})


@router.post("/api/wishlist/{item_id}/fulfill")
async def api_wishlist_fulfill(item_id: str, request: Request) -> JSONResponse:
    """Operator supplied a wished-for resource.

    Marks the item fulfilled and injects a steering directive so Smith reopens
    the blocked cells and uses the new resource — closing the loop without an HIR.
    Body: {"note": "the credential / scope / detail Smith should use"}
    """
    try:
        body = await request.json()
        note = str(body.get("note", "")).strip()
        from core.wishlist import wishlist_queue
        from core.steering import steering_queue, RESUME_REQUIRED
        item = wishlist_queue.fulfill(item_id, note=note)
        if not item:
            return JSONResponse({"ok": False, "error": "not found or already resolved"}, status_code=404)
        cells = item.get("blocking_cell_ids") or []
        cell_hint = f" Reopen and re-test these blocked cell(s) now: {', '.join(cells)}." if cells else ""
        steering_queue.add_directive(
            code=RESUME_REQUIRED,
            message=(
                f"WISHLIST FULFILLED — the operator supplied what you asked for: {item.get('need', '')}."
                + (f" Details: {note}." if note else "")
                + cell_hint
                + " Use it to go deeper; do NOT mark those cells not_applicable."
            ),
            priority="high",
            skill=None,
            trigger="WISHLIST_FULFILLED",
            force=True,
        )
        return JSONResponse({"ok": True, "item": item})
    except Exception:
        _log.exception("api_wishlist_fulfill failed")
        return JSONResponse({"ok": False, "error": _api._ERR_REQUEST_FAILED}, status_code=500)


@router.post("/api/wishlist/{item_id}/dismiss")
async def api_wishlist_dismiss(item_id: str, request: Request) -> JSONResponse:
    """Operator declined a wishlist item (won't/can't supply it)."""
    try:
        body = await request.json()
        note = str(body.get("note", "")).strip()
        from core.wishlist import wishlist_queue
        item = wishlist_queue.dismiss(item_id, note=note)
        if not item:
            return JSONResponse({"ok": False, "error": "not found or already resolved"}, status_code=404)
        return JSONResponse({"ok": True, "item": item})
    except Exception:
        _log.exception("api_wishlist_dismiss failed")
        return JSONResponse({"ok": False, "error": _api._ERR_REQUEST_FAILED}, status_code=500)
