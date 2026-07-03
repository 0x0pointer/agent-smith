"""Dashboard UI + static assets routes."""
from __future__ import annotations

from fastapi import Request
from fastapi.responses import FileResponse, JSONResponse

import core.api_server as _api

from ._common import router


# ── Dashboard UI + static assets ────────────────────────────────────────────

@router.get("/")
async def dashboard_ui(request: Request):
    """Render the dashboard shell — index.html {% include %}s the per-tab
    partials; CSS/JS load from the /static mount."""
    return _api.templates.TemplateResponse(request, "index.html")


@router.get("/healthz")
async def healthz() -> JSONResponse:
    """Unauthenticated liveness probe used by serve() to detect a healthy
    dashboard. Returns no scan data, so it stays reachable when the /api/*
    control plane requires the per-session bearer token."""
    return JSONResponse({"ok": True})


@router.get("/logo.png")
async def logo() -> FileResponse:
    return FileResponse(_api._TEMPLATES_DIR / "FullLogo_Transparent.png", media_type="image/png")


@router.get("/favicon.ico")
async def favicon() -> FileResponse:
    """Real .ico file served with the correct media type. Browsers that
    auto-probe /favicon.ico (Safari, every IE-lineage thing) want this
    exact path and content-type to avoid logging a 404 on every page load."""
    return FileResponse(
        _api._TEMPLATES_DIR / "favicon.ico",
        media_type="image/vnd.microsoft.icon",
    )


@router.get("/favicon-32x32.png")
async def favicon_png() -> FileResponse:
    """Sized PNG favicon for modern browsers — referenced explicitly from
    the <link rel="icon" sizes="32x32"> tag in index.html. Modern
    rendering pipelines prefer this over the .ico when both are available."""
    return FileResponse(
        _api._TEMPLATES_DIR / "favicon-32x32.png",
        media_type="image/png",
    )
