from __future__ import annotations

from fastapi import File, Form, Query, UploadFile
from fastapi.responses import JSONResponse

from ._common import router
from .vector_routes import api_vector_docs, api_vector_docs_delete, api_vector_docs_upload

_DEPRECATION = "/api/kb/docs is deprecated; use /api/vector/docs"


def _with_deprecation(resp: JSONResponse) -> JSONResponse:
    resp.headers["X-Agent-Smith-Deprecated"] = _DEPRECATION
    try:
        payload = resp.body and __import__("json").loads(resp.body)
        if isinstance(payload, dict):
            payload.setdefault("deprecated", _DEPRECATION)
            return JSONResponse(payload, status_code=resp.status_code, headers=resp.headers)
    except Exception:
        pass
    return resp


@router.get("/api/kb/docs")
async def api_kb_docs(vault: str | None = Query(None), dataset: str | None = Query(None)) -> JSONResponse:
    return _with_deprecation(await api_vector_docs(vault=vault, dataset=dataset))


@router.post("/api/kb/docs")
async def api_kb_docs_upload(files: list[UploadFile] = File(...), vault: str = Form(""),
                             dataset: str = Form("docs"), untrusted: str = Form("false")) -> JSONResponse:
    return _with_deprecation(await api_vector_docs_upload(files=files, vault=vault, dataset=dataset, untrusted=untrusted))


@router.delete("/api/kb/docs/{name}")
async def api_kb_docs_delete(name: str, vault: str | None = Query(None), dataset: str | None = Query(None)) -> JSONResponse:
    return _with_deprecation(await api_vector_docs_delete(name=name, vault=vault, dataset=dataset))
