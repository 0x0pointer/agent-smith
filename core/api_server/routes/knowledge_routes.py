"""Knowledge routes: browse the Source vaults registered on this machine.

A Source (https://github.com/0x0pointer/Source) is a local, offline search
service over a folder of Markdown notes. Smith consults a bound Source during a
scan and writes what it learns back to it; these endpoints let the operator read
the same vault from the dashboard:

* ``GET /api/knowledge``                 — registered Sources and whether each is up
* ``GET /api/knowledge/{name}/notes``    — the vault's note list
* ``GET /api/knowledge/{name}/search``   — hybrid / vector / keyword search
* ``GET /api/knowledge/{name}/note``     — one note's Markdown

Only Sources from the registry (``sources.yaml``) are reachable, and the
registry only admits ``http://localhost`` URLs, so these never proxy to another
host. Everything a Source returns is untrusted data: the dashboard escapes or
sanitizes it before rendering.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path

import aiohttp
from fastapi import Request
from fastapi.responses import JSONResponse

from ._common import router

_LOG = logging.getLogger(__name__)

_TIMEOUT = aiohttp.ClientTimeout(total=8, connect=2, sock_connect=2, sock_read=6)
# Saving a note makes the Source rebuild its index, which takes longer than a read.
_WRITE_TIMEOUT = aiohttp.ClientTimeout(total=60, connect=2, sock_connect=2, sock_read=55)
_MAX_NOTE_BYTES = 400_000
_NOTE_SUFFIXES = (".md", ".txt")
_SEARCH_MODES = ("hybrid", "vector", "keyword")
_MAX_K = 20


def _is_operator(request: Request) -> bool:
    return getattr(request.state, "role", "") == "operator"


def _forbidden() -> JSONResponse:
    return JSONResponse({"error": "forbidden"}, status_code=403)


def _sources() -> dict[str, dict]:
    try:
        from core.sources import list_sources

        return dict(list_sources())
    except Exception:
        _LOG.exception("source registry unreadable")
        return {}


def _source_url(name: str) -> str | None:
    meta = _sources().get(name)
    url = str((meta or {}).get("url") or "").rstrip("/")
    return url or None


async def _get(url: str, path: str, params: dict | None = None) -> tuple[int, object]:
    """GET ``url + path`` from a Source. Returns (status, json) or (0, None) if unreachable."""
    try:
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as client, client.get(
            f"{url}{path}", params=params or None
        ) as resp:
            try:
                payload = await resp.json(content_type=None)
            except Exception:
                payload = None
            return resp.status, payload
    except Exception as exc:  # noqa: BLE001 — a Source being down is an expected state
        _LOG.info("source request %s%s failed: %s", url, path, type(exc).__name__)
        return 0, None


async def _post(url: str, path: str, body: dict) -> int:
    """POST JSON to a Source. Returns the HTTP status, or 0 if unreachable."""
    try:
        async with aiohttp.ClientSession(timeout=_WRITE_TIMEOUT) as client, client.post(
            f"{url}{path}", json=body
        ) as resp:
            return resp.status
    except Exception as exc:  # noqa: BLE001
        _LOG.info("source request %s%s failed: %s", url, path, type(exc).__name__)
        return 0


async def _describe(name: str, url: str) -> dict:
    status, health = await _get(url, "/health")
    info = {"name": name, "url": url, "reachable": status == 200, "ready": False,
            "instance": "", "notes": None}
    if status == 200 and isinstance(health, dict):
        info["ready"] = bool(health.get("ready"))
        info["instance"] = str(health.get("instance") or "")
        if info["ready"]:
            list_status, listing = await _get(url, "/list")
            notes = listing.get("notes") if list_status == 200 and isinstance(listing, dict) else None
            if isinstance(notes, list):
                info["notes"] = len(notes)
    return info


@router.get("/api/knowledge")
async def api_knowledge(request: Request) -> JSONResponse:
    if not _is_operator(request):
        return _forbidden()
    sources = _sources()
    described = await asyncio.gather(*[
        _describe(name, str((meta or {}).get("url") or "").rstrip("/"))
        for name, meta in sorted(sources.items())
    ])
    return JSONResponse({"sources": list(described)})


def _unavailable(status: int) -> JSONResponse:
    if status == 503:
        return JSONResponse({"error": "The Source is still building its index. Try again in a moment."},
                            status_code=503)
    return JSONResponse({"error": "The Source is not running or did not answer."}, status_code=502)


def _clean_note(item: object) -> dict | None:
    if not isinstance(item, dict) or not item.get("path"):
        return None
    return {"path": str(item["path"]), "chunks": int(item.get("chunks") or 0)}


@router.get("/api/knowledge/{name}/notes")
async def api_knowledge_notes(name: str, request: Request) -> JSONResponse:
    if not _is_operator(request):
        return _forbidden()
    url = _source_url(name)
    if not url:
        return JSONResponse({"error": "unknown source"}, status_code=404)
    status, payload = await _get(url, "/list")
    if status != 200 or not isinstance(payload, dict):
        return _unavailable(status)
    notes = [n for n in (_clean_note(i) for i in payload.get("notes") or []) if n]
    notes.sort(key=lambda n: n["path"].lower())
    return JSONResponse({"source": name, "notes": notes})


def _clean_hit(item: object) -> dict | None:
    if not isinstance(item, dict):
        return None
    tags = item.get("tags")
    if isinstance(tags, str):
        tags = tags.split()
    return {
        "rank": item.get("rank"),
        "path": str(item.get("path") or ""),
        "heading": str(item.get("heading") or ""),
        "score": item.get("score"),
        "text": str(item.get("text") or item.get("snippet") or "")[:6000],
        "tags": [str(t) for t in tags] if isinstance(tags, list) else [],
    }


@router.get("/api/knowledge/{name}/search")
async def api_knowledge_search(name: str, request: Request, q: str = "", mode: str = "hybrid",
                               k: int = 8, path: str = "", tags: str = "") -> JSONResponse:
    if not _is_operator(request):
        return _forbidden()
    url = _source_url(name)
    if not url:
        return JSONResponse({"error": "unknown source"}, status_code=404)
    query = q.strip()
    if not query:
        return JSONResponse({"error": "Type something to search for."}, status_code=400)
    params: dict[str, object] = {
        "q": query[:500],
        "k": max(1, min(int(k), _MAX_K)),
        "mode": mode if mode in _SEARCH_MODES else "hybrid",
    }
    if path.strip():
        params["path"] = path.strip()[:300]
    if tags.strip():
        params["tags"] = tags.strip()[:300]
    status, payload = await _get(url, "/search", params)
    if status != 200 or not isinstance(payload, dict):
        return _unavailable(status)
    hits = [h for h in (_clean_hit(i) for i in payload.get("results") or []) if h]
    return JSONResponse({"source": name, "query": query, "mode": params["mode"], "results": hits})


class _NoteRefused(ValueError):
    """The requested note path is not one this endpoint will read."""


def _note_file(vault: str, note_path: str) -> Path:
    """Resolve ``note_path`` inside ``vault``; raise if it would escape it.

    The path comes from the browser, so it is normalised and then checked
    against the vault root before anything is opened: no absolute paths, no
    ``..``, no hidden segments, Markdown/text only.
    """
    rel = str(note_path or "").replace("\\", "/").strip()
    parts = [p for p in rel.split("/") if p]
    if not parts or rel.startswith("/") or any(p in (".", "..") or p.startswith(".") for p in parts):
        raise _NoteRefused("invalid note path")
    if ":" in rel or not rel.lower().endswith(_NOTE_SUFFIXES):
        raise _NoteRefused("invalid note path")
    root = os.path.realpath(vault)
    full = os.path.realpath(os.path.join(root, *parts))
    if not full.startswith(root + os.sep):
        raise _NoteRefused("note is outside the vault")
    return Path(full)


def _read_note(vault: str, note_path: str) -> dict:
    path = _note_file(vault, note_path)
    with path.open("rb") as fh:
        raw = fh.read(_MAX_NOTE_BYTES + 1)
    return {
        "content": raw[:_MAX_NOTE_BYTES].decode("utf-8", errors="replace"),
        "truncated": len(raw) > _MAX_NOTE_BYTES,
    }


@router.get("/api/knowledge/{name}/note")
async def api_knowledge_note(name: str, request: Request, path: str = "") -> JSONResponse:
    """One note's Markdown.

    Source's HTTP service has no "read note" call, but it runs on this machine
    and reports its vault folder, so the note is read from disk — only when the
    Source itself lists that exact path, and only from inside its vault.
    """
    if not _is_operator(request):
        return _forbidden()
    url = _source_url(name)
    if not url:
        return JSONResponse({"error": "unknown source"}, status_code=404)
    status, listing = await _get(url, "/list")
    if status != 200 or not isinstance(listing, dict):
        return _unavailable(status)
    listed = {str(n.get("path")) for n in listing.get("notes") or [] if isinstance(n, dict)}
    if path not in listed:
        return JSONResponse({"error": "note not found"}, status_code=404)
    vault = str(listing.get("vault") or "")
    if not vault:
        return JSONResponse({"error": "note not found"}, status_code=404)
    try:
        body = await asyncio.to_thread(_read_note, vault, path)
    except _NoteRefused:
        return JSONResponse({"error": "note not found"}, status_code=404)
    except OSError:
        return JSONResponse({"error": "This note could not be read from the vault folder."}, status_code=404)
    return JSONResponse({"source": name, "path": path, **body})


# ── Brain: map, ask, save ────────────────────────────────────────────────────

def _safe_read(vault: str, note_path: str) -> str | None:
    """A listed note's text, or None if it is unreadable or outside the vault."""
    try:
        return _read_note(vault, note_path)["content"]
    except (_NoteRefused, OSError):
        return None


@router.get("/api/knowledge/{name}/graph")
async def api_knowledge_graph(name: str, request: Request) -> JSONResponse:
    """The vault as a graph: notes, the links between them, and their tags."""
    if not _is_operator(request):
        return _forbidden()
    url = _source_url(name)
    if not url:
        return JSONResponse({"error": "unknown source"}, status_code=404)
    status, listing = await _get(url, "/list")
    if status != 200 or not isinstance(listing, dict):
        return _unavailable(status)
    paths = [str(n["path"]) for n in listing.get("notes") or [] if isinstance(n, dict) and n.get("path")]
    vault = str(listing.get("vault") or "")
    from core import knowledge_brain

    graph = await asyncio.to_thread(
        knowledge_brain.build_graph, paths, lambda p: _safe_read(vault, p) if vault else None)
    return JSONResponse({"source": name, **graph})


# One answer at a time: each one is a model call that can take a while.
_ask_lock = asyncio.Lock()
_ASK_PASSAGES = 6


async def _ask_sources(url: str, question: str, focus: str) -> tuple[list[dict], int]:
    """Numbered passages for a question: the open note first (if any), then search hits."""
    from core import knowledge_brain as brain

    sources: list[dict] = []
    if focus:
        status, listing = await _get(url, "/list")
        if status == 200 and isinstance(listing, dict):
            listed = {str(n.get("path")) for n in listing.get("notes") or [] if isinstance(n, dict)}
            vault = str(listing.get("vault") or "")
            text = await asyncio.to_thread(_safe_read, vault, focus) if focus in listed and vault else None
            if text:
                sources.append({"path": focus, "heading": "the open note",
                                "text": brain.clip(text, brain.MAX_FOCUS_NOTE_CHARS)})
    status, payload = await _get(url, "/search", {"q": question[:500], "k": _ASK_PASSAGES, "mode": "hybrid"})
    if status == 200 and isinstance(payload, dict):
        for hit in (h for h in (_clean_hit(i) for i in payload.get("results") or []) if h and h["text"]):
            if sources and focus and hit["path"] == focus:
                continue                      # the open note is already there in full
            sources.append({"path": hit["path"], "heading": hit["heading"],
                            "text": brain.clip(hit["text"], brain.MAX_PASSAGE_CHARS)})
    for n, src in enumerate(sources, 1):
        src["n"] = n
    return sources, status


@router.post("/api/knowledge/{name}/ask")
async def api_knowledge_ask(name: str, request: Request) -> JSONResponse:
    """Answer a question from the vault, with the passages it was answered from.

    Body: ``{"question": "...", "history": [{"role", "text"}], "note": "path"}``.
    Always returns the retrieved ``sources``; ``answer`` is null (with a plain
    ``message``) when nothing matched or the AI client could not answer, so the
    page can still show the passages.
    """
    if not _is_operator(request):
        return _forbidden()
    url = _source_url(name)
    if not url:
        return JSONResponse({"error": "unknown source"}, status_code=404)
    try:
        body = await request.json()
    except ValueError:
        return JSONResponse({"error": "malformed json"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "malformed json"}, status_code=400)
    from core import knowledge_brain as brain

    question = str(body.get("question") or "").strip()
    if not question:
        return JSONResponse({"error": "Type a question."}, status_code=400)
    if len(question) > brain.MAX_QUESTION_CHARS:
        return JSONResponse({"error": "That question is too long."}, status_code=400)
    if _ask_lock.locked():
        return JSONResponse({"error": "The brain is still answering another question."}, status_code=429)

    async with _ask_lock:
        sources, status = await _ask_sources(url, question, str(body.get("note") or ""))
        if not sources:
            if status != 200:
                return _unavailable(status)
            return JSONResponse({"source": name, "answer": None, "sources": [], "reason": "no_matches",
                                 "message": "Nothing in this vault matches that question."})
        prompt = brain.build_prompt(question, sources, brain.clean_history(body.get("history")))
        result = await asyncio.to_thread(brain.run_client, prompt)

    shown = [{"n": s["n"], "path": s["path"], "heading": s["heading"], "text": brain.clip(s["text"], 400)}
             for s in sources]
    if not result.get("ok"):
        _LOG.info("knowledge ask: no answer (%s)", result.get("reason"))
        return JSONResponse({"source": name, "answer": None, "sources": shown,
                             "reason": result.get("reason"), "message": result.get("message")})
    return JSONResponse({"source": name, "answer": result["text"], "sources": shown,
                         "client": result.get("client", "")})


_SLUG = re.compile(r"[^a-z0-9]+")
_TAG_OK = re.compile(r"[A-Za-z0-9_-]{1,40}")
_SAVE_FOLDER = "brain"
_MAX_SAVE_CHARS = 60_000


@router.post("/api/knowledge/{name}/notes")
async def api_knowledge_save_note(name: str, request: Request) -> JSONResponse:
    """Save a note to the vault (the page's "Save to vault" on a brain answer).

    Body: ``{"title": "...", "text": "...", "tags": [...]}``. Written through the
    Source's own ``/ingest`` to ``brain/<date>-<slug>.md``; the Source validates
    the id and re-indexes.
    """
    if not _is_operator(request):
        return _forbidden()
    url = _source_url(name)
    if not url:
        return JSONResponse({"error": "unknown source"}, status_code=404)
    try:
        body = await request.json()
    except ValueError:
        return JSONResponse({"error": "malformed json"}, status_code=400)
    title = " ".join(str((body or {}).get("title") or "").split())[:120] if isinstance(body, dict) else ""
    text = str((body or {}).get("text") or "").strip() if isinstance(body, dict) else ""
    if not title or not text:
        return JSONResponse({"error": "A note needs a title and some text."}, status_code=400)
    if len(text) > _MAX_SAVE_CHARS:
        return JSONResponse({"error": "That note is too long to save."}, status_code=400)
    tags = [t for t in (body.get("tags") or []) if isinstance(t, str) and _TAG_OK.fullmatch(t)][:8]
    slug = _SLUG.sub("-", title.lower()).strip("-")[:60] or "note"
    note_id = f"{_SAVE_FOLDER}/{datetime.now(timezone.utc):%Y-%m-%d}-{slug}"
    status = await _post(url, "/ingest", {"notes": [{"id": note_id, "title": title, "tags": tags, "text": text}]})
    if status != 200:
        return _unavailable(status)
    return JSONResponse({"source": name, "saved": True, "path": f"{note_id}.md"})
