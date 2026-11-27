from __future__ import annotations

import os

from core import run_context

from .repository import DatabaseRepository

_cached_repo: DatabaseRepository | None = None
_cached_url: str | None = None


def database_enabled() -> bool:
    if os.environ.get("SMITH_SINGLE_RUN", "").strip().lower() in ("1", "true", "yes"):
        return False
    return bool(os.environ.get("SMITH_DATABASE_URL", "").strip())


def get_repository() -> DatabaseRepository | None:
    global _cached_repo, _cached_url
    if not database_enabled():
        _cached_repo = None
        _cached_url = None
        return None
    url = os.environ.get("SMITH_DATABASE_URL", "").strip()
    if not url:
        return None
    try:
        if _cached_repo is None or _cached_url != url:
            _cached_repo = DatabaseRepository(url)
            _cached_url = url
    except Exception:
        _cached_repo = None
        _cached_url = None
        return None
    return _cached_repo


def persist_session(payload: dict) -> None:
    repo = get_repository()
    if repo is None:
        return
    run_id = run_context.run_id()
    repo.upsert_run(run_id, payload, run_context.workdir())
    repo.save_snapshot(run_id, "session", payload)


def persist_snapshot(kind: str, payload: dict) -> None:
    repo = get_repository()
    if repo is None:
        return
    repo.save_snapshot(run_context.run_id(), kind, payload)


def load_snapshot(kind: str, run_id: str | None = None) -> dict | None:
    repo = get_repository()
    if repo is None:
        return None
    try:
        return repo.load_snapshot(run_id or run_context.run_id(), kind)
    except Exception:
        return None


def list_runs() -> list[dict]:
    repo = get_repository()
    if repo is None:
        return []
    return repo.list_runs()
