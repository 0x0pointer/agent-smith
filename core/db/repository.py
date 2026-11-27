from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.engine import Engine

from .schema import dashboard_tokens, metadata, run_snapshots, runs


class DatabaseRepository:
    def __init__(self, url: str):
        self._engine: Engine = create_engine(url, future=True)
        metadata.create_all(self._engine)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def upsert_run(self, run_id: str, payload: dict, workdir: str) -> None:
        now = self._now()
        row = {
            "run_id": run_id,
            "target": str(payload.get("target") or ""),
            "status": str(payload.get("status") or ""),
            "depth": str(payload.get("depth") or ""),
            "workdir": workdir,
            "payload_json": json.dumps(payload),
            "created_at": str(payload.get("started") or now),
            "updated_at": now,
        }
        with self._engine.begin() as conn:
            existing = conn.execute(
                select(runs.c.run_id).where(runs.c.run_id == run_id)
            ).first()
            if existing:
                conn.execute(
                    runs.update().where(runs.c.run_id == run_id).values(**row)
                )
            else:
                conn.execute(runs.insert().values(**row))

    def save_snapshot(self, run_id: str, kind: str, payload: dict) -> None:
        row = {
            "run_id": run_id,
            "kind": kind,
            "payload_json": json.dumps(payload),
            "updated_at": self._now(),
        }
        with self._engine.begin() as conn:
            existing = conn.execute(
                select(run_snapshots.c.run_id).where(
                    (run_snapshots.c.run_id == run_id)
                    & (run_snapshots.c.kind == kind)
                )
            ).first()
            if existing:
                conn.execute(
                    run_snapshots.update().where(
                        (run_snapshots.c.run_id == run_id)
                        & (run_snapshots.c.kind == kind)
                    ).values(**row)
                )
            else:
                conn.execute(run_snapshots.insert().values(**row))

    def load_snapshot(self, run_id: str, kind: str) -> dict | None:
        with self._engine.begin() as conn:
            row = conn.execute(
                select(run_snapshots.c.payload_json).where(
                    (run_snapshots.c.run_id == run_id)
                    & (run_snapshots.c.kind == kind)
                )
            ).first()
        if not row:
            return None
        return json.loads(row[0])

    def list_runs(self) -> list[dict]:
        with self._engine.begin() as conn:
            rows = conn.execute(select(runs).order_by(runs.c.updated_at.desc())).mappings().all()
        return [dict(row) for row in rows]

    def save_dashboard_token(self, token_hash: str, run_id: str, role: str) -> None:
        row = {
            "token_hash": token_hash,
            "run_id": run_id,
            "role": role,
            "created_at": self._now(),
        }
        with self._engine.begin() as conn:
            conn.execute(
                dashboard_tokens.delete().where(dashboard_tokens.c.token_hash == token_hash)
            )
            conn.execute(dashboard_tokens.insert().values(**row))

    def lookup_dashboard_token(self, token_hash: str) -> dict | None:
        with self._engine.begin() as conn:
            row = conn.execute(
                select(dashboard_tokens).where(dashboard_tokens.c.token_hash == token_hash)
            ).mappings().first()
        return dict(row) if row else None
