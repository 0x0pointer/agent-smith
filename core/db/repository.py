from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import create_engine, select, update
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError

from .schema import dashboard_tokens, metadata, run_snapshots, run_work_items, runs


class DatabaseRepository:
    def __init__(self, url: str):
        self._engine: Engine = create_engine(url, future=True)
        metadata.create_all(self._engine)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _run_row(self, run_id: str, payload: dict, workdir: str) -> dict:
        now = self._now()
        return {
            "run_id": run_id,
            "target": str(payload.get("target") or ""),
            "status": str(payload.get("status") or ""),
            "depth": str(payload.get("depth") or ""),
            "workdir": workdir,
            "payload_json": json.dumps(payload),
            "created_at": str(payload.get("started") or now),
            "updated_at": now,
        }

    def create_run(self, run_id: str, payload: dict, workdir: str) -> bool:
        row = self._run_row(run_id, payload, workdir)
        try:
            with self._engine.begin() as conn:
                conn.execute(runs.insert().values(**row))
            return True
        except IntegrityError:
            return False

    def get_run(self, run_id: str) -> dict | None:
        with self._engine.begin() as conn:
            row = conn.execute(select(runs).where(runs.c.run_id == run_id)).mappings().first()
        return dict(row) if row else None

    def upsert_run(self, run_id: str, payload: dict, workdir: str) -> None:
        row = self._run_row(run_id, payload, workdir)
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

    # ── Work queue ──────────────────────────────────────────────────────────

    WORK_MAX_ATTEMPTS = 3

    @staticmethod
    def _work_row(row) -> dict:
        d = dict(row)
        try:
            d["payload"] = json.loads(d.pop("payload_json") or "{}")
        except ValueError:
            d["payload"] = {}
        return d

    def enqueue_work(self, run_id: str, kind: str, dedup_key: str, title: str, payload: dict) -> int | None:
        """Queue one work item. Returns its id, or None if this dedup_key is already known."""
        row = {
            "run_id": run_id, "kind": kind, "dedup_key": dedup_key, "title": title[:300],
            "payload_json": json.dumps(payload), "status": "queued", "attempts": 0, "note": "",
            "created_at": self._now(), "started_at": "", "finished_at": "",
        }
        try:
            with self._engine.begin() as conn:
                result = conn.execute(run_work_items.insert().values(**row))
                return int(result.inserted_primary_key[0])
        except IntegrityError:
            return None

    def list_work(self, run_id: str, statuses: tuple[str, ...] | None = None, limit: int = 200) -> list[dict]:
        query = select(run_work_items).where(run_work_items.c.run_id == run_id)
        if statuses:
            query = query.where(run_work_items.c.status.in_(statuses))
        query = query.order_by(run_work_items.c.id.desc()).limit(limit)
        with self._engine.begin() as conn:
            return [self._work_row(r) for r in conn.execute(query).mappings().all()]

    def lease_next_work(self, run_id: str) -> dict | None:
        """Claim the oldest queued item of a run (queued -> running), or None.

        The claim is a conditional UPDATE on status, so two dispatchers racing for
        the same row cannot both win.
        """
        with self._engine.begin() as conn:
            row = conn.execute(
                select(run_work_items)
                .where(run_work_items.c.run_id == run_id, run_work_items.c.status == "queued")
                .order_by(run_work_items.c.id.asc()).limit(1)
            ).mappings().first()
            if not row:
                return None
            claimed = conn.execute(
                update(run_work_items)
                .where(run_work_items.c.id == row["id"], run_work_items.c.status == "queued")
                .values(status="running", attempts=row["attempts"] + 1, started_at=self._now(), finished_at="")
            )
            if claimed.rowcount != 1:
                return None
            fresh = conn.execute(select(run_work_items).where(run_work_items.c.id == row["id"])).mappings().first()
        return self._work_row(fresh)

    def finish_work(self, item_id: int, ok: bool, note: str = "") -> str:
        """Close a running item. A failed item goes back to the queue until it has
        used WORK_MAX_ATTEMPTS, then stays failed. Returns the resulting status."""
        with self._engine.begin() as conn:
            row = conn.execute(select(run_work_items).where(run_work_items.c.id == item_id)).mappings().first()
            if not row or row["status"] != "running":
                return str(row["status"]) if row else "missing"
            if ok:
                status = "done"
            else:
                status = "queued" if row["attempts"] < self.WORK_MAX_ATTEMPTS else "failed"
            conn.execute(
                update(run_work_items).where(run_work_items.c.id == item_id, run_work_items.c.status == "running")
                .values(status=status, note=note[:500], finished_at=self._now() if status != "queued" else "")
            )
        return status
