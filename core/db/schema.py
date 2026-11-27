from __future__ import annotations

from sqlalchemy import Column, Integer, MetaData, Table, Text, UniqueConstraint

metadata = MetaData()

runs = Table(
    "runs",
    metadata,
    Column("run_id", Text, primary_key=True),
    Column("target", Text, nullable=False, default=""),
    Column("status", Text, nullable=False, default=""),
    Column("depth", Text, nullable=False, default=""),
    Column("workdir", Text, nullable=False, default=""),
    Column("payload_json", Text, nullable=False, default="{}"),
    Column("created_at", Text, nullable=False, default=""),
    Column("updated_at", Text, nullable=False, default=""),
)

run_snapshots = Table(
    "run_snapshots",
    metadata,
    Column("run_id", Text, primary_key=True),
    Column("kind", Text, primary_key=True),
    Column("payload_json", Text, nullable=False, default="{}"),
    Column("updated_at", Text, nullable=False, default=""),
)

dashboard_tokens = Table(
    "dashboard_tokens",
    metadata,
    Column("token_hash", Text, primary_key=True),
    Column("run_id", Text, nullable=False, default=""),
    Column("role", Text, nullable=False, default="run"),
    Column("created_at", Text, nullable=False, default=""),
)

# Durable per-run work queue (modelled on Construct's `scans` job queue).
# New context that arrives while a run is open — e.g. notes added to its bound
# Source — becomes a queued item instead of being pushed into a busy agent.
# An idle run is handed ONE item at a time, each in a fresh agent turn, so a
# burst of updates can neither overwrite each other in context nor be forgotten.
#   queued -> running -> done | failed          (failed is retried, see repository)
# `dedup_key` makes enqueueing idempotent: the same update observed twice
# (a re-poll, a restart) yields one item.
run_work_items = Table(
    "run_work_items",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("run_id", Text, nullable=False),
    Column("kind", Text, nullable=False, default=""),
    Column("dedup_key", Text, nullable=False, default=""),
    Column("title", Text, nullable=False, default=""),
    Column("payload_json", Text, nullable=False, default="{}"),
    Column("status", Text, nullable=False, default="queued"),
    Column("attempts", Integer, nullable=False, default=0),
    Column("note", Text, nullable=False, default=""),
    Column("created_at", Text, nullable=False, default=""),
    Column("started_at", Text, nullable=False, default=""),
    Column("finished_at", Text, nullable=False, default=""),
    UniqueConstraint("run_id", "dedup_key", name="uq_run_work_dedup"),
)
