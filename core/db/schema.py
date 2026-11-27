from __future__ import annotations

from sqlalchemy import Column, MetaData, Table, Text

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
