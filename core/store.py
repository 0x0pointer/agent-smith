"""
Atomic JSON store
==================
One place for reading and writing the server's JSON state files. ``save()``
writes to a temp file in the same directory and ``os.replace()``s it into
place — an atomic swap, so a concurrent reader (the dashboard and MCP server
are separate processes sharing these files) never sees a half-written file.

Before this, ~6 modules hand-rolled ``path.write_text(json.dumps(...))``,
which is non-atomic: a reader hitting the file mid-write gets truncated JSON.

Leaf module — imports only the stdlib, so anything may depend on it.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path


def load(path, default=None):
    """Read JSON from ``path``. Return ``default`` (or ``{}``) when the file
    is missing or unreadable/corrupt — never raises."""
    if default is None:
        default = {}
    try:
        p = Path(path)
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        pass
    return default


def save(path, data, indent: int = 2) -> None:
    """Atomically write ``data`` as JSON to ``path``.

    Writes to a uniquely-named temp file in the same directory (so the final
    ``os.replace`` is a same-filesystem atomic rename), then swaps it in. On
    any failure the temp file is cleaned up and the original is left intact.
    """
    p = Path(path)
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=f".{p.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(data, indent=indent))
        os.replace(tmp, p)
        # State files (session.json, findings.json, coverage, …) hold harvested
        # target credentials / JWTs — keep them owner-only. mkstemp already creates
        # 0600 and os.replace preserves it, but chmod explicitly in case the target
        # pre-existed with looser perms (AS-06 hardening).
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
