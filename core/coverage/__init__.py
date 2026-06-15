"""
Coverage matrix store
=====================
Thread-safe read/write of coverage_matrix.json.

Tracks every (endpoint × param × injection type) cell so the agent
systematically tests all applicable combinations instead of hoping it
remembers to circle back.

Schema
------
{
  "meta":      { "created": "<ISO>", "target": "", "total_cells": 0,
                 "tested": 0, "vulnerable": 0, "not_applicable": 0, "skipped": 0 },
  "endpoints": [ { id, path, method, params, discovered_by, discovered_at, auth_context } ],
  "matrix":    [ { id, endpoint_id, param, param_type, injection_type,
                   status, notes, finding_id, tested_at, tested_by } ]
}

Integrity rules
---------------
1. Cells that resolve to tested_clean/vulnerable MUST pass through in_progress first.
   Direct pending → tested_clean is rejected (returns a warning string instead of True).
2. Every cell tracks `tested_by` — the tool or method used for testing.
3. Marking a cell `not_applicable` for injection types with known bypass techniques
   (xxe, sqli, xss, ssti) requires the notes to mention what bypass was ruled out.
   An empty or generic note triggers a warning.

Used by mcp_server/report_tools.py (coverage action) and session_tools.py.

Layout
------
The implementation is split across focused submodules; import from
``core.coverage`` exactly as before — every name is re-exported here.

  __init__     this file — shared config (paths, lock) + JSON I/O + facade
  classify     path normalization + endpoint type classification
  validation   integrity / artifact / auth / finding-link gates
  operations   add_endpoint, update_cell, bulk_update, queries, reset

The mutable config below (COVERAGE_FILE, _ARTIFACTS_DIR, _lock) lives here,
in the package namespace, so it stays patchable as ``core.coverage.NAME``.
The submodules read it back via ``import core.coverage as _cov`` (deferred
attribute access), which is both monkeypatch-transparent and safe against
the import cycle.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

from core import paths as _paths

COVERAGE_FILE  = _paths.COVERAGE_FILE
_ARTIFACTS_DIR = _paths.ARTIFACTS_DIR

_lock = asyncio.Lock()


# ---------------------------------------------------------------------------
# Which statuses count as "addressed" for coverage percentage purposes.
# skipped is intentionally excluded — it is a deferral, not evidence of testing.
# ---------------------------------------------------------------------------

ADDRESSED_STATUSES: frozenset[str] = frozenset({"tested_clean", "vulnerable", "not_applicable"})


# ---------------------------------------------------------------------------
# Internal I/O — read/write coverage_matrix.json. These read COVERAGE_FILE
# from this module's namespace, so tests patching core.coverage.COVERAGE_FILE
# take effect transparently.
# ---------------------------------------------------------------------------

def _load() -> dict:
    if COVERAGE_FILE.exists():
        try:
            return json.loads(COVERAGE_FILE.read_text())
        except Exception:
            pass
    return {
        "meta": {
            "created": datetime.now(timezone.utc).isoformat(),
            "target": "",
            "total_cells": 0,
            "tested": 0,
            "vulnerable": 0,
            "not_applicable": 0,
            "skipped": 0,
        },
        "endpoints": [],
        "matrix": [],
    }


def _save(data: dict) -> None:
    # COVERAGE_FILE is derived from __file__ at module load — it is not user-controlled.
    # Suppression below silences the false-positive S2083 path-construction rule.
    Path(COVERAGE_FILE).write_text(json.dumps(data, indent=2))  # NOSONAR


def _recount(data: dict) -> None:
    """Recompute meta counters from the matrix."""
    cells = data["matrix"]
    data["meta"]["total_cells"]    = len(cells)
    data["meta"]["tested"]         = sum(1 for c in cells if c["status"] in ("tested_clean", "vulnerable"))
    data["meta"]["in_progress"]    = sum(1 for c in cells if c["status"] == "in_progress")
    data["meta"]["vulnerable"]     = sum(1 for c in cells if c["status"] == "vulnerable")
    data["meta"]["not_applicable"] = sum(1 for c in cells if c["status"] == "not_applicable")
    data["meta"]["skipped"]        = sum(1 for c in cells if c["status"] == "skipped")
    data["meta"]["addressed"]      = sum(1 for c in cells if c["status"] in ADDRESSED_STATUSES)


# ---------------------------------------------------------------------------
# Facade re-exports. Imported last and intentionally below the config + I/O
# above: the submodules bind ``core.coverage`` at import time but only read
# its attributes at call time, so the names above are guaranteed present.
# ---------------------------------------------------------------------------

from .classify import (  # noqa: E402
    _APPLICABILITY,
    _applicable_types,
    _normalize_path,
    classify_endpoint,
)
from .validation import (  # noqa: E402
    _AUTH_GATED_TYPES,
    _BYPASS_REQUIRED_TYPES,
    _integrity_warning_for_status,
    _na_bypass_warning,
    _validate_artifact,
    _validate_auth_response,
    _validate_finding_link,
)
from .operations import (  # noqa: E402
    _apply_bulk_cell,
    add_endpoint,
    bulk_update,
    get_matrix,
    get_pending,
    list_cells,
    reset,
    update_cell,
)

__all__ = [
    "ADDRESSED_STATUSES",
    "COVERAGE_FILE",
    "classify_endpoint",
    "add_endpoint",
    "update_cell",
    "bulk_update",
    "get_matrix",
    "get_pending",
    "list_cells",
    "reset",
]
