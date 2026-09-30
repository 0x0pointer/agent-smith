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
  "endpoints": [ { id, path, method, params, discovered_by, discovered_at,
                   auth_context, candidate } ],
  "matrix":    [ { id, endpoint_id, param, param_type, injection_type,
                   status, notes, finding_id, tested_at, tested_by, candidate } ]
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
from core import store as _store

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
    _store.save(COVERAGE_FILE, data)


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

    # Confirmed vs candidate split (issue #180). A candidate cell belongs to an
    # endpoint whose existence liveness-classification could not prove (a wordlist
    # hit that 403'd / matched the not-found baseline / went unprobed). A missing
    # flag means confirmed, so legacy matrices and every non-fuzz cell count as
    # confirmed. The completion gate and coverage % should measure CONFIRMED cells
    # so ~3k phantom cells from non-existent paths can't wedge coverage or deflate
    # the headline figure.
    candidate_cells = sum(1 for c in cells if c.get("candidate"))
    data["meta"]["candidate_cells"] = candidate_cells
    data["meta"]["confirmed_cells"] = len(cells) - candidate_cells
    data["meta"]["addressed_confirmed"] = sum(
        1 for c in cells if not c.get("candidate") and c["status"] in ADDRESSED_STATUSES
    )
    eps = data.get("endpoints", [])
    cand_eps = sum(1 for e in eps if e.get("candidate"))
    data["meta"]["candidate_endpoints"] = cand_eps
    data["meta"]["confirmed_endpoints"] = len(eps) - cand_eps


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
    cell_has_test_evidence,
    unregistered_finding_paths,
)
from .operations import (  # noqa: E402
    _apply_bulk_cell,
    add_endpoint,
    bulk_update,
    get_matrix,
    get_next_batch,
    get_pending,
    list_cells,
    reset,
    select_next_batch,
    update_cell,
)
from .autoclose import (  # noqa: E402
    CROSSCUTTING_TYPES,
    parse_artifact_headers,
    pick_representative_artifact,
    plan_crosscutting_closures,
)

__all__ = [
    "ADDRESSED_STATUSES",
    "COVERAGE_FILE",
    "classify_endpoint",
    "add_endpoint",
    "update_cell",
    "bulk_update",
    "get_matrix",
    "get_next_batch",
    "get_pending",
    "list_cells",
    "reset",
    "select_next_batch",
    "cell_has_test_evidence",
    "unregistered_finding_paths",
]
