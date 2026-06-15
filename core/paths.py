"""
Canonical filesystem paths
===========================
Single source of truth for the repo root and every state/output artifact the
server reads or writes. Before this module these literals (and the
``Path(__file__).parent…`` root resolution) were re-derived in ~10 modules.

Each module aliases what it needs, e.g.::

    from core import paths as _paths
    _SESSION_FILE = _paths.SESSION_FILE

Keeping the per-module name means the path strings live in ONE place while
each module still exposes its own attribute for tests to monkeypatch — so
this change is behaviour-preserving with zero test churn.

This is a **leaf** module: it imports nothing from ``core``, so anything may
depend on it without creating an import cycle.
"""
from __future__ import annotations

from pathlib import Path

# core/paths.py → one parent up is core/, two is the repo root. Resolved so
# every consumer derives the same canonical absolute path.
REPO_ROOT = Path(__file__).parent.parent.resolve()

# ── State / output files (repo root) ──────────────────────────────────────────
SESSION_FILE     = REPO_ROOT / "session.json"
FINDINGS_FILE    = REPO_ROOT / "findings.json"
COVERAGE_FILE    = REPO_ROOT / "coverage_matrix.json"
QA_STATE_FILE    = REPO_ROOT / "qa_state.json"
STEERING_FILE    = REPO_ROOT / "steering_queue.json"
QUICK_LOG_FILE   = REPO_ROOT / "quick_log.json"
COST_FILE        = REPO_ROOT / "session_cost.json"
METRICS_FILE     = REPO_ROOT / "pentest_metrics.jsonl"

# ── Directories ───────────────────────────────────────────────────────────────
LOGS_DIR         = REPO_ROOT / "logs"
ARTIFACTS_DIR    = REPO_ROOT / "artifacts"
TEMPLATES_DIR    = REPO_ROOT / "templates"
DASHBOARD_DIR    = REPO_ROOT / "dashboard"
THREAT_MODEL_DIR = REPO_ROOT / "threat-model"
POCS_DIR         = REPO_ROOT / "pocs"

# ── Files within logs/ ────────────────────────────────────────────────────────
SMITH_PID_FILE     = LOGS_DIR / "smith.pid"
SMITH_CLIENT_FILE  = LOGS_DIR / "smith.client"
DASHBOARD_PID_FILE = LOGS_DIR / "dashboard.pid"
LOG_FILE           = LOGS_DIR / "pentest.log"
