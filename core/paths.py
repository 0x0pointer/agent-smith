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

import os
from pathlib import Path

# core/paths.py → one parent up is core/, two is the repo root. Resolved so
# every consumer derives the same canonical absolute path.
REPO_ROOT = Path(__file__).parent.parent.resolve()
RUNTIME_ROOT = Path(os.environ.get("SMITH_WORKDIR", "")).expanduser().resolve() if os.environ.get("SMITH_WORKDIR") else REPO_ROOT

# ── State / output files (repo root) ──────────────────────────────────────────
SESSION_FILE     = RUNTIME_ROOT / "session.json"
FINDINGS_FILE    = RUNTIME_ROOT / "findings.json"
COVERAGE_FILE    = RUNTIME_ROOT / "coverage_matrix.json"
AI_REDTEAM_FILE  = RUNTIME_ROOT / "ai_redteam.json"
QA_STATE_FILE    = RUNTIME_ROOT / "qa_state.json"
STEERING_FILE    = RUNTIME_ROOT / "steering_queue.json"
WISHLIST_FILE    = RUNTIME_ROOT / "wishlist_queue.json"
QUICK_LOG_FILE        = RUNTIME_ROOT / "quick_log.json"
ADJUDICATION_LOG_FILE = RUNTIME_ROOT / "adjudication_log.jsonl"
COST_FILE        = RUNTIME_ROOT / "session_cost.json"
METRICS_FILE     = RUNTIME_ROOT / "pentest_metrics.jsonl"

# ── Directories ───────────────────────────────────────────────────────────────
LOGS_DIR         = RUNTIME_ROOT / "logs"
SMITH_EVENTS_DIR = LOGS_DIR / "smith-events"  # per-session reasoning/event streams (<engagement_id>.jsonl)
JOBS_DIR         = LOGS_DIR / "jobs"          # background-job registry (one <job_id>.json per job, gitignored)
ARTIFACTS_DIR    = RUNTIME_ROOT / "artifacts"
TEMPLATES_DIR    = REPO_ROOT / "templates"
DASHBOARD_DIR    = REPO_ROOT / "dashboard"
THREAT_MODEL_DIR = REPO_ROOT / "threat-model"
POCS_DIR         = RUNTIME_ROOT / "pocs"

# ── Files within logs/ ────────────────────────────────────────────────────────
SMITH_PID_FILE       = LOGS_DIR / "smith.pid"
SMITH_CLIENT_FILE    = LOGS_DIR / "smith.client"
DASHBOARD_PID_FILE   = LOGS_DIR / "dashboard.pid"
DASHBOARD_TOKEN_FILE = LOGS_DIR / "dashboard.token"  # per-session dashboard bearer token (0600)
LOG_FILE             = LOGS_DIR / "pentest.log"
