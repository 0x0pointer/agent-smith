"""
Shared fixtures for the agent-smith test suite.

Key concerns handled here:
- core.cost and core.session use module-level mutable globals — reset between tests.
- core.findings writes to a hardcoded findings.json path — redirect to tmp_path.
- core.findings._lock is an asyncio.Lock() — recreate per test to avoid cross-loop issues.
- File writes from cost/session modules are redirected to tmp_path so the repo root stays clean.
"""
import asyncio
import pytest
import core.cost
import core.session
import core.findings


@pytest.fixture(autouse=True)
def isolate_cost(tmp_path, monkeypatch):
    """Reset cost module state and redirect output file for each test."""
    monkeypatch.setattr(core.cost, "_calls", [])
    monkeypatch.setattr(core.cost, "_COST_FILE", tmp_path / "session_cost.json")


@pytest.fixture(autouse=True)
def isolate_session(tmp_path, monkeypatch):
    """Reset session module state and redirect output file for each test."""
    monkeypatch.setattr(core.session, "_current", None)
    monkeypatch.setattr(core.session, "_SESSION_FILE", tmp_path / "session.json")


@pytest.fixture(autouse=True)
def reset_findings_lock(monkeypatch):
    """
    asyncio.Lock() attaches to the running event loop on first use.
    With per-test event loops (pytest-asyncio default), we recreate the lock
    each test so it always binds to the correct loop.
    """
    monkeypatch.setattr(core.findings, "_lock", asyncio.Lock())


@pytest.fixture
def findings_file(tmp_path, monkeypatch):
    """Redirect findings.json to a temp file and return the Path."""
    path = tmp_path / "findings.json"
    monkeypatch.setattr(core.findings, "FINDINGS_FILE", path)
    return path
