"""
Shared fixtures for the agent-smith test suite.

Key concerns handled here:
- core.cost and core.session use module-level mutable globals — reset between tests.
- core.findings writes to a hardcoded findings.json path — redirect to tmp_path.
- core.findings._lock is an asyncio.Lock() — recreate per test to avoid cross-loop issues.
- File writes from cost/session modules are redirected to tmp_path so the repo root stays clean.
"""
import asyncio
import logging
import pytest
import core.cost
import core.session
import core.findings
import core.coverage

# ── MCP tool decorator shim ───────────────────────────────────────────────────
# FastMCP.add_tool() calls pydantic.create_model(result=<class 'str'>) which
# raises PydanticUserError on pydantic v2.10+ (unannotated field). This patch
# replaces FastMCP.tool() with a no-op BEFORE any mcp_server module is
# imported during test collection, so the underlying _do_* helpers are
# importable and testable without triggering the decorator machinery.
from unittest.mock import patch as _patch
from mcp.server.fastmcp import FastMCP as _FastMCP
_mcp_tool_shim = _patch.object(_FastMCP, "tool", side_effect=lambda **kw: lambda f: f)
_mcp_tool_shim.start()


@pytest.fixture(autouse=True)
def isolate_logger():
    """Remove the file handler from the pentest logger during tests.

    Without this, every test that calls core.logger.* writes to the real
    logs/pentest.log, polluting it with test entries that look like live
    pentest activity — making the Logs and Skills tabs misleading.
    Tests that need to assert log output should use pytest's caplog fixture,
    which captures in-memory records regardless of this change.
    """
    logger = logging.getLogger("pentest")
    file_handlers = [h for h in logger.handlers if isinstance(h, logging.FileHandler)]
    for h in file_handlers:
        logger.removeHandler(h)
    yield
    for h in file_handlers:
        logger.addHandler(h)


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


@pytest.fixture(autouse=True)
def reset_coverage_lock(monkeypatch):
    """Recreate the coverage module's asyncio.Lock() per test."""
    monkeypatch.setattr(core.coverage, "_lock", asyncio.Lock())


@pytest.fixture
def findings_file(tmp_path, monkeypatch):
    """Redirect findings.json to a temp file and return the Path."""
    path = tmp_path / "findings.json"
    monkeypatch.setattr(core.findings, "FINDINGS_FILE", path)
    return path


@pytest.fixture
def coverage_file(tmp_path, monkeypatch):
    """Redirect coverage_matrix.json to a temp file and return the Path."""
    path = tmp_path / "coverage_matrix.json"
    monkeypatch.setattr(core.coverage, "COVERAGE_FILE", path)
    return path
