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
import core.paths

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
def _reset_graph_cache():
    """build_graph() memoizes on the (mtime,size) of the three store files. Tests
    monkeypatch those stores in-memory without touching disk, so the mtime key
    can't see the change — invalidate before and after each test so a graph built
    from one test's monkeypatched stores never leaks into the next."""
    from core.graph import build as _gb
    _gb.invalidate_graph_cache()
    yield
    _gb.invalidate_graph_cache()


@pytest.fixture(autouse=True)
def disable_dashboard_auth(monkeypatch, tmp_path):
    """Disable the per-session dashboard bearer-token gate for the suite.

    The FastAPI middleware requires an Authorization header on /api/* once a
    scan has minted a token (core.dashboard_auth). The existing API tests drive
    those routes via TestClient without a header, so enforcement is switched off
    here; the auth behaviour itself is covered by test_dashboard_auth.py, which
    re-enables it explicitly. The token file is also redirected to tmp_path so a
    test that runs the real session-start path can't mint a token into the repo's
    logs/dashboard.token.
    """
    monkeypatch.setenv("SMITH_DASHBOARD_AUTH", "0")
    monkeypatch.setattr(core.paths, "DASHBOARD_TOKEN_FILE", tmp_path / "dashboard.token")


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
    """Reset session module state and redirect output file for each test.

    _last_local_write_mtime tracks "when did this process last flush
    session.json?" — used by load_from_disk(force=True) and
    _reconcile_if_external_write to detect external deletions. Earlier
    tests that exercise _flush() leave this global non-zero, which then
    causes later tests that monkeypatch _current without writing disk
    to have their stub clobbered (the reconcile reads
    "_last_local_write_mtime > 0 AND file gone → external deletion →
    clear cache"). Resetting it per-test restores isolation.
    """
    monkeypatch.setattr(core.session, "_current", None)
    monkeypatch.setattr(core.session, "_SESSION_FILE", tmp_path / "session.json")
    monkeypatch.setattr(core.session, "_last_local_write_mtime", 0.0)


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
    """Redirect coverage_matrix.json and _ARTIFACTS_DIR to temp paths."""
    path = tmp_path / "coverage_matrix.json"
    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.mkdir()
    monkeypatch.setattr(core.coverage, "COVERAGE_FILE", path)
    monkeypatch.setattr(core.coverage, "_ARTIFACTS_DIR", artifacts_dir)
    return path
