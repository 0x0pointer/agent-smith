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
def isolate_api_runtime_files(tmp_path, monkeypatch):
    """HARD guard: no test may destroy real runtime state through the API layer.

    DELETE /api/clear (core.api_server.routes.scan_state_routes.api_clear) wipes session.json,
    coverage, logs, artifacts, pocs, steering, cost, recovery + metrics using the core.api_server
    module-level path constants, _REPO_ROOT, core.logger._LOG_DIR, core.coverage and core.findings.
    Several api tests call DELETE /api/clear; without this redirect those wipes hit the REAL repo
    files and DESTROY a live/completed scan's state whenever the suite runs in a working tree that
    holds one — this actually happened once (a full-suite run erased a completed scan's
    session.json, coverage_matrix.json and pentest.log). Redirect every path api_clear touches to
    tmp so a test clear is inert on real data. Opt-in findings/coverage fixtures override these
    (last monkeypatch wins) for tests that need a specific path."""
    import core.api_server as _api
    import core.logger as _logger
    import core.coverage as _coverage
    import core.findings as _findings
    # Distinct guard dir — NOT tmp_path/"logs", which several tests create themselves via
    # (tmp_path/"logs").mkdir() and would collide with (FileExistsError).
    guard = tmp_path / "_apiclear_guard"
    guard.mkdir(exist_ok=True)
    monkeypatch.setattr(_api, "_REPO_ROOT", guard, raising=False)
    for _name, _rel in (("_SESSION_FILE", "session.json"),
                        ("_QUICK_LOG_FILE", "quick_log.json"),
                        ("_QA_STATE_FILE", "qa_state.json"),
                        ("_COST_FILE", "session_cost.json"),
                        ("_STEERING_FILE", "steering_queue.json"),
                        ("_SMITH_PID_FILE", "smith.pid"),
                        ("_SMITH_CLIENT_FILE", "smith.client")):
        if hasattr(_api, _name):
            monkeypatch.setattr(_api, _name, guard / _rel, raising=False)
    monkeypatch.setattr(_logger, "_LOG_DIR", guard, raising=False)
    monkeypatch.setattr(_coverage, "COVERAGE_FILE", tmp_path / "coverage_matrix.json", raising=False)
    monkeypatch.setattr(_findings, "FINDINGS_FILE", tmp_path / "findings.json", raising=False)
    # A scan reaching a terminal state now stops the pentest containers (Kali/MSF/MobSF).
    # Tests call complete()/_stop() constantly — without this a suite run would `docker stop`
    # the operator's REAL running containers. The teardown tests opt back in by unsetting this.
    monkeypatch.setenv("SMITH_KEEP_CONTAINERS", "1")


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
