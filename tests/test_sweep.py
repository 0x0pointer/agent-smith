"""Server-side coverage sweep (SM-5 / SM-10) — end-to-end behavior.

Auto-close confident-clean cells, flag oracle-positives as candidates (never
auto-file), leave auth-blocked/inconclusive pending. Plus the medium-profile
enforce_coverage flip the sweep enables.
"""
import pytest

import core.coverage
import core.session as scan_session
import mcp_server.http_tools as http_tools
import mcp_server.report_tools as rt
import mcp_server.scan_engine.artifacts as _artifacts
import tools.kali_runner as kali_runner


@pytest.fixture
def running_session():
    scan_session._current = {"status": "running", "target": "http://t.test",
                             "known_assets": {}}
    yield
    scan_session._current = None


@pytest.mark.asyncio
async def test_sweep_autocloses_clean_and_flags_candidates(
        coverage_file, running_session, monkeypatch):
    # store_artifact (mcp) and the coverage validator must share the artifact dir
    monkeypatch.setattr(_artifacts, "_ARTIFACTS_DIR", core.coverage._ARTIFACTS_DIR)

    await core.coverage.add_endpoint(
        "/q", "GET", [{"name": "q", "type": "query", "value_hint": ""}])

    async def fake_probe(url, method="GET", headers=None, body=None, timeout=20):
        # the SSTI probe evaluates (49); everything else is benign → clean
        if "{{7*7}}" in url:
            return {"status": 200, "headers": {}, "body": "answer is 49"}
        return {"status": 200, "headers": {}, "body": "nothing interesting here"}

    async def fake_kali(cmd, *a, **k):
        return "all tested parameters do not appear to be injectable"

    monkeypatch.setattr(http_tools, "http_probe", fake_probe)
    monkeypatch.setattr(kali_runner, "exec_command", fake_kali)

    out = await rt._do_coverage_sweep({"max_cells": 50}, core.coverage)

    assert "auto-closed tested_clean" in out
    assert "cell" in out and "ssti" in out.lower()  # ssti surfaced as a candidate

    statuses = {c["injection_type"]: c["status"]
                for c in core.coverage.get_matrix()["matrix"] if c["param"] == "q"}
    assert statuses.get("xss") == "tested_clean"        # benign body → auto-closed
    assert statuses.get("cmdi") == "tested_clean"
    assert statuses.get("sqli") == "tested_clean"       # sqlmap clean marker
    assert statuses.get("ssti") == "pending"            # candidate — model must confirm+file


@pytest.mark.asyncio
async def test_sweep_leaves_auth_blocked_pending(coverage_file, running_session, monkeypatch):
    monkeypatch.setattr(_artifacts, "_ARTIFACTS_DIR", core.coverage._ARTIFACTS_DIR)
    await core.coverage.add_endpoint(
        "/x", "GET", [{"name": "q", "type": "query", "value_hint": ""}])

    async def blocked(url, method="GET", headers=None, body=None, timeout=20):
        return {"status": 401, "headers": {}, "body": "unauthorized"}

    monkeypatch.setattr(http_tools, "http_probe", blocked)
    monkeypatch.setattr(kali_runner, "exec_command",
                        lambda *a, **k: _async_ret("inconclusive output"))

    out = await rt._do_coverage_sweep({"max_cells": 50}, core.coverage)
    assert "auth-blocked" in out
    statuses = [c["status"] for c in core.coverage.get_matrix()["matrix"]
                if c["injection_type"] in ("xss", "ssti", "cmdi", "traversal")]
    assert all(s == "pending" for s in statuses)  # never auto-closed clean under auth block


async def _async_ret(v):
    return v


@pytest.mark.asyncio
async def test_sweep_no_target():
    scan_session._current = {"status": "running"}
    try:
        out = await rt._do_coverage_sweep({}, core.coverage)
        assert "needs a running scan with a target" in out
    finally:
        scan_session._current = None


def test_medium_enforces_coverage():
    from mcp_server.scan_engine import budget
    assert budget.MODEL_PROFILES["medium"]["enforce_coverage"] is True
    assert budget.MODEL_PROFILES["small"]["enforce_coverage"] is False  # still advisory
