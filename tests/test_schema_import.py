"""SM-4 / SP-3: one-call schema import → coverage cells."""
import pytest

import core.coverage
import core.session as scan_session
import mcp_server.scan_engine.discovery as discovery


_SPEC = (
    '{"openapi":"3.0.0","paths":{'
    '"/users/{id}":{"get":{"parameters":[{"name":"id","in":"path"},{"name":"q","in":"query"}]}},'
    '"/orders":{"post":{"requestBody":{"content":{"application/json":'
    '{"schema":{"properties":{"amount":{}}}}}}}}}}'
)


@pytest.fixture
def running():
    scan_session._current = {"status": "running", "known_assets": {}}
    yield
    scan_session._current = None


@pytest.mark.asyncio
async def test_import_openapi_registers_all_operations(coverage_file, running, monkeypatch):
    async def fake_fetch(u):
        return 200, _SPEC
    monkeypatch.setattr(discovery, "_fetch", fake_fetch)

    res = await discovery.import_openapi("http://t/openapi.json")
    assert res["registered"] == 2 and res["operations"] == 2 and res["cells"] > 0
    # both operations became endpoints in the matrix
    paths = {e["path"] for e in core.coverage.get_matrix()["endpoints"]}
    assert "/users/{id}" in paths and "/orders" in paths


@pytest.mark.asyncio
async def test_import_openapi_bad_spec(coverage_file, running, monkeypatch):
    async def fake_fetch(u):
        return 200, "<html>not a spec</html>"
    monkeypatch.setattr(discovery, "_fetch", fake_fetch)
    res = await discovery.import_openapi("http://t/nope")
    assert res["registered"] == 0 and "error" in res


@pytest.mark.asyncio
async def test_coverage_import_dispatch_requires_url(coverage_file, running):
    from mcp_server.report_tools.coverage import _do_coverage_import
    out = await _do_coverage_import("import_openapi", {})
    assert "needs a 'url'" in out
