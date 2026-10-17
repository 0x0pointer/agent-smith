"""Phase 3 (docs/plan-danger-depth.md): host-aware coverage matrix.

Endpoint identity is (host, normalized_path, method) so the SAME path on a
different internal host (a pivot discovery) is its own endpoint with its own
cells. Host comes from an explicit host= arg, a scheme-qualified URL path, or
defaults to the matrix target — so ordinary single-host scans are unchanged.
"""
import json
import pytest

import core.coverage


@pytest.mark.asyncio
async def test_same_path_different_hosts_are_distinct(coverage_file):
    r1 = await core.coverage.add_endpoint("/admin", "GET", [{"name": "id", "type": "query"}], host="10.0.0.1")
    r2 = await core.coverage.add_endpoint("/admin", "GET", [{"name": "id", "type": "query"}], host="10.0.0.2")
    assert not r1["dedup"] and not r2["dedup"]
    assert r1["endpoint_id"] != r2["endpoint_id"]
    eps = json.loads(coverage_file.read_text())["endpoints"]
    assert {e["host"] for e in eps} == {"10.0.0.1", "10.0.0.2"}


@pytest.mark.asyncio
async def test_same_host_path_dedups(coverage_file):
    await core.coverage.add_endpoint("/admin", "GET", [], host="10.0.0.1")
    r2 = await core.coverage.add_endpoint("/admin", "GET", [], host="10.0.0.1")
    assert r2["dedup"]


@pytest.mark.asyncio
async def test_scheme_url_path_splits_host_and_path(coverage_file):
    r = await core.coverage.add_endpoint(
        "http://10.1.2.3:5000/api/v1", "POST", [{"name": "q", "type": "query"}])
    ep = json.loads(coverage_file.read_text())["endpoints"][0]
    assert ep["host"] == "10.1.2.3:5000"
    assert ep["path"] == "/api/v1"
    assert r["new_cells"] > 0


@pytest.mark.asyncio
async def test_different_port_is_different_surface(coverage_file):
    # a Flask pod on :5000 is a distinct coverage surface from :80 on the same IP
    await core.coverage.add_endpoint("/x", "GET", [], host="10.0.0.1:80")
    r2 = await core.coverage.add_endpoint("/x", "GET", [], host="10.0.0.1:5000")
    assert not r2["dedup"]
    eps = json.loads(coverage_file.read_text())["endpoints"]
    assert {e["host"] for e in eps} == {"10.0.0.1:80", "10.0.0.1:5000"}


@pytest.mark.asyncio
async def test_relative_path_defaults_to_target_host(coverage_file):
    d = core.coverage._load()
    d["meta"]["target"] = "http://tgt.test:30081"
    core.coverage._save(d)
    await core.coverage.add_endpoint("/login", "POST", [{"name": "u", "type": "body"}])
    ep = json.loads(coverage_file.read_text())["endpoints"][-1]
    assert ep["host"] == "tgt.test:30081" and ep["path"] == "/login"


@pytest.mark.asyncio
async def test_relative_path_dedups_against_legacy_no_host(coverage_file):
    # a pre-Phase-3 endpoint (no "host" key) + empty target → relative re-register dedups
    d = core.coverage._load()
    d["endpoints"].append({
        "id": "ep-legacy", "path": "/old", "_normalized": "/old", "method": "GET",
        "params": [], "discovered_by": "x", "discovered_at": "", "auth_context": "none",
        "candidate": False})
    core.coverage._save(d)
    r = await core.coverage.add_endpoint("/old", "GET", [])
    assert r["dedup"] and r["endpoint_id"] == "ep-legacy"


def test_projection_includes_host():
    from core.coverage.operations import _project_cell_with_endpoint
    out = _project_cell_with_endpoint(
        {"id": "c1", "param": "q"}, {"host": "10.5.5.5:8080", "path": "/p", "method": "GET"})
    assert out["host"] == "10.5.5.5:8080"
