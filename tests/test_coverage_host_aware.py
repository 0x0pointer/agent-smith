"""Phase 3 (docs/plan-danger-depth.md): host-aware coverage matrix.

Endpoint identity is (host, normalized_path, method) so the SAME path on a
different internal host (a pivot discovery) is its own endpoint with its own
cells. Host comes from an explicit host= arg, a scheme-qualified URL path, or
defaults to the matrix target — so ordinary single-host scans are unchanged.
"""
import json
import pytest

import core.coverage


@pytest.fixture
def danger_pivot_env(coverage_file, tmp_path, monkeypatch):
    """A live danger session (deep-pivot enabled) + redirected coverage matrix, so a
    promotion can register pivot-host attribution stubs into the isolated matrix."""
    import core.session as scan_session
    monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
    scan_session._current = None
    scan_session.start("http://perimeter.test:30081", depth="danger")
    yield
    scan_session._current = None


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


def test_discovery_gap_is_host_aware():
    from core.coverage.validation import unregistered_finding_paths
    cov = {"endpoints": [{"_normalized": "/admin", "path": "/admin", "method": "GET", "host": "t.test"}]}
    finds = {"findings": [
        {"target": "http://t.test/admin"},            # registered on this host → OK
        {"target": "http://10.0.0.5:5000/admin"},      # same path, DIFFERENT host → gap
        {"target": "http://t.test/newpath"},           # brand-new path → gap
    ]}
    out = unregistered_finding_paths(finds, cov)
    assert "/newpath" in out
    assert any(o.startswith("10.0.0.5") and o.endswith("/admin") for o in out)   # pivoted-host gap
    assert "/admin" not in out                                                    # perimeter one is fine


def test_discovery_gap_legacy_hostless_no_false_positive():
    # a pre-Phase-3 (host-less) matrix falls back to path-only — no new false gaps
    from core.coverage.validation import unregistered_finding_paths
    cov = {"endpoints": [{"_normalized": "/admin", "path": "/admin", "method": "GET"}]}
    finds = {"findings": [{"target": "http://10.0.0.5/admin"}]}
    assert unregistered_finding_paths(finds, cov) == []


@pytest.mark.asyncio
async def test_list_cells_host_filter(coverage_file):
    await core.coverage.add_endpoint("/admin", "GET", [{"name": "id", "type": "query"}], host="10.0.0.1")
    await core.coverage.add_endpoint("/admin", "GET", [{"name": "id", "type": "query"}], host="10.0.0.2")
    res = await core.coverage.list_cells(host="10.0.0.2")
    assert res["filtered"] > 0
    assert all(c["host"] == "10.0.0.2" for c in res["cells"])     # scoped to the pivoted host
    res_all = await core.coverage.list_cells()
    assert {c["host"] for c in res_all["cells"]} == {"10.0.0.1", "10.0.0.2"}


@pytest.mark.asyncio
async def test_empty_meta_target_falls_back_to_live_scan_target(coverage_file, monkeypatch):
    """Fix 4: a matrix auto-created with meta.target='' (a coverage op ran before the reset
    populated it) must still host-stamp endpoints from the LIVE scan target — instead of leaving
    every endpoint host='' (the inert-host bug that made all 993 cells look single-host)."""
    import core.session as _sess
    monkeypatch.setattr(_sess, "_current", {"status": "running", "target": "http://10.9.9.9:30081"})
    r = await core.coverage.add_endpoint("/login", "POST", [{"name": "u", "type": "query"}])
    assert not r["dedup"]
    eps = json.loads(coverage_file.read_text())["endpoints"]
    assert eps[0]["host"] == "10.9.9.9:30081"      # from the live session target, not ''


@pytest.mark.asyncio
async def test_explicit_host_still_wins_over_live_target(coverage_file, monkeypatch):
    """Fix 4: the live-target fallback must not override an explicit pivot host= on the call."""
    import core.session as _sess
    monkeypatch.setattr(_sess, "_current", {"status": "running", "target": "http://10.9.9.9:30081"})
    await core.coverage.add_endpoint("/x", "GET", [{"name": "id", "type": "query"}], host="10.44.0.9")
    eps = json.loads(coverage_file.read_text())["endpoints"]
    assert eps[0]["host"] == "10.44.0.9"           # pivot host, not the fallback target


# ── IMPROVEMENT-PLAN 1.4: pivot hosts enter the matrix as thin attribution stubs ──

def test_pivot_stub_registers_host_without_cells(coverage_file):
    """A promoted internal host gets a host-tagged endpoint row so the matrix is
    host-attributable — but NO cells (no NA/injection bloat, nothing to stall completion)."""
    r = core.coverage.register_pivot_stub("10.150.0.158:5000")
    assert r and not r["dedup"]
    data = json.loads(coverage_file.read_text())
    ep = data["endpoints"][0]
    assert ep["host"] == "10.150.0.158:5000" and ep["stub"] is True
    assert data["meta"]["total_cells"] == 0        # attribution only — zero cells


def test_pivot_stub_dedups(coverage_file):
    core.coverage.register_pivot_stub("10.1.1.1:443")
    r2 = core.coverage.register_pivot_stub("10.1.1.1:443")
    assert r2["dedup"]
    assert len(json.loads(coverage_file.read_text())["endpoints"]) == 1


@pytest.mark.asyncio
async def test_stub_upgraded_in_place_when_registered_with_params(coverage_file):
    """Once a route exists and the agent registers the host-qualified endpoint WITH params,
    the stub is upgraded in place: cells fan out and the stub flag clears (the attribution
    record must not suppress real coverage)."""
    stub = core.coverage.register_pivot_stub("10.2.2.2:5000", path="/api/v1", method="GET")
    r = await core.coverage.add_endpoint(
        "/api/v1", "GET", [{"name": "ns", "type": "query"}], host="10.2.2.2:5000")
    assert r["dedup"] and r["endpoint_id"] == stub["endpoint_id"]   # same row, upgraded
    assert r["new_cells"] > 0                                        # cells now fanned out
    ep = next(e for e in json.loads(coverage_file.read_text())["endpoints"]
              if e["id"] == stub["endpoint_id"])
    assert ep.get("stub") is False and ep["params"]


def test_promote_registers_matrix_stub(danger_pivot_env):
    """End-to-end: deep-pivot promotion tags the promoted host into the matrix as a stub."""
    import core.pivot as pivot
    pivot.promote_internal_hosts("SSRF reached internal pod 10.77.0.9:5000", source="ssrf")
    hosts = {e["host"] for e in core.coverage._load()["endpoints"]}
    # the promoter collapses :port on an IP (10.x:5000 and 10.x are one host), so the stub
    # is tagged with the bare IP
    assert "10.77.0.9" in hosts
