"""#4 — deterministic IDOR/BOLA id-enumeration sweep: planner + differential + tool."""
import re

import pytest

from core.coverage import id_sweep as S


# ── planner ──────────────────────────────────────────────────────────────────

def test_plan_nearest_first_bounded_excludes_baseline():
    ids = S.plan_ids(100, window=5, max_probes=60)
    assert 100 not in ids
    assert ids[:4] == [99, 101, 98, 102]       # nearest-first, both directions
    assert all(i >= 0 for i in ids)


def test_plan_respects_max_probes():
    assert len(S.plan_ids(1000, window=500, max_probes=20)) == 20


def test_plan_non_numeric_uses_extras_only():
    assert S.plan_ids("abc", extra=[5, 7, "x"]) == [5, 7]


def test_plan_no_negatives():
    assert all(i >= 0 for i in S.plan_ids(2, window=10))


# ── evaluator ────────────────────────────────────────────────────────────────

def _r(i, status, h):
    return {"id": i, "status": status, "length": 10, "body_hash": h}


def test_authz_boundary_is_candidate():
    base = {"status": 200, "body_hash": "base"}
    results = [_r(1, 403, "deny"), _r(2, 403, "deny"), _r(3, 200, "obj3"), _r(4, 403, "deny")]
    v = S.evaluate(base, results)
    assert v["verdict"] == "candidate" and v["hits"][0]["id"] == 3


def test_distinct_objects_is_bola_candidate():
    base = {"status": 200, "body_hash": "obj100"}
    results = [_r(i, 200, f"obj{i}") for i in range(101, 106)]
    v = S.evaluate(base, results)
    assert v["verdict"] == "candidate" and "IDOR" in v["basis"].upper() or "BOLA" in v["basis"]
    assert len(v["hits"]) >= 3


def test_uniform_denial_is_clean():
    base = {"status": 403, "body_hash": "deny"}
    results = [_r(i, 403, "deny") for i in range(1, 6)]
    assert S.evaluate(base, results)["verdict"] == "clean"


def test_shared_200_body_is_clean():
    base = {"status": 200, "body_hash": "same"}
    results = [_r(i, 200, "same") for i in range(1, 6)]
    assert S.evaluate(base, results)["verdict"] == "clean"


def test_empty_is_inconclusive():
    assert S.evaluate({"status": 200, "body_hash": "x"}, [])["verdict"] == "inconclusive"


# ── orchestration (monkeypatched http) ───────────────────────────────────────

@pytest.fixture
def _patch(monkeypatch):
    import mcp_server.http_tools as ht
    import mcp_server.scan_engine.envelope as env
    monkeypatch.setattr(env, "store_artifact", lambda *a, **k: "id-art")

    def _id_of(url):
        m = re.search(r"/order/(\d+)/", url)
        return int(m.group(1)) if m else -1
    return ht, _id_of


async def test_orchestration_surfaces_idor(_patch, monkeypatch):
    from mcp_server.report_tools import coverage
    ht, id_of = _patch

    async def fake(url, method="GET", headers=None, body=None, timeout=20):
        i = id_of(url)
        # every id returns its own distinct object → BOLA
        return {"status": 200, "headers": {}, "body": f"receipt for order {i}"}
    monkeypatch.setattr(ht, "http_probe", fake)

    out = await coverage._do_coverage_id_sweep(
        {"url": "http://t/order/{}/receipt", "baseline": 300100, "window": 5}, None)
    assert "candidate" in out.lower() and "id=" in out


async def test_orchestration_secured_endpoint_is_clean(_patch, monkeypatch):
    from mcp_server.report_tools import coverage
    ht, id_of = _patch

    async def fake(url, method="GET", headers=None, body=None, timeout=20):
        i = id_of(url)
        return ({"status": 200, "headers": {}, "body": "your receipt"} if i == 300100
                else {"status": 403, "headers": {}, "body": "forbidden"})
    monkeypatch.setattr(ht, "http_probe", fake)

    out = await coverage._do_coverage_id_sweep(
        {"url": "http://t/order/{}/receipt", "baseline": 300100, "window": 5}, None)
    assert "No broken-object-authorization candidate" in out


async def test_orchestration_requires_baseline():
    from mcp_server.report_tools import coverage
    out = await coverage._do_coverage_id_sweep({"url": "http://t/order/{}/x"}, None)
    assert "baseline" in out.lower()
