"""#2 — differential phantom-check for the SSTI sweep oracle.

The single-probe oracle fired "SSTI candidate" on `"49" in body`, so any page
containing 49 (a price, an id, the year 1949) produced a phantom. The
differential requires the output to TRACK two randomized operands, which a bare
constant cannot do. These tests prove the phantom is defused while a real
template injection still surfaces.
"""
import random

import pytest

from core.coverage import sweep as S
from mcp_server.scan_engine import planner


# ── pure differential evaluator ──────────────────────────────────────────────

def _p(expected, body, status=200, payload="{{x}}"):
    return {"expected": str(expected), "body": body, "status": status, "payload": payload}


def test_both_products_tracked_is_candidate():
    v = S.evaluate_ssti_differential([_p(49, "result=49"), _p(143, "result=143")])
    assert v["verdict"] == "candidate"


def test_phantom_single_constant_is_not_candidate():
    """A page that always contains '49' but never the second random product
    must NOT be a candidate — this is the exact phantom the old oracle fired on."""
    v = S.evaluate_ssti_differential([_p(49, "price: 49 USD"), _p(143, "price: 49 USD")])
    assert v["verdict"] == "inconclusive"


def test_no_product_tracked_is_clean():
    v = S.evaluate_ssti_differential([_p(49, "hello world"), _p(143, "hello world")])
    assert v["verdict"] == "clean"


def test_auth_block_is_blocked():
    v = S.evaluate_ssti_differential([_p(49, "", status=401), _p(143, "x")])
    assert v["verdict"] == "blocked"


def test_single_usable_response_is_inconclusive():
    v = S.evaluate_ssti_differential([_p(49, "49"), _p(143, "", status=500)])
    assert v["verdict"] == "inconclusive"


def test_both_5xx_is_inconclusive():
    v = S.evaluate_ssti_differential([_p(49, "", status=500), _p(143, "", status=500)])
    assert v["verdict"] == "inconclusive"


# ── build_probe operand parameterization ─────────────────────────────────────

def test_build_probe_default_ssti():
    p = planner.build_probe("ssti", "http://t", "/x", "GET", "q", "query")
    assert p["payload"] == "{{7*7}}" and p["expected"] == "49"


def test_build_probe_ssti_operands():
    p = planner.build_probe("ssti", "http://t", "/x", "GET", "q", "query", operands=(11, 13))
    assert "11*13" in p["payload"] and p["expected"] == "143"
    assert "11*13" in p["url"]


# ── orchestration: phantom defused end-to-end ────────────────────────────────

@pytest.fixture
def _patch_io(monkeypatch):
    import mcp_server.scan_engine.envelope as env
    monkeypatch.setattr(env, "store_artifact", lambda *a, **k: "art-test")
    random.seed(1234)  # deterministic operand choice


async def _run(monkeypatch, http_fake):
    from mcp_server.report_tools import coverage
    monkeypatch.setattr(coverage, "_run_http_probe", http_fake)
    cell = {"id": "c1", "injection_type": "ssti", "param": "q", "param_type": "query"}
    ep = {"path": "/x", "method": "GET"}
    return await coverage._run_ssti_differential(cell, ep, "http://t")


async def test_real_ssti_surfaces_candidate(_patch_io, monkeypatch):
    async def http_fake(probe):
        # a real engine evaluates: the expected product appears in the body
        return 200, f"<h1>Welcome {probe['expected']}</h1>", "{}"
    art, v = await _run(monkeypatch, http_fake)
    assert art == "art-test" and v["verdict"] == "candidate"


async def test_page_containing_49_is_not_a_phantom(_patch_io, monkeypatch):
    async def http_fake(probe):
        # page always shows "49" (a price) but never evaluates anything
        return 200, "<p>Only 49 left in stock</p>", "{}"
    _art, v = await _run(monkeypatch, http_fake)
    assert v["verdict"] != "candidate"   # phantom defused


async def test_clean_page_auto_closes(_patch_io, monkeypatch):
    async def http_fake(probe):
        return 200, "<p>nothing here</p>", "{}"
    _art, v = await _run(monkeypatch, http_fake)
    assert v["verdict"] == "clean"
