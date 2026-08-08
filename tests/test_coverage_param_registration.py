"""Coverage registration quality: param-type normalization makes the fan-out generate the
RIGHT injection set (form->body_form gains xxe; json/body->body_json gain prototype/
mass_assignment), a param-less registration is warned at registration time, and the
completion gate flags write endpoints registered with no params."""
import pytest

import core.coverage
from core.taxonomy import normalize_param_type as nz
from mcp_server.session_tools.coverage_gates import _underregistered_endpoints_blocker


# ── normalizer (pure) ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("raw,canon", [
    ("form", "body_form"), ("multipart", "body_form"), ("urlencoded", "body_form"),
    ("json", "body_json"), ("body", "body_json"), ("application/json", "body_json"),
    ("querystring", "query"), ("qs", "query"), ("GET", "query"),
    ("url", "path"), ("route", "path"), ("head", "header"), ("cookies", "cookie"),
    ("prompt", "llm_prompt"),
])
def test_normalize_aliases(raw, canon):
    assert nz(raw) == canon


@pytest.mark.parametrize("canon", ["query", "body_form", "body_json", "path", "header", "cookie"])
def test_normalize_canonical_passthrough(canon):
    assert nz(canon) == canon


def test_normalize_unknown_passthrough():
    assert nz("weird_custom_type") == "weird_custom_type"   # falls back to query/default downstream


# ── add_endpoint fan-out with normalization ──────────────────────────────────

def _cells_for(data, ep_id, param):
    return {c["injection_type"] for c in data["matrix"]
            if c["endpoint_id"] == ep_id and c["param"] == param}


@pytest.mark.asyncio
async def test_form_param_gains_xxe():
    r = await core.coverage.add_endpoint("/submit", "POST",
                                         [{"name": "data", "type": "form"}])
    injs = _cells_for(core.coverage._load(), r["endpoint_id"], "data")
    assert "xxe" in injs                      # form -> body_form now includes xxe
    assert {"sqli", "cmdi", "ssti"} <= injs   # (was falling back to query, which has no xxe)


@pytest.mark.asyncio
async def test_json_param_gains_prototype_and_mass_assignment():
    r = await core.coverage.add_endpoint("/api/user", "POST",
                                         [{"name": "profile", "type": "json"}])
    injs = _cells_for(core.coverage._load(), r["endpoint_id"], "profile")
    assert {"prototype", "mass_assignment"} <= injs   # json -> body_json fans these out


@pytest.mark.asyncio
async def test_param_less_registration_warns():
    r = await core.coverage.add_endpoint("/login", "POST", [])
    assert "warning" in r and "0 params" in r["warning"]
    assert r["new_cells"] > 0                  # still gets the cross-cutting cells


@pytest.mark.asyncio
async def test_registration_with_params_no_warning():
    r = await core.coverage.add_endpoint("/search", "GET",
                                         [{"name": "q", "type": "query"}])
    assert "warning" not in r


# ── under-registration completion gate (pure) ────────────────────────────────

def _cov(endpoints, matrix):
    return {"endpoints": endpoints, "matrix": matrix}


def test_gate_flags_write_endpoint_with_no_params():
    cov = _cov(
        endpoints=[{"id": "ep1", "method": "POST", "path": "/login"}],
        matrix=[{"endpoint_id": "ep1", "param": "_endpoint", "param_type": "endpoint",
                 "injection_type": "cors"}],   # only cross-cutting, no per-param cell
    )
    b = _underregistered_endpoints_blocker(cov, coverage_enforced=True)
    assert b and "POST /login" in b and "UNDER-REGISTERED" in b


def test_gate_ignores_static_get_with_no_params():
    cov = _cov(
        endpoints=[{"id": "ep1", "method": "GET", "path": "/companies"}],
        matrix=[{"endpoint_id": "ep1", "param": "_endpoint", "param_type": "endpoint",
                 "injection_type": "cors"}],
    )
    assert _underregistered_endpoints_blocker(cov, coverage_enforced=True) is None


def test_gate_ignores_write_endpoint_that_has_params():
    cov = _cov(
        endpoints=[{"id": "ep1", "method": "POST", "path": "/login"}],
        matrix=[{"endpoint_id": "ep1", "param": "username", "param_type": "body_form",
                 "injection_type": "sqli"}],
    )
    assert _underregistered_endpoints_blocker(cov, coverage_enforced=True) is None


def test_gate_advisory_when_not_enforced():
    cov = _cov(
        endpoints=[{"id": "ep1", "method": "POST", "path": "/login"}],
        matrix=[{"endpoint_id": "ep1", "param": "_endpoint", "param_type": "endpoint",
                 "injection_type": "cors"}],
    )
    assert _underregistered_endpoints_blocker(cov, coverage_enforced=False) is None
