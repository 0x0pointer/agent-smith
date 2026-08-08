"""
Tests for core.target_class.classify_target and its advisory wiring into
_do_start (it must surface a recommendation and tailor the first move without
gating the LLM's skill choice).
"""
import pytest

from core.target_class import classify_target
from mcp_server.session_tools import _do_start


# ── pure classifier ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("target,kind,skill", [
    ("./src", "codebase", "/codebase"),
    ("/Users/me/project", "codebase", "/codebase"),
    ("~/work/app", "codebase", "/codebase"),
    ("C:\\code\\app", "codebase", "/codebase"),
    ("arn:aws:iam::123456789012:role/admin", "cloud", "/cloud-security"),
    ("https://my-bucket.s3.amazonaws.com", "cloud", "/cloud-security"),
    ("https://app.azurewebsites.net", "cloud", "/cloud-security"),
    ("10.0.0.0/24", "network", "/network-assess"),
    ("192.168.1.10", "network", "/network-assess"),
    ("10.0.0.1-10.0.0.50", "network", "/network-assess"),
    ("https://api.example.com/graphql", "api", "/api-security"),
    ("https://example.com/api/v2/users", "api", "/api-security"),
    ("https://example.com/swagger.json", "api", "/api-security"),
    ("https://example.com", "web", "/web-exploit"),
    ("https://shop.example.com/products", "web", "/web-exploit"),
    ("", "web", "/web-exploit"),
])
def test_classify_target_kinds(target, kind, skill):
    out = classify_target(target)
    assert out["kind"] == kind
    assert out["skill_prior"] == skill
    assert out["reason"]


def test_classify_target_shape():
    out = classify_target("https://example.com")
    assert set(out) == {"kind", "boot_tools", "skill_prior", "reason"}
    assert isinstance(out["boot_tools"], list)


def test_classify_target_codebase_not_treated_as_host():
    # A path must never be classified as a network/web host.
    assert classify_target("/etc/app")["kind"] == "codebase"


# ── advisory wiring into _do_start (no gating) ──────────────────────────────────

def test_do_start_surfaces_classification_and_persists(coverage_file):
    import core.session as scan_session
    result = _do_start({"target": "10.0.0.0/24", "depth": "recon"})
    # Advisory line present, recommends the network skill, and tailors the first move.
    assert "Target classification" in result
    assert "/network-assess" in result
    assert "scan(tool='naabu'" in result
    # Persisted for the dashboard.
    assert (scan_session.get() or {}).get("classifier", {}).get("kind") == "network"


def test_do_start_codebase_first_move_is_set_codebase(coverage_file):
    result = _do_start({"target": "./src", "depth": "recon"})
    assert "kind=codebase" in result
    assert "set_codebase" in result
    # A codebase target must NOT be greeted with an httpx web scan as the first move.
    assert "scan(tool='httpx', target='./src')" not in result


def test_do_start_web_default_unchanged(coverage_file):
    result = _do_start({"target": "https://example.com", "depth": "recon"})
    assert "kind=web" in result
    assert "scan(tool='httpx', target='https://example.com')" in result
