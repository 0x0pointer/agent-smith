"""Phase 2 of depth=danger (docs/plan-danger-depth.md): deep post-exploit pivot.

When SSRF/RCE reveals internal hosts, a deep-pivot scan (depth=danger /
scan_mode=benchmark) promotes them to assets + per-host scan surfaces and blocks
completion until they're scanned; a normal scan raises a wishlist scope-approval.
"""
import pytest

import core.session as scan_session
import core.wishlist as wl
from core import pivot, netextract
from core.session import surface_ledger as ledger
from mcp_server.session_tools.completion_gates import _deep_pivot_host_blocker

# SSRF evidence naming internal hosts (+ a public IP that must NOT be promoted).
SSRF_TEXT = ("SSRF via /upload_profile_picture_url reached https://10.110.32.1:443/version "
             "and the Flask app pod 10.150.0.158:5000 OPEN; resolver is 8.8.8.8 (public)")


@pytest.fixture
def danger_session(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
    scan_session._current = None
    scan_session.start("http://perimeter.test:30081", depth="danger")
    yield
    scan_session._current = None


@pytest.fixture
def normal_session(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
    monkeypatch.setattr(wl, "_WISHLIST_FILE", tmp_path / "wishlist.json")
    scan_session._current = None
    scan_session.start("http://perimeter.test:30081", depth="thorough")
    yield
    scan_session._current = None


# ── netextract ──────────────────────────────────────────────────────────────

def test_extract_internal_hosts_only_internal():
    hosts = netextract.extract_internal_hosts(SSRF_TEXT)
    assert "10.110.32.1" in hosts and "10.150.0.158" in hosts   # :port collapsed
    assert "8.8.8.8" not in hosts                               # public excluded


def test_extract_metadata_and_cluster_hosts():
    t = "fetched http://169.254.169.254/latest/meta-data/ and kubernetes.default.svc.cluster.local"
    hosts = netextract.extract_internal_hosts(t)
    assert "169.254.169.254" in hosts
    assert any("cluster.local" in h for h in hosts)


def test_looks_like_ip():
    assert netextract.looks_like_ip("10.150.0.158")
    assert not netextract.looks_like_ip("kubernetes.default.svc.cluster.local")


# ── promotion (deep-pivot) ────────────────────────────────────────────────────

def test_promote_internal_hosts_danger(danger_session):
    promoted = pivot.promote_internal_hosts(SSRF_TEXT, source="test")
    assert set(promoted) == {"10.110.32.1", "10.150.0.158"}
    ka = scan_session.get()["known_assets"]
    assert "10.110.32.1" in ka["ips"] and "10.150.0.158" in ka["ips"]
    # per-host scan surface recorded for network-assess
    assert set(ledger.pending("network-assess")) == {"10.110.32.1", "10.150.0.158"}
    # internal_network gate opened
    assert any(g.get("id") == "internal_network" for g in scan_session.pending_gates())


def test_promote_excludes_known_and_target(danger_session):
    scan_session.update_known_assets("ips", ["10.0.0.9"])   # already known
    promoted = pivot.promote_internal_hosts("reached 10.0.0.9 and new host 10.1.2.3")
    assert promoted == ["10.1.2.3"]                          # known one skipped


def test_promote_excludes_out_of_scope(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "s.json")
    scan_session._current = None
    scan_session.start("http://p.test", depth="danger", out_of_scope=["10.9.9.9"])
    try:
        assert pivot.promote_internal_hosts("hosts 10.9.9.9 and 10.8.8.8") == ["10.8.8.8"]
    finally:
        scan_session._current = None


def test_promote_noop_when_not_deep_pivot(normal_session):
    assert pivot.promote_internal_hosts(SSRF_TEXT) == []
    assert scan_session.get()["known_assets"]["ips"] == []


# ── normal scan → wishlist scope-ask ────────────────────────────────────────────

def test_normal_scan_raises_wishlist_scope(normal_session):
    hosts = pivot.request_pivot_scope(SSRF_TEXT, source="test")
    assert set(hosts) == {"10.110.32.1", "10.150.0.158"}
    opens = wl.wishlist_queue.list_open()
    assert any(getattr(i, "category", "") == "scope" for i in opens)


def test_request_pivot_scope_noop_under_deep_pivot(danger_session):
    assert pivot.request_pivot_scope(SSRF_TEXT) == []


def test_handle_routes_deep_pivot_to_promotion(danger_session):
    pivot.handle_internal_host_discovery(SSRF_TEXT)
    assert scan_session.get()["known_assets"]["ips"]           # promoted, not wishlisted


# ── completion blocker (2c) ─────────────────────────────────────────────────────

def test_deep_pivot_blocker_fires_then_clears(danger_session):
    assert _deep_pivot_host_blocker() is None                  # nothing discovered yet
    pivot.promote_internal_hosts(SSRF_TEXT)
    b = _deep_pivot_host_blocker()
    assert b and "not yet scanned" in b and "10.150.0.158" in b
    for h in ("10.110.32.1", "10.150.0.158"):
        ledger.record_covered("network-assess", h)            # scanned each
    assert _deep_pivot_host_blocker() is None                  # discharged


def test_deep_pivot_blocker_noop_for_normal_scan(normal_session):
    pivot.request_pivot_scope(SSRF_TEXT)
    assert _deep_pivot_host_blocker() is None


def test_do_complete_blocks_danger_on_unscanned_hosts(danger_session):
    """Integration: a danger scan routes through the thorough gate — verify the host
    blocker is checked FIRST in _do_complete so it actually blocks completion there."""
    from mcp_server.session_tools import _do_complete
    pivot.promote_internal_hosts(SSRF_TEXT)
    resp = _do_complete()
    assert "DEEP-PIVOT" in resp and "not yet scanned" in resp     # blocked on the thorough path
    for h in ("10.110.32.1", "10.150.0.158"):
        ledger.record_covered("network-assess", h)                # scan each host
    assert "not yet scanned" not in _do_complete()                # deep-pivot block cleared
