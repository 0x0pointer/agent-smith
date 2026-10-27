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


def test_loopback_and_linklocal_not_promoted():
    # 127.x (scanner/target localhost) and generic link-local are NOT pivot targets;
    # the two real cloud-metadata IPs are still kept (via _META_HOSTS).
    assert netextract.scannable_internal_ip("10.150.0.158")
    assert not netextract.scannable_internal_ip("127.0.0.1")
    assert not netextract.scannable_internal_ip("169.254.1.5")
    hosts = netextract.extract_internal_hosts(
        "SSRF hit 127.0.0.1:5000/internal and a pod 10.150.0.158:5000; IMDS 169.254.169.254")
    assert "10.150.0.158" in hosts
    assert "127.0.0.1" not in hosts
    assert "169.254.169.254" in hosts        # IMDS kept via metadata-host branch


def test_promote_excludes_loopback_under_danger(danger_session):
    promoted = pivot.promote_internal_hosts("reached 127.0.0.1:5000 and pod 10.9.9.9", source="t")
    assert promoted == ["10.9.9.9"]           # 127.0.0.1 not promoted
    assert "127.0.0.1" not in scan_session.get()["known_assets"]["ips"]


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
    # No host reached yet → TUNNEL-FIRST message (not the per-host 'scan each' churn).
    assert b and "DEEP-PIVOT" in b and "10.150.0.158" in b and "reached yet" in b and "chisel" in b
    for h in ("10.110.32.1", "10.150.0.158"):
        ledger.record_covered("network-assess", h)            # scanned each
    assert _deep_pivot_host_blocker() is None                  # discharged


def test_blocker_is_tunnel_first_until_a_host_is_reached(danger_session):
    """Fix 1: while NO internal host has been reached, the blocker must steer to a single tunnel
    (not per-host retries from Kali); once a host IS reached, it switches to 'scan each through it'."""
    pivot.promote_internal_hosts("hosts 10.30.30.1 and 10.30.30.2 and 10.30.30.3")
    b1 = _deep_pivot_host_blocker()
    assert b1 and "reached yet" in b1 and ("chisel" in b1 or "ssh -D" in b1)   # tunnel-first
    assert "A pivot path EXISTS" not in b1
    ledger.record_host_scanned("10.30.30.1", reached=True)     # a route now exists
    b2 = _deep_pivot_host_blocker()
    assert b2 and "A pivot path EXISTS" in b2 and "not yet scanned" in b2       # scan-each wording
    assert "reached yet" not in b2


def test_unreachable_hosts_reopen_when_a_new_vuln_reaches_one(danger_session):
    """User scenario: hosts unreachable via the FIRST vuln (e.g. blind SSRF) must be RE-OPENED for
    a re-probe once a LATER, better primitive proves reachability changed — not left permanently
    dead-ended. The reached host flips to covered; the others return to pending."""
    from mcp_server.session_tools.completion_gates import _deep_pivot_host_blocker
    pivot.promote_internal_hosts("hosts 10.9.9.1 and 10.9.9.2 and 10.9.9.3")
    for h in ("10.9.9.1", "10.9.9.2", "10.9.9.3"):
        ledger.record_host_scanned(h, reached=False)        # vuln A reaches none of them
    assert ledger.host_scan_pending() == []                 # all discharged (scan could finish here)

    ledger.record_host_scanned("10.9.9.1", reached=True)     # vuln B (new primitive) reaches one
    na = scan_session.get()["surface_coverage"]["network-assess"]
    assert "10.9.9.1" in na["covered"] and "10.9.9.1" not in na["unreachable"]
    assert set(ledger.host_scan_pending()) == {"10.9.9.2", "10.9.9.3"}   # others re-opened to re-probe
    b = _deep_pivot_host_blocker()
    assert b and "A pivot path EXISTS" in b                  # steers to scan-each-through-the-pivot


def test_reopen_is_bounded_no_improvement_no_reopen(danger_session):
    """The re-open fires only on a PROVEN reachability improvement — a plain unreachable mark does
    not resurrect already-dead-ended hosts (so it can't loop on genuinely dead hosts)."""
    pivot.promote_internal_hosts("hosts 10.8.8.1 and 10.8.8.2")
    ledger.record_host_scanned("10.8.8.1", reached=True)     # first route (improvement → reopen, nothing to reopen yet)
    ledger.record_host_scanned("10.8.8.2", reached=False)    # 10.8.8.2 dead-ends
    assert ledger.host_scan_pending() == []
    # a SECOND reach on the already-covered host is NOT an improvement → 10.8.8.2 stays dead-ended
    ledger.record_host_scanned("10.8.8.1", reached=True)
    assert ledger.host_scan_pending() == []


def test_scanner_infra_never_promoted(danger_session):
    """Fix 2: the scanner's own Docker fabric (Kali container IP, Docker Desktop gateway,
    *.docker.internal) is never promoted as a pivot target; real internal + corp-LAN hosts are."""
    promoted = pivot.promote_internal_hosts(
        "SSRF saw 172.17.0.2 (kali self), 192.168.65.7 gw, host.docker.internal, "
        "real pod 10.44.0.9 and corp host 192.168.1.50")
    assert "10.44.0.9" in promoted and "192.168.1.50" in promoted
    assert not any(x in promoted for x in ("172.17.0.2", "192.168.65.7", "host.docker.internal"))
    ips = scan_session.get()["known_assets"]["ips"]
    assert "172.17.0.2" not in ips and "192.168.65.7" not in ips


def test_registered_scanner_own_ip_excluded_but_real_10x_promoted(danger_session):
    """IMPROVEMENT-PLAN 1.2: the Kali container's OWN bridge IP (resolved at runtime, lives in
    10.0.0.0/8) is excluded as an exact /32 — WITHOUT a CIDR that would blind genuine 10.x /
    172.16 pivot targets."""
    try:
        netextract.register_scanner_own_ips(["10.110.0.3"])   # what the Kali runner registers
        assert "10.110.0.3" in netextract.scanner_own_ips()
        assert not netextract.scannable_internal_ip("10.110.0.3")   # own IP → not a target
        promoted = pivot.promote_internal_hosts(
            "SSRF saw the scanner 10.110.0.3, a real pod 10.44.0.9, and corp host 172.16.5.9")
        assert "10.110.0.3" not in promoted                   # exact scanner IP excluded
        assert "10.44.0.9" in promoted and "172.16.5.9" in promoted   # real 10.x/172.16 still promoted
    finally:
        netextract.clear_scanner_own_ips()


def test_k8s_dns_variants_collapse_across_calls(danger_session):
    """Fix 2: a K8s service short-name and its FQDN are ONE host, not several."""
    first = pivot.promote_internal_hosts("reached kubernetes.default")
    again = pivot.promote_internal_hosts("later kubernetes.default.svc.cluster.local")
    assert first == ["kubernetes.default"]
    assert again == []                      # FQDN variant of an already-promoted service
    domains = scan_session.get()["known_assets"].get("domains", [])
    assert sum("kubernetes.default" in d for d in domains) == 1


def test_danger_pivot_raises_single_operator_notice(danger_session, monkeypatch, tmp_path):
    """Fix 5: danger auto-pivots, but surfaces ONE non-blocking operator FYI (deduped by stable
    text → one notice no matter how many hosts stream in), so the operator can see/de-scope it."""
    import core.wishlist as wl
    monkeypatch.setattr(wl, "_WISHLIST_FILE", tmp_path / "wl.json")
    pivot.promote_internal_hosts("pod 10.55.0.1")
    pivot.promote_internal_hosts("pod 10.55.0.2")       # a second batch later
    open_items = wl.WishlistQueue().list_open()
    assert len(open_items) == 1                          # ONE notice regardless of host count
    assert "Deep-pivot ACTIVE" in open_items[0].need and open_items[0].category == "scope"


def test_normal_scan_has_no_pivot_notice_but_asks_approval(normal_session, monkeypatch, tmp_path):
    """Fix 5 boundary: a NORMAL scan keeps the approval wishlist (request_pivot_scope), NOT the
    danger auto-pivot FYI — the two paths stay distinct."""
    import core.wishlist as wl
    monkeypatch.setattr(wl, "_WISHLIST_FILE", tmp_path / "wl.json")
    pivot.handle_internal_host_discovery("pod 10.66.0.1", source="ssrf")
    needs = [i.need for i in wl.WishlistQueue().list_open()]
    assert any("Approve internal pivot" in n for n in needs)
    assert not any("Deep-pivot ACTIVE" in n for n in needs)


def test_deep_pivot_blocker_noop_for_normal_scan(normal_session):
    pivot.request_pivot_scope(SSRF_TEXT)
    assert _deep_pivot_host_blocker() is None


def test_dismiss_internal_network_refused_while_hosts_pending(danger_session):
    from mcp_server.session_tools.skills import _internal_network_dismiss_refusal
    pivot.promote_internal_hosts("pod 10.6.6.6")
    msg = _internal_network_dismiss_refusal("internal_network")
    assert msg and "REFUSED" in msg and "10.6.6.6" in msg
    ledger.record_host_scanned("10.6.6.6", reached=True)        # scanned → dischargeable
    assert _internal_network_dismiss_refusal("internal_network") is None
    assert _internal_network_dismiss_refusal("some_other_gate") is None   # guard is scoped


def test_recovery_next_call_steers_to_pending_host(danger_session):
    from mcp_server.session_tools.recovery_build import _deep_pivot_next_call
    assert _deep_pivot_next_call() is None                      # nothing pending yet
    pivot.promote_internal_hosts("pod 10.8.8.8")
    call = _deep_pivot_next_call()
    assert call and "DEEP-PIVOT resume" in call and "naabu" in call


def test_resume_restores_surface_coverage(danger_session):
    # a prior engagement's ledger (discovered internal hosts) is carried forward on resume,
    # so the pivot obligation survives instead of being silently dropped.
    from mcp_server.report_tools.coverage import _restore_prior_surface_coverage
    prior = {"surface_coverage": {"network-assess": {
        "unit": "host", "discovered": ["10.20.20.1", "10.20.20.2"],
        "covered": ["10.20.20.1"], "unreachable": []}}}
    n = _restore_prior_surface_coverage(prior, [])
    assert n == 3                                               # 2 discovered + 1 covered merged
    assert ledger.host_scan_pending() == ["10.20.20.2"]        # obligation restored (1 still owed)


def test_host_scanned_reached_covers_all_host_skills(danger_session):
    pivot.promote_internal_hosts("pod 10.1.1.1 and pod 10.2.2.2")
    assert set(ledger.host_scan_pending()) == {"10.1.1.1", "10.2.2.2"}
    ledger.record_host_scanned("10.1.1.1", reached=True)
    for sk in ledger.HOST_UNIT_SKILLS:           # credited across ALL host-unit skills (mis-attribution fix)
        assert "10.1.1.1" not in ledger.pending(sk)
    assert ledger.host_scan_pending() == ["10.2.2.2"]


def test_host_scanned_unreachable_is_dead_end_not_covered(danger_session):
    pivot.promote_internal_hosts("pod 10.3.3.3")
    ledger.record_host_scanned("10.3.3.3", reached=False)
    na = scan_session.get()["surface_coverage"]["network-assess"]
    assert ledger.host_scan_pending() == []                 # dead-end → no longer blocks
    assert "10.3.3.3" not in na.get("covered", [])          # but NOT falsely "covered"
    assert "10.3.3.3" in na.get("unreachable", [])          # recorded honestly as unreachable


def test_blocker_clears_on_reached_or_unreachable(danger_session):
    from mcp_server.session_tools.completion_gates import _deep_pivot_host_blocker
    pivot.promote_internal_hosts("hosts 10.4.4.4 and 10.5.5.5")
    assert _deep_pivot_host_blocker()                        # blocked (2 pending)
    ledger.record_host_scanned("10.4.4.4", reached=True)     # reached
    ledger.record_host_scanned("10.5.5.5", reached=False)    # documented unreachable
    assert _deep_pivot_host_blocker() is None                # both resolved


def test_envelope_promotes_and_covers_from_scan_output(danger_session):
    import mcp_server.scan_engine.envelope as env

    class R:
        summary = "naabu Found 1 open port(s): 5000 on 10.7.7.7"
        evidence = {"ports": [5000], "hosts": ["10.7.7.7"]}
    # promotion now fires from a SCAN tool's output (not just a finding/http_request)...
    env._deep_pivot_host_tracking("naabu", R(), {"host": "10.7.7.7", "command": "naabu -host 10.7.7.7"}, R.summary)
    assert "10.7.7.7" in scan_session.get()["known_assets"]["ips"]
    # ...and because the scan REACHED it (open port), it's credited as covered, not pending
    assert "10.7.7.7" not in ledger.host_scan_pending()


def test_do_complete_blocks_danger_on_unscanned_hosts(danger_session):
    """Integration: a danger scan routes through the thorough gate — verify the host
    blocker is checked FIRST in _do_complete so it actually blocks completion there."""
    from mcp_server.session_tools import _do_complete
    pivot.promote_internal_hosts(SSRF_TEXT)
    resp = _do_complete()
    assert "DEEP-PIVOT" in resp and "reached yet" in resp         # blocked (tunnel-first, no reach)
    for h in ("10.110.32.1", "10.150.0.158"):
        ledger.record_covered("network-assess", h)                # scan each host
    assert "DEEP-PIVOT" not in _do_complete()                     # deep-pivot block cleared
