"""IMPROVEMENT-PLAN 1.1 — a re-issued start() must never clobber a LIVE scan.

Root cause: two paths call the low-level ``session.start()`` when this process's
in-memory cache looks empty/not-running — the scan-tools auto-start (which passes the
TOOL's target, often a promoted pivot host, and depth='thorough') and a re-issued
``session(action='start')`` from a RESPAWNED MCP process. Either silently reset a live
danger run's ``target``/``depth`` and wiped ``known_assets`` + the wishlist.

The guard: ``resume_if_running()`` reconciles with disk and, when a scan is still running,
callers resume it in place instead of re-initialising.
"""
import core.session as scan_session
import core.wishlist as wl
from mcp_server.scan_tools import _ensure_session_for_tool
from mcp_server.session_tools.start import _do_start


def _start_live_danger(tmp_path, monkeypatch, target="http://app.test:30081"):
    """Start a danger scan, seed known_assets + a wishlist item, then simulate a
    RESPAWNED MCP process (fresh in-memory cache) by dropping _current. Disk keeps the
    running session."""
    monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
    monkeypatch.setattr(wl, "_WISHLIST_FILE", tmp_path / "wishlist.json")
    scan_session._current = None
    scan_session.start(target, depth="danger")
    scan_session.update_known_assets("ips", ["10.150.0.158"])
    scan_session.update_known_assets("credentials", [{"username": "admin", "password": "x", "source": "t"}])
    wl.wishlist_queue.add(need="Deep-pivot ACTIVE", category="scope", rationale="r")
    # Respawn: new process, cache not populated, no local write recorded yet.
    scan_session._current = None
    monkeypatch.setattr(scan_session, "_last_local_write_mtime", 0.0)


# ── resume_if_running() ───────────────────────────────────────────────────────

def test_resume_if_running_none_when_no_session(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
    scan_session._current = None
    assert scan_session.resume_if_running() is None


def test_resume_if_running_loads_live_scan_from_disk(tmp_path, monkeypatch):
    _start_live_danger(tmp_path, monkeypatch)
    live = scan_session.resume_if_running()
    assert live is not None
    assert live["target"] == "http://app.test:30081"
    assert live["depth"] == "danger"
    assert "10.150.0.158" in live["known_assets"]["ips"]


def test_resume_if_running_none_for_terminal_scan(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
    scan_session._current = None
    scan_session.start("http://app.test", depth="danger")
    scan_session.complete(notes="done")
    scan_session._current = None
    monkeypatch.setattr(scan_session, "_last_local_write_mtime", 0.0)
    assert scan_session.resume_if_running() is None   # complete → not resumable


# ── scan-tools auto-start guard ───────────────────────────────────────────────

def test_autostart_resumes_live_scan_not_clobber(tmp_path, monkeypatch):
    """The clobber scenario: a scan tool fires against a PIVOT host in a respawned process.
    The auto-start must resume the live danger scan, not reset target→pivot/depth→thorough."""
    _start_live_danger(tmp_path, monkeypatch)
    # scan(tool=..., target='kubernetes.default...') on the pivot host, respawned process.
    _ensure_session_for_tool("http://kubernetes.default.svc.cluster.local:443")
    cur = scan_session.get()
    assert cur["target"] == "http://app.test:30081"      # NOT the pivot host
    assert cur["depth"] == "danger"                       # NOT downgraded to thorough
    assert "10.150.0.158" in cur["known_assets"]["ips"]   # assets preserved
    # wishlist preserved (start() would have cleared it)
    assert any("Deep-pivot" in i.need for i in wl.WishlistQueue().list_open())


def test_autostart_fresh_when_no_live_scan(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
    scan_session._current = None
    _ensure_session_for_tool("http://new.test")
    cur = scan_session.get()
    assert cur and cur["target"] == "http://new.test" and cur["depth"] == "thorough"


def test_autostart_noop_when_already_running_in_process(tmp_path, monkeypatch):
    """Same-process live scan: get() already shows running, so no disk round-trip or reset."""
    monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
    scan_session._current = None
    scan_session.start("http://app.test", depth="danger")
    _ensure_session_for_tool("http://pivot.test")
    assert scan_session.get()["target"] == "http://app.test"
    assert scan_session.get()["depth"] == "danger"


# ── _do_start operator path ───────────────────────────────────────────────────

def test_do_start_same_target_resumes_in_place(tmp_path, monkeypatch):
    _start_live_danger(tmp_path, monkeypatch)
    resp = _do_start({"target": "http://app.test:30081", "depth": "danger"})
    assert "RESUME" in resp
    cur = scan_session.get()
    assert cur["depth"] == "danger"
    assert "10.150.0.158" in cur["known_assets"]["ips"]      # not wiped
    assert any("Deep-pivot" in i.need for i in wl.WishlistQueue().list_open())  # wishlist kept


def test_do_start_different_target_refused_while_running(tmp_path, monkeypatch):
    _start_live_danger(tmp_path, monkeypatch)
    resp = _do_start({"target": "http://other.test", "depth": "thorough"})
    assert "REFUSED" in resp and "still RUNNING" in resp and "force_restart" in resp
    # untouched: the live scan keeps its target/depth/assets
    cur = scan_session.get()
    assert cur["target"] == "http://app.test:30081" and cur["depth"] == "danger"
    assert "10.150.0.158" in cur["known_assets"]["ips"]


def test_do_start_force_restart_replaces_running(tmp_path, monkeypatch):
    _start_live_danger(tmp_path, monkeypatch)
    resp = _do_start({"target": "http://other.test", "depth": "standard", "force_restart": True})
    assert "Scan started" in resp
    cur = scan_session.get()
    assert cur["target"] == "http://other.test" and cur["depth"] == "standard"
    assert cur["known_assets"]["ips"] == []                  # genuine fresh start
