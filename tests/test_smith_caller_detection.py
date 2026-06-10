"""
Tests for the Smith-caller detection wired into session.start().

The watchdog used to rely on quick_log.json mtime + a PID file written only
by dashboard-spawned restarts. Interactive runs (operator launches
opencode/claude themselves) didn't update the PID file, and long thinking-
mode reasoning aged the mtime past the 180s "active" threshold — producing
"Smith stopped while scan running" false positives.

These tests cover the fix: at session.start(), inspect TCP connections to
the MCP SSE port (7778) via psutil and persist the real driving PID + client
into logs/smith.pid + logs/smith.client so _smith_running() resolves to an
exact process check.

The detection now uses psutil (cross-platform), not lsof + ps.
"""
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
import psutil

from core import session as scan_session


# ---------------------------------------------------------------------------
# Helpers — build fake psutil connections / processes
# ---------------------------------------------------------------------------

def _fake_conn(pid: int, local_port: int | None, remote_port: int | None,
               status: str = "ESTABLISHED"):
    """Construct a psutil-shaped sconn for connection mocking. The mocked
    object's ``pid`` field is informational only — the new _connected_pids()
    iterates processes and asks each for its own connection list, so the
    PID is carried on the parent ``Process`` mock, not on the connection."""
    laddr = MagicMock(); laddr.port = local_port
    raddr = MagicMock(); raddr.port = remote_port
    return MagicMock(
        pid=pid,
        status=psutil.CONN_ESTABLISHED if status == "ESTABLISHED" else status,
        laddr=laddr if local_port is not None else None,
        raddr=raddr if remote_port is not None else None,
    )


def _fake_proc(cmdline: str, pid: int | None = None, conns: list | None = None):
    """Build a psutil.Process-shaped mock with a stable ``pid``, an iterable
    ``net_connections`` method, and a ``cmdline`` that returns the parsed
    argv. ``conns`` defaults to empty so callers that don't care about the
    connection signal can omit it."""
    p = MagicMock()
    p.pid = pid if pid is not None else 0
    p.cmdline.return_value = cmdline.split()
    p.net_connections.return_value = conns or []
    p.connections.return_value = conns or []   # legacy alias
    return p


def _patch_process_iter(processes):
    """Return a context manager that patches psutil.process_iter to return
    the given mocked processes. Used by _connected_pids to walk processes
    and inspect their connections."""
    return patch("psutil.process_iter", return_value=processes)


# ---------------------------------------------------------------------------
# _detect_smith_caller — pure detection logic
# ---------------------------------------------------------------------------

class TestDetectSmithCaller:
    """Each test builds a list of fake Process mocks (each with its own
    ``net_connections`` list + cmdline), patches ``psutil.process_iter`` to
    yield them, and asserts the caller-detection result. This mirrors the
    refactored production code: we walk processes, not the system-wide
    socket table (which on macOS / Windows needs admin)."""

    def test_detects_opencode_via_tcp(self, monkeypatch):
        proc = _fake_proc(
            "/Users/u/.opencode/bin/opencode run scan x",
            pid=98765,
            conns=[_fake_conn(98765, local_port=44444, remote_port=7778)],
        )
        with _patch_process_iter([proc]), \
             patch("psutil.Process", return_value=proc):
            got = scan_session._detect_smith_caller()
        assert got == {"pid": 98765, "client": "opencode"}

    def test_detects_claude_via_tcp(self, monkeypatch):
        proc = _fake_proc(
            "/opt/homebrew/bin/claude --dangerously-skip-permissions -p prompt",
            pid=12345,
            conns=[_fake_conn(12345, local_port=33333, remote_port=7778)],
        )
        with _patch_process_iter([proc]), \
             patch("psutil.Process", return_value=proc):
            got = scan_session._detect_smith_caller()
        assert got == {"pid": 12345, "client": "claude"}

    def test_detects_codex_via_tcp(self, monkeypatch):
        proc = _fake_proc(
            "/usr/local/bin/codex mcp pentest-agent --run",
            pid=55555,
            conns=[_fake_conn(55555, local_port=22222, remote_port=7778)],
        )
        with _patch_process_iter([proc]), \
             patch("psutil.Process", return_value=proc):
            got = scan_session._detect_smith_caller()
        assert got == {"pid": 55555, "client": "codex"}

    def test_skips_unrelated_processes(self, monkeypatch):
        """The MCP server's own PID, vLLM workers, etc. must NOT be picked.
        Each connects to the same port but their cmdlines don't match a
        known Smith client pattern."""
        # MCP server side (local 7778, remote ephemeral)
        server = _fake_proc(
            "/usr/bin/python3 -m mcp_server --transport sse",
            pid=1000,
            conns=[_fake_conn(1000, local_port=7778, remote_port=44440)],
        )
        vllm = _fake_proc(
            "/usr/bin/python3 /usr/local/bin/vllm serve --port 7778",
            pid=2000,
            conns=[_fake_conn(2000, local_port=55550, remote_port=7778)],
        )
        other = _fake_proc(
            "node /Users/u/something-else.js",
            pid=3000,
            conns=[_fake_conn(3000, local_port=66660, remote_port=7778)],
        )
        process_lookup = {p.pid: p for p in (server, vllm, other)}

        def _proc(pid):
            return process_lookup.get(pid,
                                       MagicMock(cmdline=MagicMock(return_value=[])))

        with _patch_process_iter([server, vllm, other]), \
             patch("psutil.Process", side_effect=_proc), \
             patch("os.getppid", return_value=99999):
            got = scan_session._detect_smith_caller()
        assert got is None

    def test_handles_psutil_missing(self, monkeypatch):
        """Some Windows setups may not have psutil installed; detection
        gracefully returns None instead of raising."""
        import builtins
        real_import = builtins.__import__

        def _no_psutil(name, *a, **kw):
            if name == "psutil":
                raise ImportError("psutil unavailable")
            return real_import(name, *a, **kw)

        with patch("builtins.__import__", side_effect=_no_psutil):
            got = scan_session._detect_smith_caller()
        assert got is None

    def test_handles_per_process_access_denied(self, monkeypatch):
        """When a process raises AccessDenied during inspection (e.g. a
        SYSTEM-owned process on Windows), the iteration must continue and
        find the real Smith client among the others — not bail out entirely."""
        # First process raises (privileged), second is the actual opencode
        privileged = MagicMock()
        privileged.pid = 100
        privileged.net_connections.side_effect = psutil.AccessDenied(pid=100)
        privileged.connections.side_effect = psutil.AccessDenied(pid=100)

        opencode = _fake_proc(
            "/Users/u/.opencode/bin/opencode run x",
            pid=200,
            conns=[_fake_conn(200, local_port=33333, remote_port=7778)],
        )
        process_lookup = {200: opencode}

        with _patch_process_iter([privileged, opencode]), \
             patch("psutil.Process", side_effect=lambda pid: process_lookup.get(pid, MagicMock())):
            got = scan_session._detect_smith_caller()
        assert got == {"pid": 200, "client": "opencode"}

    def test_stdio_fallback_picks_parent_when_no_tcp(self, monkeypatch):
        """Codex stdio transport: no TCP connection to inspect — fallback to
        the parent process, which is the client."""
        # No processes have a 7778 connection
        with _patch_process_iter([]), \
             patch("psutil.Process",
                   return_value=_fake_proc("/usr/local/bin/codex run --mcp")), \
             patch("os.getppid", return_value=424242):
            got = scan_session._detect_smith_caller()
        assert got == {"pid": 424242, "client": "codex"}

    def test_skips_non_established_connections(self, monkeypatch):
        """LISTEN, CLOSE_WAIT, etc. should be ignored — we only want active
        client connections (ESTABLISHED). A process that's only listening
        on 7778 (e.g. the MCP server itself) shouldn't get picked as the
        caller even if no other process is connected."""
        listening = _fake_proc(
            "/some/server",
            pid=1111,
            conns=[_fake_conn(1111, local_port=7778, remote_port=None,
                               status="LISTEN")],
        )
        with _patch_process_iter([listening]), \
             patch("os.getppid", return_value=99999):
            got = scan_session._detect_smith_caller()
        assert got is None

    def test_detects_node_wrapped_opencode(self, monkeypatch):
        """opencode is commonly invoked via `node /Users/u/.opencode/bin/opencode`.
        The process name is 'node' (or 'node-bin' on some installs) — the
        cmdline anchor is the .opencode/bin/opencode path."""
        proc = _fake_proc(
            "node /Users/gibson/.opencode/bin/opencode run scan target",
            pid=77777,
            conns=[_fake_conn(77777, local_port=55555, remote_port=7778)],
        )
        with _patch_process_iter([proc]), \
             patch("psutil.Process", return_value=proc):
            got = scan_session._detect_smith_caller()
        assert got == {"pid": 77777, "client": "opencode"}

    def test_detects_npm_dist_opencode(self, monkeypatch):
        """npm-installed opencode runs from /opencode/dist/index.js."""
        proc = _fake_proc(
            "node /usr/local/lib/node_modules/opencode/dist/index.js run x",
            pid=88888,
            conns=[_fake_conn(88888, local_port=44444, remote_port=7778)],
        )
        with _patch_process_iter([proc]), \
             patch("psutil.Process", return_value=proc):
            got = scan_session._detect_smith_caller()
        assert got == {"pid": 88888, "client": "opencode"}

    def test_macos_no_admin_per_process_works(self, monkeypatch):
        """The bug that motivated the rewrite: on macOS without admin,
        psutil.net_connections() system-wide silently returns []. The
        per-process iteration we use now MUST still find the Smith client
        — that's the whole point. Simulate it by having process_iter return
        a real-looking opencode process whose own net_connections() works
        (because Process.net_connections() works without admin for processes
        owned by the current user)."""
        proc = _fake_proc(
            "/Users/u/.opencode/bin/opencode run /pentester scan x",
            pid=42424,
            conns=[_fake_conn(42424, local_port=62020, remote_port=7778)],
        )
        with _patch_process_iter([proc]), \
             patch("psutil.Process", return_value=proc):
            got = scan_session._detect_smith_caller()
        assert got == {"pid": 42424, "client": "opencode"}


# ---------------------------------------------------------------------------
# Lazy PID refresh on mutations
# ---------------------------------------------------------------------------

class TestLazyPidRefresh:
    """When logs/smith.pid points at a dead PID (because Smith died and
    respawned outside the dashboard's restart path), the next mutation
    should detect a live caller and rewrite the file. Catches the false-
    positive "Smith stopped" alerts the user was hitting."""

    @pytest.fixture
    def isolated(self, tmp_path, monkeypatch):
        monkeypatch.setattr(scan_session, "_REPO_ROOT", tmp_path)
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        scan_session._current = None
        scan_session._last_local_write_mtime = 0.0
        scan_session._last_pid_refresh_attempt = 0.0
        yield tmp_path
        scan_session._current = None
        scan_session._last_local_write_mtime = 0.0
        scan_session._last_pid_refresh_attempt = 0.0

    def test_refresh_skips_when_tracked_pid_is_alive(self, isolated, monkeypatch):
        """No-op when smith.pid points at a live process — common hot path."""
        (isolated / "logs").mkdir()
        (isolated / "logs" / "smith.pid").write_text("12345")
        # Stub _detect_smith_caller so any unexpected invocation raises a
        # detectable mismatch — proves we short-circuit at the alive check.
        detect_calls = []
        monkeypatch.setattr(
            scan_session, "_detect_smith_caller",
            lambda: (detect_calls.append(1), None)[1],
        )
        import psutil
        with patch.object(psutil, "pid_exists", return_value=True):
            scan_session._refresh_smith_pid_if_stale()
        assert detect_calls == [], "should not invoke detection when PID is alive"
        assert (isolated / "logs" / "smith.pid").read_text() == "12345"

    def test_refresh_replaces_dead_pid_with_fresh_detection(self, isolated, monkeypatch):
        """When tracked PID is dead but detection finds a live caller, the
        file is rewritten and the watchdog can again resolve to True."""
        (isolated / "logs").mkdir()
        (isolated / "logs" / "smith.pid").write_text("99999")
        monkeypatch.setattr(
            scan_session, "_detect_smith_caller",
            lambda: {"pid": 11111, "client": "opencode"},
        )
        import psutil
        with patch.object(psutil, "pid_exists", return_value=False):
            scan_session._refresh_smith_pid_if_stale()
        assert (isolated / "logs" / "smith.pid").read_text() == "11111"
        assert (isolated / "logs" / "smith.client").read_text() == "opencode"

    def test_refresh_no_op_when_detection_returns_none(self, isolated, monkeypatch):
        """Dead PID + nothing detectable → leave the file alone (don't trash
        diagnostics with a wiped marker just because detection couldn't
        find anything; the process-scan signal in api_server can still help)."""
        (isolated / "logs").mkdir()
        (isolated / "logs" / "smith.pid").write_text("99999")
        monkeypatch.setattr(scan_session, "_detect_smith_caller", lambda: None)
        import psutil
        with patch.object(psutil, "pid_exists", return_value=False):
            scan_session._refresh_smith_pid_if_stale()
        # File untouched, even though tracked PID is dead.
        assert (isolated / "logs" / "smith.pid").read_text() == "99999"

    def test_refresh_rate_limited(self, isolated, monkeypatch):
        """A single mutation burst (e.g. add_tool_called fires 5 times in a
        100ms window) must not psutil-scan 5 times. Rate-limit blocks the
        2nd-Nth attempts until _PID_REFRESH_MIN_INTERVAL_SECONDS elapses."""
        (isolated / "logs").mkdir()
        (isolated / "logs" / "smith.pid").write_text("99999")
        calls = []
        monkeypatch.setattr(
            scan_session, "_detect_smith_caller",
            lambda: (calls.append(1), None)[1],
        )
        import psutil
        with patch.object(psutil, "pid_exists", return_value=False):
            for _ in range(5):
                scan_session._refresh_smith_pid_if_stale()
        # Only ONE detection attempt despite 5 calls.
        assert len(calls) == 1

    def test_refresh_runs_when_pid_file_missing(self, isolated, monkeypatch):
        """No PID file at all → run detection so a freshly-started Smith gets
        captured even if session.start() wasn't called yet (e.g. user started
        interactive opencode and is reading docs before any tool call)."""
        # Don't create logs/ — the file is missing entirely
        captured = {"pid": 22222, "client": "claude"}
        monkeypatch.setattr(scan_session, "_detect_smith_caller", lambda: captured)
        scan_session._refresh_smith_pid_if_stale()
        assert (isolated / "logs" / "smith.pid").read_text() == "22222"


# ---------------------------------------------------------------------------
# _persist_smith_caller — file writes
# ---------------------------------------------------------------------------

class TestPersistSmithCaller:

    def test_writes_pid_and_client_files(self, tmp_path, monkeypatch):
        monkeypatch.setattr(scan_session, "_REPO_ROOT", tmp_path)
        scan_session._persist_smith_caller({"pid": 1234, "client": "opencode"})
        assert (tmp_path / "logs" / "smith.pid").read_text() == "1234"
        assert (tmp_path / "logs" / "smith.client").read_text() == "opencode"

    def test_overwrites_stale_pid(self, tmp_path, monkeypatch):
        """Previous scan left a stale smith.pid behind; the new scan must
        replace it cleanly, not append."""
        monkeypatch.setattr(scan_session, "_REPO_ROOT", tmp_path)
        (tmp_path / "logs").mkdir()
        (tmp_path / "logs" / "smith.pid").write_text("9999")
        scan_session._persist_smith_caller({"pid": 1234, "client": "claude"})
        assert (tmp_path / "logs" / "smith.pid").read_text() == "1234"

    def test_no_caller_is_noop(self, tmp_path, monkeypatch):
        """When detection returns None, we don't touch the files — the
        legacy heuristic still wins."""
        monkeypatch.setattr(scan_session, "_REPO_ROOT", tmp_path)
        scan_session._persist_smith_caller(None)
        assert not (tmp_path / "logs" / "smith.pid").exists()

    @pytest.mark.skipif(sys.platform == "win32",
                        reason="Unix permission semantics — Windows NTFS uses ACLs")
    def test_unwritable_path_does_not_raise(self, tmp_path, monkeypatch):
        """Audit-log style: file errors never propagate into scan logic."""
        unwritable = tmp_path / "ro"
        unwritable.mkdir(); unwritable.chmod(0o500)
        monkeypatch.setattr(scan_session, "_REPO_ROOT", unwritable)
        scan_session._persist_smith_caller({"pid": 1, "client": "opencode"})
        unwritable.chmod(0o700)


# ---------------------------------------------------------------------------
# session.start() integration
# ---------------------------------------------------------------------------

class TestStartIntegration:

    @pytest.fixture
    def isolated_session(self, tmp_path, monkeypatch):
        monkeypatch.setattr(scan_session, "_REPO_ROOT", tmp_path)
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        scan_session._current = None
        yield tmp_path
        scan_session._current = None

    def test_start_captures_smith_proc_into_session_state(self, isolated_session, monkeypatch):
        monkeypatch.setattr(
            scan_session, "_detect_smith_caller",
            lambda: {"pid": 7777, "client": "opencode"},
        )
        cur = scan_session.start(target="http://example.test", depth="quick")
        assert cur["smith_proc"]["pid"] == 7777
        assert cur["smith_proc"]["client"] == "opencode"
        assert cur["smith_proc"]["source"] == "interactive_mcp"
        assert "captured_at" in cur["smith_proc"]

    def test_start_persists_pid_file(self, isolated_session, monkeypatch):
        monkeypatch.setattr(
            scan_session, "_detect_smith_caller",
            lambda: {"pid": 8888, "client": "claude"},
        )
        scan_session.start(target="http://x.test", depth="quick")
        assert (isolated_session / "logs" / "smith.pid").read_text() == "8888"
        assert (isolated_session / "logs" / "smith.client").read_text() == "claude"

    def test_start_without_detectable_caller_still_works(self, isolated_session, monkeypatch):
        """Detection returning None is fine — start() just won't have a
        smith_proc field and the watchdog falls back to the legacy heuristic."""
        monkeypatch.setattr(scan_session, "_detect_smith_caller", lambda: None)
        cur = scan_session.start(target="http://x.test", depth="quick")
        assert "smith_proc" not in cur
