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
    """Construct a psutil-shaped sconn for net_connections mocking."""
    addr = MagicMock()
    laddr = MagicMock(); laddr.port = local_port
    raddr = MagicMock(); raddr.port = remote_port
    return MagicMock(
        pid=pid,
        status=psutil.CONN_ESTABLISHED if status == "ESTABLISHED" else status,
        laddr=laddr if local_port is not None else None,
        raddr=raddr if remote_port is not None else None,
    )


def _fake_proc(cmdline: str):
    p = MagicMock()
    p.cmdline.return_value = cmdline.split()
    return p


# ---------------------------------------------------------------------------
# _detect_smith_caller — pure detection logic
# ---------------------------------------------------------------------------

class TestDetectSmithCaller:

    def test_detects_opencode_via_tcp(self, monkeypatch):
        conns = [_fake_conn(98765, local_port=44444, remote_port=7778)]
        with patch("psutil.net_connections", return_value=conns), \
             patch("psutil.Process", return_value=_fake_proc(
                 "/Users/u/.opencode/bin/opencode run scan x")):
            got = scan_session._detect_smith_caller()
        assert got == {"pid": 98765, "client": "opencode"}

    def test_detects_claude_via_tcp(self, monkeypatch):
        conns = [_fake_conn(12345, local_port=33333, remote_port=7778)]
        with patch("psutil.net_connections", return_value=conns), \
             patch("psutil.Process", return_value=_fake_proc(
                 "/opt/homebrew/bin/claude --dangerously-skip-permissions -p prompt")):
            got = scan_session._detect_smith_caller()
        assert got == {"pid": 12345, "client": "claude"}

    def test_detects_codex_via_tcp(self, monkeypatch):
        conns = [_fake_conn(55555, local_port=22222, remote_port=7778)]
        with patch("psutil.net_connections", return_value=conns), \
             patch("psutil.Process", return_value=_fake_proc(
                 "/usr/local/bin/codex mcp pentest-agent --run")):
            got = scan_session._detect_smith_caller()
        assert got == {"pid": 55555, "client": "codex"}

    def test_skips_unrelated_processes(self, monkeypatch):
        """The MCP server's own PID, vLLM workers, etc. must NOT be picked."""
        conns = [
            _fake_conn(1000, local_port=7778, remote_port=44440),  # MCP server side
            _fake_conn(2000, local_port=55550, remote_port=7778),  # generic node
            _fake_conn(3000, local_port=66660, remote_port=7778),  # other client
        ]
        unrelated_procs = {
            1000: _fake_proc("/usr/bin/python3 -m mcp_server --transport sse"),
            2000: _fake_proc("/usr/bin/python3 /usr/local/bin/vllm serve --port 7778"),
            3000: _fake_proc("node /Users/u/something-else.js"),
        }

        def _proc(pid):
            return unrelated_procs.get(pid, MagicMock(cmdline=MagicMock(return_value=[])))

        with patch("psutil.net_connections", return_value=conns), \
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

    def test_handles_access_denied(self, monkeypatch):
        """net_connections() can require root/admin on some platforms.
        We must return None silently, not crash."""
        with patch("psutil.net_connections",
                   side_effect=psutil.AccessDenied(pid=0)), \
             patch("os.getppid", return_value=99999):
            got = scan_session._detect_smith_caller()
        assert got is None

    def test_stdio_fallback_picks_parent_when_no_tcp(self, monkeypatch):
        """Codex stdio transport: no TCP connection to inspect — fallback to
        the parent process, which is the client."""
        with patch("psutil.net_connections", return_value=[]), \
             patch("psutil.Process",
                   return_value=_fake_proc("/usr/local/bin/codex run --mcp")), \
             patch("os.getppid", return_value=424242):
            got = scan_session._detect_smith_caller()
        assert got == {"pid": 424242, "client": "codex"}

    def test_skips_non_established_connections(self, monkeypatch):
        """LISTEN, CLOSE_WAIT, etc. should be ignored — we only want active
        client connections (ESTABLISHED)."""
        listening = _fake_conn(1111, local_port=7778, remote_port=None,
                                status="LISTEN")
        with patch("psutil.net_connections", return_value=[listening]), \
             patch("os.getppid", return_value=99999):
            got = scan_session._detect_smith_caller()
        assert got is None


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
