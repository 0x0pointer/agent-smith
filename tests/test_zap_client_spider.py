"""
Tests for the ZAP Client Spider migration (issue #184):
  - tools/zap_runner.py helpers, ensure_image, run_client_spider (mocked docker)
  - tools/zap/client_spider_hook.py (auth replacer rules + URL dump to stdout)
  - spider.py two-pass wiring + credentials-wishlist deferral
Plus an OPT-IN docker smoke test (SMITH_DOCKER_SMOKE=1) that runs the real spider.
"""
import asyncio
import importlib.util
import os
import shutil
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import tools.zap_runner as zr


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

class TestHostRewrite:
    def test_localhost_rewritten(self):
        assert zr._host_rewrite("http://localhost:8099/x") == "http://host.docker.internal:8099/x"

    def test_127_rewritten(self):
        assert zr._host_rewrite("https://127.0.0.1/api") == "https://host.docker.internal/api"

    def test_external_untouched(self):
        assert zr._host_rewrite("https://example.com/a") == "https://example.com/a"


class TestAuthEnv:
    def test_none_is_empty(self):
        assert zr._auth_env(None) == {}
        assert zr._auth_env({"headers": {}, "cookies": {}}) == {}

    def test_bearer_header(self):
        env = zr._auth_env({"headers": {"Authorization": "Bearer abc"}, "cookies": {}})
        assert env["SMITH_ZAP_AUTH_HEADER"] == "Bearer abc"
        assert "SMITH_ZAP_AUTH_COOKIE" not in env

    def test_cookies_joined(self):
        env = zr._auth_env({"headers": {}, "cookies": {"s": "1", "csrf": "2"}})
        assert env["SMITH_ZAP_AUTH_COOKIE"] == "s=1; csrf=2"


class TestParseUrls:
    def test_parses_between_markers(self):
        out = (f"noise\n{zr._URLS_BEGIN}\nhttp://x/a\n http://x/b \n{zr._URLS_END}\nmore noise\n")
        assert zr._parse_urls(out) == ["http://x/a", "http://x/b"]

    def test_no_markers_is_empty(self):
        assert zr._parse_urls("just some\nlog lines\n") == []

    def test_empty_block(self):
        assert zr._parse_urls(f"{zr._URLS_BEGIN}\n{zr._URLS_END}") == []


# ---------------------------------------------------------------------------
# ensure_image / _image_exists / _reap
# ---------------------------------------------------------------------------

def _inspect_proc(rc: int):
    p = MagicMock()
    p.returncode = rc
    p.wait = AsyncMock(return_value=rc)
    return p


def _comm_proc(rc: int, out: bytes = b""):
    p = MagicMock()
    p.returncode = rc
    p.communicate = AsyncMock(return_value=(out, None))
    p.kill = MagicMock()
    return p


@pytest.fixture(autouse=True)
def _reset_image_ready():
    zr._image_ready = False
    yield
    zr._image_ready = False


class TestEnsureImage:
    @pytest.mark.asyncio
    async def test_present_no_pull(self):
        with patch("tools.zap_runner.asyncio.create_subprocess_exec",
                   return_value=_inspect_proc(0)) as ex:
            ok, msg = await zr.ensure_image()
        assert ok and msg == "present"
        assert ex.call_count == 1          # inspect only, no pull

    @pytest.mark.asyncio
    async def test_pull_success(self):
        calls = []

        async def _side(*a, **k):
            calls.append(a)
            return _inspect_proc(1) if len(calls) == 1 else _comm_proc(0, b"pulled")

        with patch("tools.zap_runner.asyncio.create_subprocess_exec", side_effect=_side):
            ok, msg = await zr.ensure_image()
        assert ok and msg == "pulled"

    @pytest.mark.asyncio
    async def test_pull_failure(self):
        calls = []

        async def _side(*a, **k):
            calls.append(a)
            return _inspect_proc(1) if len(calls) == 1 else _comm_proc(1, b"denied")

        with patch("tools.zap_runner.asyncio.create_subprocess_exec", side_effect=_side):
            ok, msg = await zr.ensure_image()
        assert not ok and "failed to pull" in msg

    @pytest.mark.asyncio
    async def test_image_exists_true(self):
        with patch("tools.zap_runner.asyncio.create_subprocess_exec", return_value=_inspect_proc(0)):
            assert await zr._image_exists() is True

    def test_reap_never_raises(self):
        with patch("tools.zap_runner.subprocess.Popen", side_effect=RuntimeError("boom")):
            zr._reap("x")   # must swallow


# ---------------------------------------------------------------------------
# run_client_spider — stdout parsing + exit-code semantics (mocked docker)
# ---------------------------------------------------------------------------

@pytest.fixture
def _image_present():
    with patch.object(zr, "ensure_image", new=AsyncMock(return_value=(True, "present"))):
        yield


def _stdout_with_urls(*urls: str) -> bytes:
    body = "\n".join([zr._URLS_BEGIN, *urls, zr._URLS_END])
    return ("zap log line\n" + body + "\nmore log\n").encode()


@pytest.mark.asyncio
async def test_run_ok_exit0_parses_urls(_image_present):
    proc = _comm_proc(0, _stdout_with_urls("http://x/a", "http://x/b"))
    with patch("tools.zap_runner.asyncio.create_subprocess_exec", return_value=proc):
        res = await zr.run_client_spider("http://x", minutes=1, timeout=30)
    assert res["ok"] is True
    assert res["exit_code"] == 0
    assert res["urls"] == ["http://x/a", "http://x/b"]
    assert "black-box" in res["note"]


@pytest.mark.asyncio
async def test_run_exit1_still_ran(_image_present):
    proc = _comm_proc(1, _stdout_with_urls("http://x/a"))
    with patch("tools.zap_runner.asyncio.create_subprocess_exec", return_value=proc):
        res = await zr.run_client_spider("http://x", minutes=1, timeout=30)
    assert res["ok"] is True
    assert res["exit_code"] == 1


@pytest.mark.asyncio
async def test_run_exit3_failed_to_run(_image_present):
    proc = _comm_proc(3, b"ZAP failed to start")
    with patch("tools.zap_runner.asyncio.create_subprocess_exec", return_value=proc):
        res = await zr.run_client_spider("http://x", minutes=1, timeout=30)
    assert res["ok"] is False
    assert res["exit_code"] == 3
    assert "FAILED to run" in res["note"]


@pytest.mark.asyncio
async def test_run_authenticated_injects_env(_image_present):
    captured = {}

    async def _capture(*args, **kwargs):
        captured["argv"] = args
        return _comm_proc(0, _stdout_with_urls())

    auth = {"headers": {"Authorization": "Bearer tkn"}, "cookies": {"sid": "9"}}
    with patch("tools.zap_runner.asyncio.create_subprocess_exec", side_effect=_capture):
        res = await zr.run_client_spider("http://x", minutes=1, auth=auth, timeout=30)
    argv = list(captured["argv"])
    assert "SMITH_ZAP_AUTH_HEADER=Bearer tkn" in argv
    assert "SMITH_ZAP_AUTH_COOKIE=sid=9" in argv
    assert "--client-spider" in argv
    assert "authenticated" in res["note"]


@pytest.mark.asyncio
async def test_run_timeout_branch(_image_present):
    proc = MagicMock()

    async def _slow():
        await asyncio.sleep(0.3)
        return (b"", None)

    proc.communicate = _slow
    proc.kill = MagicMock()
    proc.returncode = None
    with patch("tools.zap_runner.asyncio.create_subprocess_exec", return_value=proc):
        res = await zr.run_client_spider("http://x", minutes=1, timeout=0.05)
    assert res["ok"] is False
    assert "timed out" in res["note"]
    proc.kill.assert_called()


@pytest.mark.asyncio
async def test_run_unavailable_is_failsoft():
    with patch.object(zr, "ensure_image", new=AsyncMock(return_value=(False, "no daemon"))):
        res = await zr.run_client_spider("http://x", minutes=1, timeout=30)
    assert res["ok"] is False
    assert res["urls"] == []
    assert "unavailable" in res["note"]


@pytest.mark.asyncio
async def test_run_could_not_start(_image_present):
    with patch("tools.zap_runner.asyncio.create_subprocess_exec", side_effect=RuntimeError("no docker")):
        res = await zr.run_client_spider("http://x", minutes=1, timeout=30)
    assert res["ok"] is False
    assert "could not start" in res["note"]


# ---------------------------------------------------------------------------
# The hook file
# ---------------------------------------------------------------------------

def _load_hook():
    path = Path(zr._HOOK_SRC)
    spec = importlib.util.spec_from_file_location("zap_hook_undertest", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestHook:
    def test_zap_started_adds_auth_rules(self, monkeypatch):
        hook = _load_hook()
        monkeypatch.setenv("SMITH_ZAP_AUTH_HEADER", "Bearer xyz")
        monkeypatch.setenv("SMITH_ZAP_AUTH_COOKIE", "s=1")
        zap = MagicMock()
        hook.zap_started(zap, "http://x")        # ZAP calls it as (zap, target)
        assert zap.replacer.add_rule.call_count == 2
        kinds = [c.kwargs.get("matchstring") for c in zap.replacer.add_rule.call_args_list]
        assert "Authorization" in kinds
        assert "Cookie" in kinds

    def test_zap_started_no_env_no_rules(self, monkeypatch):
        hook = _load_hook()
        monkeypatch.delenv("SMITH_ZAP_AUTH_HEADER", raising=False)
        monkeypatch.delenv("SMITH_ZAP_AUTH_COOKIE", raising=False)
        zap = MagicMock()
        hook.zap_started(zap, "http://x")
        zap.replacer.add_rule.assert_not_called()

    def test_zap_pre_shutdown_prints_urls(self, capsys):
        hook = _load_hook()
        zap = MagicMock()
        zap.core.urls.return_value = ["http://x/a", "http://x/b"]
        hook.zap_pre_shutdown(zap)
        out = capsys.readouterr().out
        assert hook.URLS_BEGIN in out and hook.URLS_END in out
        assert zr._parse_urls(out) == ["http://x/a", "http://x/b"]

    def test_zap_pre_shutdown_handles_api_error(self, capsys):
        hook = _load_hook()
        zap = MagicMock()
        zap.core.urls.side_effect = RuntimeError("api down")
        hook.zap_pre_shutdown(zap)              # must not raise
        out = capsys.readouterr().out
        assert zr._parse_urls(out) == []


# ---------------------------------------------------------------------------
# spider.py two-pass wiring
# ---------------------------------------------------------------------------

class TestSpiderWiring:
    def _ka(self, monkeypatch, ka):
        import core.session as scan_session
        monkeypatch.setattr(scan_session, "get", lambda: {"known_assets": ka})

    def test_deferral_wishlists_when_no_creds(self, monkeypatch):
        import mcp_server.scan_tools.spider as sp
        self._ka(monkeypatch, {})
        with patch("core.wishlist.wishlist_queue.add") as add:
            note = sp._authpass_deferral_note("http://x")
        add.assert_called_once()
        assert add.call_args.kwargs.get("category") == "credentials"
        assert "wishlist" in note.lower()

    def test_deferral_no_wishlist_when_creds_held(self, monkeypatch):
        import mcp_server.scan_tools.spider as sp
        self._ka(monkeypatch, {"credentials": [{"u": "a"}]})
        with patch("core.wishlist.wishlist_queue.add") as add:
            note = sp._authpass_deferral_note("http://x")
        add.assert_not_called()
        assert "authenticate" in note.lower()

    @pytest.mark.asyncio
    async def test_two_passes_when_auth_present(self, monkeypatch):
        import mcp_server.scan_tools.spider as sp
        monkeypatch.setattr(sp, "_spider_discovery_auth",
                            lambda c: {"headers": {"Authorization": "Bearer t"}, "cookies": {}})
        calls = []

        async def _fake(target, minutes, auth, timeout):
            calls.append(auth)
            return {"ok": True, "exit_code": 0, "urls": [f"http://x/{len(calls)}"], "note": f"n{len(calls)}"}

        with patch("tools.zap_runner.run_client_spider", side_effect=_fake):
            out = await sp._run_zap_client_spider("http://x", 600, {})
        assert len(calls) == 2            # black-box + authenticated
        assert calls[0] is None
        assert calls[1] is not None
        assert "http://x/1" in out and "http://x/2" in out

    @pytest.mark.asyncio
    async def test_one_pass_plus_wishlist_when_no_auth(self, monkeypatch):
        import mcp_server.scan_tools.spider as sp
        monkeypatch.setattr(sp, "_spider_discovery_auth", lambda c: None)
        monkeypatch.setattr(sp, "_authpass_deferral_note", lambda t: "[deferral]")
        calls = []

        async def _fake(target, minutes, auth, timeout):
            calls.append(auth)
            return {"ok": True, "exit_code": 0, "urls": [], "note": "n"}

        with patch("tools.zap_runner.run_client_spider", side_effect=_fake):
            out = await sp._run_zap_client_spider("http://x", 600, {})
        assert len(calls) == 1            # black-box only
        assert "[deferral]" in out

    @pytest.mark.asyncio
    async def test_failsoft_on_runner_exception(self, monkeypatch):
        import mcp_server.scan_tools.spider as sp
        monkeypatch.setattr(sp, "_spider_discovery_auth", lambda c: None)
        with patch("tools.zap_runner.run_client_spider", side_effect=RuntimeError("docker gone")):
            out = await sp._run_zap_client_spider("http://x", 600, {})
        assert "skipped" in out.lower()   # never raises, returns a note

    @pytest.mark.asyncio
    async def test_fast_deep_mode_uses_client_spider(self, monkeypatch):
        import mcp_server.scan_tools.spider as sp

        async def _fake(target, total, cookies):
            return "ZAPURLS"

        monkeypatch.setattr(sp, "_run_zap_client_spider", _fake)
        out = await sp._run_spider_fast("http://x", "", {}, "3", "200", "deep", 600)
        assert out == "ZAPURLS"

    @pytest.mark.asyncio
    async def test_thorough_merges_client_spider(self, monkeypatch):
        import mcp_server.scan_tools.spider as sp
        from tools import kali_runner

        monkeypatch.setattr(kali_runner, "exec_command", AsyncMock(return_value="crawl-out"))

        async def _fakez(target, total, cookies):
            return "http://x/zap"

        monkeypatch.setattr(sp, "_run_zap_client_spider", _fakez)
        out = await sp._run_spider_thorough("http://x", "", {}, "3", "200", 3600)
        assert "=== katana ===" in out
        assert "=== zap-client-spider ===" in out
        assert "http://x/zap" in out


# ---------------------------------------------------------------------------
# Opt-in docker smoke test (SMITH_DOCKER_SMOKE=1) — real client spider
# ---------------------------------------------------------------------------

def _docker_up() -> bool:
    if shutil.which("docker") is None:
        return False
    import subprocess
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False


_RUN_SMOKE = os.environ.get("SMITH_DOCKER_SMOKE") == "1" and _docker_up()


@pytest.mark.skipif(not _RUN_SMOKE, reason="opt-in Docker smoke test — set SMITH_DOCKER_SMOKE=1 to run")
@pytest.mark.asyncio
async def test_client_spider_crawls_dom_link(tmp_path):
    """Serve a tiny site with a JS-injected link and confirm the DOM-aware Client
    Spider discovers it (the whole point of the migration)."""
    import http.server
    import socketserver
    import threading

    (tmp_path / "index.html").write_text(
        '<a href="/a.html">a</a><div id="j"></div>'
        '<script>document.getElementById("j").innerHTML='
        "'<a href=\"/dom-only.html\">js</a>'</script>")
    (tmp_path / "a.html").write_text("ok")
    (tmp_path / "dom-only.html").write_text("dom ok")

    class H(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **k):
            super().__init__(*a, directory=str(tmp_path), **k)

        def log_message(self, *a):
            pass

    srv = socketserver.TCPServer(("0.0.0.0", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        res = await zr.run_client_spider(f"http://localhost:{port}", minutes=1, timeout=420)
    finally:
        srv.shutdown()
    assert res["ok"] is True, res["note"]
    assert any("dom-only" in u for u in res["urls"]), res["urls"]
