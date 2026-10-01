"""
Tests for the ZAP Client Spider migration (issue #184):
  - tools/zap_runner.py helpers + run_client_spider exit-code semantics (mocked docker)
  - tools/zap/client_spider_hook.py (auth replacer rules + URL dump)
  - spider.py two-pass wiring + credentials-wishlist deferral
Plus an OPT-IN docker smoke test (SMITH_DOCKER_SMOKE=1) that runs the real spider.
"""
import importlib.util
import json
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


class TestReadHelpers:
    def test_read_urls(self, tmp_path):
        (tmp_path / "urls.txt").write_text("http://a\n\n http://b \n")
        assert zr._read_urls(str(tmp_path)) == ["http://a", "http://b"]

    def test_read_urls_missing(self, tmp_path):
        assert zr._read_urls(str(tmp_path)) == []

    def test_read_alert_count(self, tmp_path):
        (tmp_path / "report.json").write_text(json.dumps(
            {"site": [{"alerts": [{"a": 1}, {"a": 2}]}, {"alerts": [{"a": 3}]}]}))
        assert zr._read_alert_count(str(tmp_path)) == 3

    def test_read_alert_count_missing(self, tmp_path):
        assert zr._read_alert_count(str(tmp_path)) == 0


# ---------------------------------------------------------------------------
# run_client_spider — exit-code semantics with mocked docker
# ---------------------------------------------------------------------------

def _proc(returncode: int, out: bytes = b""):
    p = MagicMock()
    p.returncode = returncode
    p.communicate = AsyncMock(return_value=(out, None))
    p.kill = MagicMock()
    return p


@pytest.fixture
def _image_present():
    with patch.object(zr, "ensure_image", new=AsyncMock(return_value=(True, "present"))):
        yield


@pytest.mark.asyncio
async def test_run_ok_exit0_is_ok(_image_present):
    with patch("tools.zap_runner.asyncio.create_subprocess_exec", return_value=_proc(0)), \
         patch.object(zr, "_read_urls", return_value=["http://x/a"]), \
         patch.object(zr, "_read_alert_count", return_value=2):
        res = await zr.run_client_spider("http://x", minutes=1, timeout=30)
    assert res["ok"] is True
    assert res["exit_code"] == 0
    assert res["urls"] == ["http://x/a"]
    assert "black-box" in res["note"]


@pytest.mark.asyncio
async def test_run_exit1_still_ran(_image_present):
    # exit 1 = FAIL alert threshold, but the scan RAN — must be ok=True.
    with patch("tools.zap_runner.asyncio.create_subprocess_exec", return_value=_proc(1)), \
         patch.object(zr, "_read_urls", return_value=[]), \
         patch.object(zr, "_read_alert_count", return_value=0):
        res = await zr.run_client_spider("http://x", minutes=1, timeout=30)
    assert res["ok"] is True
    assert res["exit_code"] == 1


@pytest.mark.asyncio
async def test_run_exit3_failed_to_run(_image_present):
    with patch("tools.zap_runner.asyncio.create_subprocess_exec", return_value=_proc(3, b"ZAP failed to start")), \
         patch.object(zr, "_read_urls", return_value=[]), \
         patch.object(zr, "_read_alert_count", return_value=0):
        res = await zr.run_client_spider("http://x", minutes=1, timeout=30)
    assert res["ok"] is False
    assert res["exit_code"] == 3
    assert "FAILED to run" in res["note"]


@pytest.mark.asyncio
async def test_run_authenticated_injects_env(_image_present):
    captured = {}

    def _capture(*args, **kwargs):
        captured["argv"] = args
        return _proc(0)

    auth = {"headers": {"Authorization": "Bearer tkn"}, "cookies": {"sid": "9"}}
    with patch("tools.zap_runner.asyncio.create_subprocess_exec", side_effect=_capture), \
         patch.object(zr, "_read_urls", return_value=[]), \
         patch.object(zr, "_read_alert_count", return_value=0):
        res = await zr.run_client_spider("http://x", minutes=1, auth=auth, timeout=30)
    argv = list(captured["argv"])
    assert "SMITH_ZAP_AUTH_HEADER=Bearer tkn" in argv
    assert "SMITH_ZAP_AUTH_COOKIE=sid=9" in argv
    assert "--client-spider" in argv
    assert "authenticated" in res["note"]


@pytest.mark.asyncio
async def test_run_unavailable_is_failsoft():
    with patch.object(zr, "ensure_image", new=AsyncMock(return_value=(False, "no daemon"))):
        res = await zr.run_client_spider("http://x", minutes=1, timeout=30)
    assert res["ok"] is False
    assert res["urls"] == []
    assert "unavailable" in res["note"]


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
        hook.zap_started(zap, "http://x")
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

    def test_zap_pre_shutdown_writes_urls(self, tmp_path, monkeypatch):
        hook = _load_hook()
        monkeypatch.setattr(hook, "_WORK", str(tmp_path))
        zap = MagicMock()
        zap.core.urls.return_value = ["http://x/a", "http://x/b"]
        hook.zap_pre_shutdown(zap)
        assert (tmp_path / "urls.txt").read_text().splitlines() == ["http://x/a", "http://x/b"]


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
            return {"ok": True, "exit_code": 0, "urls": [f"http://x/{len(calls)}"],
                    "alert_count": 0, "note": f"note{len(calls)}"}

        with patch("tools.zap_runner.run_client_spider", side_effect=_fake):
            out = await sp._run_zap_client_spider("http://x", 600, {})
        assert len(calls) == 2            # black-box + authenticated
        assert calls[0] is None
        assert calls[1] is not None

    @pytest.mark.asyncio
    async def test_one_pass_plus_wishlist_when_no_auth(self, monkeypatch):
        import mcp_server.scan_tools.spider as sp
        monkeypatch.setattr(sp, "_spider_discovery_auth", lambda c: None)
        monkeypatch.setattr(sp, "_authpass_deferral_note", lambda t: "[deferral]")
        calls = []

        async def _fake(target, minutes, auth, timeout):
            calls.append(auth)
            return {"ok": True, "exit_code": 0, "urls": [], "alert_count": 0, "note": "n"}

        with patch("tools.zap_runner.run_client_spider", side_effect=_fake):
            out = await sp._run_zap_client_spider("http://x", 600, {})
        assert len(calls) == 1            # black-box only
        assert "[deferral]" in out


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
