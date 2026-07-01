"""Regression tests for mobile scanning: the mobsfscan lightweight tool, the MobSF
runner summary, the scan() dispatch handlers, and the start/stop_mobsf session actions.
The MobSF container itself is mocked — these lock the wiring without building the image.
"""
import asyncio
import os
import tempfile
from unittest.mock import AsyncMock, patch

import core.session as s
from tools import REGISTRY, mobsf_runner, mobsfscan


# ── mobsfscan lightweight tool ──────────────────────────────────────────────────

def test_mobsfscan_registered_and_needs_mount():
    assert "mobsfscan" in REGISTRY
    assert REGISTRY["mobsfscan"].needs_mount is True


def test_mobsfscan_arg_remap_to_mount():
    args = mobsfscan._build_args("/home/user/app-src", "--json")
    assert args[0] == "mobsfscan" and "/target" in args and "/home/user/app-src" not in args


def test_mobsfscan_parser_flattens_and_maps_severity():
    raw = (
        '{"results": {"android_world_readable": '
        '{"files": [{"file_path": "A.java", "match_lines": [10, 10]}], '
        '"metadata": {"severity": "WARNING", "masvs": "MSTG-STORAGE-2", "description": "world readable"}}}}'
    )
    out = mobsfscan._parse(raw, "")
    assert out and out[0]["severity"] == "medium" and out[0]["masvs"] == "MSTG-STORAGE-2"
    assert out[0]["path"] == "A.java"


def test_mobsfscan_parser_bad_json_is_empty():
    assert mobsfscan._parse("not json", "") == []


# ── MobSF runner summary ────────────────────────────────────────────────────────

def test_mobsf_summarize_condenses_appsec():
    report = {"app_name": "V", "package_name": "com.v",
              "appsec": {"security_score": 25, "high": [{"title": "MD5"}], "warning": [], "info": []}}
    out = mobsf_runner.summarize(report)
    assert out["package"] == "com.v" and out["finding_counts"]["high"] == 1


# ── scan() dispatch handlers ─────────────────────────────────────────────────────

def test_scan_dispatch_has_mobile_tools():
    import mcp_server.scan_tools as sc
    assert "mobsf" in sc._DISPATCH and "mobsfscan" in sc._DISPATCH


def test_handle_mobsf_success_summarizes(monkeypatch):
    import mcp_server.scan_tools as sc
    s.start("http://t.test", depth="recon")
    fd, apk = tempfile.mkstemp(suffix=".apk")
    os.write(fd, b"PK\x03\x04")
    os.close(fd)
    report = {"app_name": "Vuln", "package_name": "com.vuln",
              "appsec": {"security_score": 30, "high": [{"title": "MASVS-CRYPTO: MD5"}], "warning": [], "info": []}}

    async def fake_analyze(path):
        return {"ok": True, "hash": "h1", "scan_type": "apk", "file_name": os.path.basename(path), "report": report}

    monkeypatch.setattr(mobsf_runner, "analyze", AsyncMock(side_effect=fake_analyze))
    out = asyncio.run(sc._handle_mobsf(apk, "", {}))
    os.unlink(apk)
    assert "com.vuln" in out and "MASVS-CRYPTO" in out


def test_handle_mobsf_missing_file_guarded():
    import mcp_server.scan_tools as sc
    out = asyncio.run(sc._handle_mobsf("/no/such/app.apk", "", {}))
    assert "not a file" in out


def test_handle_mobsf_analysis_error_surfaced(monkeypatch):
    import mcp_server.scan_tools as sc
    s.start("http://t.test", depth="recon")
    fd, apk = tempfile.mkstemp(suffix=".apk")
    os.close(fd)
    monkeypatch.setattr(mobsf_runner, "analyze",
                        AsyncMock(return_value={"ok": False, "error": "MobSF 401 — API key rejected"}))
    out = asyncio.run(sc._handle_mobsf(apk, "", {}))
    os.unlink(apk)
    assert "401" in out or "api key" in out.lower()


# ── session lifecycle actions ────────────────────────────────────────────────────

def test_session_unknown_action_lists_mobsf():
    import mcp_server.session_tools as se
    help_txt = se._dispatch_sync_action("bogus", {})
    assert "start_mobsf" in help_txt and "stop_mobsf" in help_txt


def test_start_mobsf_routes_to_handler(monkeypatch):
    import mcp_server.session_tools as se
    monkeypatch.setattr(mobsf_runner, "ensure_running", AsyncMock(return_value=(True, "started")))
    out = asyncio.run(se._dispatch_async_action("start_mobsf", {}))
    assert out is not None and "MobSF container ready" in out


# ── skill-path resolver (domain-nesting tolerance) ───────────────────────────────

def test_resolve_skill_dir_flat_and_nested(monkeypatch, tmp_path):
    from core import skill_paths
    monkeypatch.setattr(skill_paths, "SKILLS_DIR", tmp_path)
    (tmp_path / "flatskill").mkdir()
    (tmp_path / "mobile" / "nestedskill").mkdir(parents=True)
    assert skill_paths.resolve_skill_dir("flatskill") == tmp_path / "flatskill"
    assert skill_paths.resolve_skill_dir("nestedskill") == tmp_path / "mobile" / "nestedskill"
    assert skill_paths.resolve_skill_dir("ghost") is None
    assert skill_paths.skill_file("nestedskill", "refs", "x.md") == tmp_path / "mobile" / "nestedskill" / "refs" / "x.md"
    assert skill_paths.skill_file("ghost", "x") is None


# ── mobsf_runner lifecycle + REST (mocked Docker/aiohttp) ────────────────────────

import asyncio as _aio


class _FakeProc:
    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.returncode = returncode
        self._out, self._err = stdout, stderr

    async def wait(self):
        return self.returncode

    async def communicate(self):
        return (self._out, self._err)


class _FakeResp:
    def __init__(self, status=200, json_data=None, read_data=b""):
        self.status = status
        self._json = json_data if json_data is not None else {}
        self._read = read_data

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def json(self):
        return self._json

    async def read(self):
        return self._read


class _FakeSession:
    def __init__(self, responses):
        self._responses = list(responses)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    def post(self, *a, **k):
        return self._responses.pop(0)

    def get(self, *a, **k):
        return self._responses.pop(0)


def _patch_subproc(monkeypatch, proc):
    async def _fake(*a, **k):
        return proc
    monkeypatch.setattr(_aio, "create_subprocess_exec", _fake)


def test_mobsf_image_and_container_checks(monkeypatch):
    _patch_subproc(monkeypatch, _FakeProc(returncode=0))
    assert _aio.run(mobsf_runner.image_exists()) is True
    _patch_subproc(monkeypatch, _FakeProc(returncode=0, stdout=b"true\n"))
    assert _aio.run(mobsf_runner.container_running()) is True
    _patch_subproc(monkeypatch, _FakeProc(returncode=0, stdout=b"false\n"))
    assert _aio.run(mobsf_runner.container_running()) is False


def test_mobsf_ensure_running_already_up(monkeypatch):
    monkeypatch.setattr(mobsf_runner, "container_running", AsyncMock(return_value=True))
    ok, msg = _aio.run(mobsf_runner.ensure_running())
    assert ok and msg == "already running"


def test_mobsf_ensure_running_pull_fails(monkeypatch):
    monkeypatch.setattr(mobsf_runner, "container_running", AsyncMock(return_value=False))
    monkeypatch.setattr(mobsf_runner, "image_exists", AsyncMock(return_value=False))
    _patch_subproc(monkeypatch, _FakeProc(returncode=1, stderr=b"no such image"))
    ok, msg = _aio.run(mobsf_runner.ensure_running())
    assert not ok and "could not pull" in msg


def test_mobsf_stop(monkeypatch):
    _patch_subproc(monkeypatch, _FakeProc(returncode=0))
    assert "stopped" in _aio.run(mobsf_runner.stop())


def test_mobsf_analyze_file_not_found():
    out = _aio.run(mobsf_runner.analyze("/no/such/file.apk"))
    assert out["ok"] is False and "file not found" in out["error"]


def test_mobsf_analyze_ensure_running_fails(monkeypatch, tmp_path):
    apk = tmp_path / "x.apk"; apk.write_bytes(b"PK\x03\x04")
    monkeypatch.setattr(mobsf_runner, "ensure_running", AsyncMock(return_value=(False, "image missing")))
    out = _aio.run(mobsf_runner.analyze(str(apk)))
    assert out["ok"] is False and out["error"] == "image missing"


def test_mobsf_analyze_success(monkeypatch, tmp_path):
    apk = tmp_path / "x.apk"; apk.write_bytes(b"PK\x03\x04")
    monkeypatch.setattr(mobsf_runner, "ensure_running", AsyncMock(return_value=(True, "started")))
    report = {"app_name": "V", "package_name": "com.v", "appsec": {"high": [], "warning": [], "info": []}}
    sess = _FakeSession([
        _FakeResp(200, {"hash": "h1", "scan_type": "apk", "file_name": "x.apk"}),  # upload
        _FakeResp(200, read_data=b"scanned"),                                        # scan
        _FakeResp(200, report),                                                      # report_json
    ])
    monkeypatch.setattr("aiohttp.ClientSession", lambda *a, **k: sess)
    out = _aio.run(mobsf_runner.analyze(str(apk)))
    assert out["ok"] is True and out["hash"] == "h1" and out["report"]["package_name"] == "com.v"


def test_mobsf_analyze_401(monkeypatch, tmp_path):
    apk = tmp_path / "x.apk"; apk.write_bytes(b"PK\x03\x04")
    monkeypatch.setattr(mobsf_runner, "ensure_running", AsyncMock(return_value=(True, "started")))
    sess = _FakeSession([_FakeResp(401, {})])
    monkeypatch.setattr("aiohttp.ClientSession", lambda *a, **k: sess)
    out = _aio.run(mobsf_runner.analyze(str(apk)))
    assert out["ok"] is False and "401" in out["error"]


def test_mobsf_analyze_upload_no_hash(monkeypatch, tmp_path):
    apk = tmp_path / "x.apk"; apk.write_bytes(b"PK\x03\x04")
    monkeypatch.setattr(mobsf_runner, "ensure_running", AsyncMock(return_value=(True, "started")))
    sess = _FakeSession([_FakeResp(200, {"status": "failed"})])  # no hash
    monkeypatch.setattr("aiohttp.ClientSession", lambda *a, **k: sess)
    out = _aio.run(mobsf_runner.analyze(str(apk)))
    assert out["ok"] is False and "upload failed" in out["error"]


def test_skill_paths_empty_name():
    from core import skill_paths
    assert skill_paths.resolve_skill_dir("") is None
    assert skill_paths.skill_file("", "x") is None


def test_mobsf_ensure_running_starts_and_healthchecks(monkeypatch):
    monkeypatch.setattr(mobsf_runner, "container_running", AsyncMock(return_value=False))
    monkeypatch.setattr(mobsf_runner, "image_exists", AsyncMock(return_value=True))
    _patch_subproc(monkeypatch, _FakeProc(returncode=0))                 # docker run OK
    monkeypatch.setattr("aiohttp.ClientSession", lambda *a, **k: _FakeSession([_FakeResp(200)]))
    ok, msg = _aio.run(mobsf_runner.ensure_running())
    assert ok and msg == "started"


def test_session_stop_mobsf_routes(monkeypatch):
    import mcp_server.session_tools as se
    monkeypatch.setattr(mobsf_runner, "stop", AsyncMock(return_value="Container 'pentest-mobsf' stopped."))
    out = _aio.run(se._dispatch_async_action("stop_mobsf", {}))
    assert out is not None and "stopped" in out
