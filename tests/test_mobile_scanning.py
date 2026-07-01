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
