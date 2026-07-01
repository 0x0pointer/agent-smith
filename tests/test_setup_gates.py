"""Regression tests for the manual-setup gate feature (capabilities.yaml +
readiness probes + host execution lane). Covers the security boundary, the
session state model, the (inline, co-located) capabilities loader, the probe
runner, and the session_tools lifecycle wiring.
"""
import asyncio
import os
import sys
import tempfile
from pathlib import Path

import pytest

import core.session as s
from core import capabilities, host_lane, probe_runner, probe_verbs


# ── probe-verb allow-list (the security boundary) ──────────────────────────────

def test_allowlist_rejects_injection_and_unknown_verbs():
    ok, _ = probe_verbs.validate("adb", ["; rm -rf /"])
    assert not ok
    ok, _ = probe_verbs.validate("adb", ["a b"])  # space → shell-splittable
    assert not ok
    ok, _ = probe_verbs.validate("curl", ["http://x"])  # not allow-listed
    assert not ok
    ok, _ = probe_verbs.validate("adb", ["connect", "127.0.0.1:5555"])
    assert ok


# ── session setup_gate state model ─────────────────────────────────────────────

def _cap(cid, requires_host=False, sba=None, run_on="host", verb="ping"):
    return {
        "id": cid, "category": "device", "description": "x",
        "requires_host": requires_host, "satisfied_by_assets": sba or [],
        "runbook": [{"step": "do a thing"}],
        "readiness_probe": {"run_on": run_on, "verb": verb, "args": ["-c", "1", "127.0.0.1"], "success": "exit_zero"},
    }


def test_open_gate_and_election_and_probe_result():
    s.start("http://t.test", depth="recon")
    g = s.open_setup_gate(_cap("g1"), skill="sk")
    assert g["status"] == "pending_election" and g["election"] is None
    # idempotent by id
    assert s.open_setup_gate(_cap("g1"))["id"] == "g1"
    assert len(s.list_setup_gates()) == 1
    s.record_election("g1", "now")
    assert s.setup_gate_by_id("g1")["status"] == "elected_now"
    s.record_probe_result("g1", True, artifact_id="a1", stdout_excerpt="ok")
    assert s.setup_gate_by_id("g1")["status"] == "satisfied"
    assert s.probe_is_fresh("g1") is True


def test_requires_host_never_auto_satisfies_from_assets():
    s.start("http://t.test", depth="recon")
    s.update_known_assets("devices", [{"kind": "adb", "serial": "emulator-5554"}])
    # requires_host capability must NOT pre-elect even with a matching device (G22)
    g = s.open_setup_gate(_cap("hostcap", requires_host=True, sba=[{"kind": "adb"}]))
    assert g["status"] == "pending_election" and g["election"] is None
    # a non-host capability with a matching asset DOES pre-elect (prompt suppressed)
    g2 = s.open_setup_gate(_cap("netcap", requires_host=False, sba=[{"kind": "adb"}], run_on="kali", verb="adb"))
    assert g2["status"] == "elected_now" and g2["election"] == "now"


def test_devices_asset_dedup_on_serial():
    s.start("http://t.test", depth="recon")
    s.update_known_assets("devices", [{"kind": "adb", "serial": "X"}])
    s.update_known_assets("devices", [{"kind": "adb", "serial": "X"}])  # dup
    s.update_known_assets("devices", [{"kind": "adb", "serial": "Y"}])
    serials = {d["serial"] for d in s.get()["known_assets"]["devices"]}
    assert serials == {"X", "Y"}


# ── host lane + probe runner ────────────────────────────────────────────────────

def test_host_lane_runs_real_binary_and_reports_missing():
    r = host_lane.run("ping", ["-c", "1", "127.0.0.1"], timeout=5)
    assert r["ok"] and r["exit_code"] == 0
    # disallowed arg is rejected before execution
    bad = host_lane.run("ping", ["; echo hi"], timeout=5)
    assert not bad["ok"] and "rejected" in bad["error"]


def test_evaluate_success_matrix_and_device_parse():
    assert probe_runner.evaluate_success("exit_zero", 0, "") is True
    assert probe_runner.evaluate_success("exit_zero_nonempty", 0, "") is False
    assert probe_runner.evaluate_success("exit_zero_nonempty", 0, "x") is True
    assert probe_runner.evaluate_success("contains:device", None, "emulator-5554\tdevice") is True
    d = probe_runner.parse_device("adb", ["devices"], "List of devices attached\nemulator-5554\tdevice\n")
    assert d and d["serial"] == "emulator-5554"


def test_check_gate_end_to_end_host_probe():
    s.start("http://t.test", depth="recon")
    s.open_setup_gate(_cap("png", verb="ping"), skill="sk")
    s.record_election("png", "now")
    out = asyncio.run(probe_runner.check_gate("png"))
    assert out["status"] == "ok" and out["result"]["ok"] is True
    assert s.setup_gate_by_id("png")["status"] == "satisfied"
    # a device asset was produced
    assert s.get()["known_assets"]["devices"], "probe pass should write a device asset"


def test_check_gate_skipped_short_circuits():
    s.start("http://t.test", depth="recon")
    s.open_setup_gate(_cap("sk1"))
    s.record_election("sk1", "skip")
    out = asyncio.run(probe_runner.check_gate("sk1"))
    assert out["status"] == "skipped" and out["result"] is None


# ── capabilities loader (inline-only, co-located; bad-verb skip) ────────────────

def test_loader_inline_and_rejections(monkeypatch):
    tmp = Path(tempfile.mkdtemp())
    monkeypatch.setattr(capabilities, "_SKILLS_DIR", tmp)
    (tmp / "sk").mkdir()
    (tmp / "sk" / "capabilities.yaml").write_text(
        "- id: inline-uart\n"
        "  category: hardware\n"
        "  readiness_probe: {run_on: host, verb: picocom, args: ['-b','115200','/dev/ttyUSB0'], success: 'contains:login'}\n"
        "- id: inline-adb\n"
        "  category: device\n"
        "  readiness_probe: {run_on: kali, verb: adb, args: ['devices'], success: exit_zero}\n"
    )
    caps, warns = capabilities.load_capabilities("sk")
    assert {c["id"] for c in caps} == {"inline-uart", "inline-adb"}, caps
    assert not warns, warns

    # disallowed probe verb skipped with a warning
    (tmp / "bad").mkdir()
    (tmp / "bad" / "capabilities.yaml").write_text(
        "- id: bad\n  readiness_probe: {run_on: host, verb: curl, args: ['http://x'], success: exit_zero}\n"
    )
    caps2, warns2 = capabilities.load_capabilities("bad")
    assert caps2 == [] and any("allow-list" in w for w in warns2)


# ── session_tools lifecycle wiring ──────────────────────────────────────────────

def test_set_skill_hook_opens_gate_and_recovery_surfaces_it(monkeypatch):
    from mcp_server import session_tools as st
    s.start("http://t.test", depth="recon")
    tmp = Path(tempfile.mkdtemp())
    monkeypatch.setattr(capabilities, "_SKILLS_DIR", tmp)
    (tmp / "tskill").mkdir()
    (tmp / "tskill" / "capabilities.yaml").write_text(
        "- id: t-ping\n  category: network\n  requires_host: false\n"
        "  readiness_probe: {run_on: host, verb: ping, args: ['-c','1','127.0.0.1'], success: exit_zero}\n"
    )
    msg = st._do_set_skill({"skill": "tskill"})
    assert "MANUAL SETUP REQUIRED" in msg and "t-ping" in msg
    # deferred gate surfaces in the recovery brief
    s.record_election("t-ping", "defer")
    import json
    rec = json.loads(st._do_recovery())
    assert any(g["id"] == "t-ping" for g in rec.get("open_setup_gates", []))
    # Unknown-action help advertises setup_gate
    assert "setup_gate" in st._dispatch_sync_action("bogus", {})


# ── probe_runner branch coverage (kali lane, errors, check_gate paths) ──────────

def test_probe_runner_kali_lane(monkeypatch):
    from unittest.mock import AsyncMock
    from tools import kali_runner
    monkeypatch.setattr(kali_runner, "exec_command", AsyncMock(return_value="emulator-5554\tdevice"))
    res = asyncio.run(probe_runner.run_probe(
        {"run_on": "kali", "verb": "adb", "args": ["devices"], "success": "contains:device"}))
    assert res["ran"] and res["ok"]


def test_probe_runner_kali_error(monkeypatch):
    from unittest.mock import AsyncMock
    from tools import kali_runner
    monkeypatch.setattr(kali_runner, "exec_command", AsyncMock(side_effect=RuntimeError("boom")))
    res = asyncio.run(probe_runner.run_probe(
        {"run_on": "kali", "verb": "adb", "args": ["devices"], "success": "exit_zero"}))
    assert not res["ran"] and "boom" in res["error"]


def test_probe_runner_unknown_run_on_and_rejected_verb():
    res = asyncio.run(probe_runner.run_probe(
        {"run_on": "mars", "verb": "ping", "args": ["-c", "1", "127.0.0.1"], "success": "exit_zero"}))
    assert not res["ran"] and "unknown run_on" in res["error"]
    res2 = asyncio.run(probe_runner.run_probe({"run_on": "host", "verb": "curl", "args": ["x"]}))
    assert not res2["ran"] and "rejected" in res2["error"]


def test_parse_device_adb_no_device_line():
    assert probe_runner.parse_device("adb", ["devices"], "List of devices attached\n\n") is None


def test_check_gate_no_gate_and_no_probe():
    s.start("http://t.test", depth="recon")
    assert asyncio.run(probe_runner.check_gate("missing"))["status"] == "no_gate"
    s.open_setup_gate({"id": "noprobe", "category": "other"})
    assert asyncio.run(probe_runner.check_gate("noprobe"))["status"] == "no_probe"


def test_check_gate_failed_with_artifact_store():
    s.start("http://t.test", depth="recon")
    s.open_setup_gate({"id": "failp", "readiness_probe":
                       {"run_on": "host", "verb": "ping", "args": ["-c", "1", "127.0.0.1"], "success": "contains:NOPEXYZ"}})
    s.record_election("failp", "now")
    captured = {}

    def store(res):
        captured["res"] = res
        return "art-1"

    out = asyncio.run(probe_runner.check_gate("failp", artifact_store=store))
    assert out["status"] == "failed" and out["artifact_id"] == "art-1" and "res" in captured


def test_check_gate_artifact_store_raises_is_swallowed():
    s.start("http://t.test", depth="recon")
    s.open_setup_gate({"id": "pg2", "readiness_probe":
                       {"run_on": "host", "verb": "ping", "args": ["-c", "1", "127.0.0.1"], "success": "exit_zero"}})
    s.record_election("pg2", "now")

    def boom(_res):
        raise RuntimeError("x")

    out = asyncio.run(probe_runner.check_gate("pg2", artifact_store=boom))
    assert out["status"] == "ok" and out["artifact_id"] == ""


# ── host_lane branch coverage (missing binary, timeout) ─────────────────────────

def test_host_lane_missing_binary(monkeypatch):
    monkeypatch.setattr(host_lane.shutil, "which", lambda b: None)
    r = host_lane.run("frida-ps", ["-U"], timeout=5)
    assert not r["ok"] and "not installed" in r["error"]


def test_host_lane_timeout(monkeypatch):
    import subprocess

    def fake_run(*a, **k):
        raise subprocess.TimeoutExpired(cmd="x", timeout=1)

    monkeypatch.setattr(host_lane.subprocess, "run", fake_run)
    r = host_lane.run("ping", ["-c", "1", "127.0.0.1"], timeout=1)
    assert not r["ok"] and r["timed_out"]


# ── setup_gates + capabilities edge cases ───────────────────────────────────────

def test_record_election_invalid_choice_and_probe_freshness():
    s.start("http://t.test", depth="recon")
    s.open_setup_gate(_cap("g"))
    assert s.record_election("g", "bogus") is None
    assert s.probe_is_fresh("g") is False  # no probe result yet


def test_capabilities_invalid_yaml_warns(monkeypatch):
    tmp = Path(tempfile.mkdtemp())
    monkeypatch.setattr(capabilities, "_SKILLS_DIR", tmp)
    (tmp / "sk").mkdir()
    (tmp / "sk" / "capabilities.yaml").write_text("- id: x\n  bad: : : [\n")  # malformed YAML
    caps, warns = capabilities.load_capabilities("sk")
    assert caps == [] and warns and "parse" in warns[0].lower()


def test_capabilities_non_list_top_level(monkeypatch):
    tmp = Path(tempfile.mkdtemp())
    monkeypatch.setattr(capabilities, "_SKILLS_DIR", tmp)
    (tmp / "sk").mkdir()
    (tmp / "sk" / "capabilities.yaml").write_text("id: not-a-list\n")
    caps, warns = capabilities.load_capabilities("sk")
    assert caps == [] and any("list" in w for w in warns)


def test_parse_device_ios_and_serial_kinds():
    assert probe_runner.parse_device("ideviceinfo", [], "ok")["kind"] == "ios"
    assert probe_runner.parse_device("picocom", [], "login:")["kind"] == "serial"


def test_capabilities_lookup_supports_domain_nesting(monkeypatch):
    """skills/<name>/capabilities.yaml AND skills/<domain>/<name>/capabilities.yaml
    both resolve (enables the /mobile /web domain split)."""
    tmp = Path(tempfile.mkdtemp())
    monkeypatch.setattr(capabilities, "_SKILLS_DIR", tmp)
    probe = "  readiness_probe: {run_on: host, verb: ping, args: ['-c','1','127.0.0.1'], success: exit_zero}\n"
    (tmp / "flatskill").mkdir()
    (tmp / "flatskill" / "capabilities.yaml").write_text("- id: flat\n" + probe)
    (tmp / "mobile" / "nested").mkdir(parents=True)
    (tmp / "mobile" / "nested" / "capabilities.yaml").write_text("- id: nested\n" + probe)
    assert capabilities._capabilities_path("flatskill") is not None
    assert capabilities._capabilities_path("nested") is not None      # one level of nesting
    assert capabilities._capabilities_path("ghost") is None
    caps_flat, _ = capabilities.load_capabilities("flatskill")
    caps_nested, _ = capabilities.load_capabilities("nested")
    assert caps_flat[0]["id"] == "flat" and caps_nested[0]["id"] == "nested"


def test_capabilities_yaml_unavailable(monkeypatch):
    monkeypatch.setattr(capabilities, "yaml", None)
    tmp = Path(tempfile.mkdtemp())
    monkeypatch.setattr(capabilities, "_SKILLS_DIR", tmp)
    (tmp / "sk").mkdir()
    (tmp / "sk" / "capabilities.yaml").write_text("- id: x\n")
    caps, warns = capabilities.load_capabilities("sk")
    assert caps == [] and any("PyYAML" in w for w in warns)


def test_do_setup_gate_open_and_dispatch_errors():
    from mcp_server import session_tools as st
    s.start("http://t.test", depth="recon")
    assert "needs options.capability" in asyncio.run(st._do_setup_gate({"action": "open"}))
    opened = asyncio.run(st._do_setup_gate({"action": "open", "capability": _cap("o1")}))
    assert "Opened 'o1'" in opened
    assert "requires options.id" in asyncio.run(st._do_setup_gate({"action": "elect", "id": "", "choice": "x"}))
    assert "requires options.id" in asyncio.run(st._do_setup_gate({"action": "check"}))
    assert "must be one of" in asyncio.run(st._do_setup_gate({"action": "bogus"}))
    import json as _j
    assert _j.loads(asyncio.run(st._do_setup_gate({"action": "list"})))["count"] >= 1
