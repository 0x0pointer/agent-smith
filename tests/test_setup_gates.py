"""Regression tests for the manual-setup gate feature (capabilities.yaml +
readiness probes + host execution lane). Covers the security boundary, the
session state model, the loader's $ref jail, the probe runner, and the
session_tools lifecycle wiring.
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


# ── capabilities loader ($ref jail, bad-verb skip) ──────────────────────────────

def test_loader_inline_and_ref_and_rejections(monkeypatch):
    tmp = Path(tempfile.mkdtemp())
    monkeypatch.setattr(capabilities, "_SKILLS_DIR", tmp)
    (tmp / "sk").mkdir()
    (tmp / "sk" / "capabilities.yaml").write_text(
        "- id: inline-uart\n"
        "  category: hardware\n"
        "  readiness_probe: {run_on: host, verb: picocom, args: ['-b','115200','/dev/ttyUSB0'], success: 'contains:login'}\n"
        "- {$ref: android-dynamic}\n"
    )
    caps, warns = capabilities.load_capabilities("sk")
    assert {c["id"] for c in caps} == {"inline-uart", "android-dynamic"}, caps
    assert not warns, warns

    # $ref traversal rejected
    cap, w = capabilities._resolve_ref("../../../etc/passwd")
    assert cap is None and "invalid" in w

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
