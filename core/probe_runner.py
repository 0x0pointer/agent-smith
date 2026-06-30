"""
Readiness-probe runner — the linchpin of manual-setup verification.

Given a capability's ``readiness_probe`` ({run_on, verb, args, success}), execute
the allow-listed probe and judge its success criterion. ``run_on: host`` goes
through the in-process core.host_lane; ``run_on: kali`` goes through the
persistent Kali container (adb-over-network probes like ``adb connect <ip>:5555``
work headless today). On a green host/adb probe we can parse the connected
device so it lands in known_assets.devices.

Kept independent of session state and the dashboard so both the MCP ``check``
action and the dashboard ``recheck`` route can call it.
"""
from __future__ import annotations

import re
import shlex

from core import host_lane, probe_verbs

# A readiness probe is a short, fixed check — bound its wall-clock here rather
# than threading a timeout through the async API.
_PROBE_TIMEOUT_S = 30


def evaluate_success(success: str, exit_code, stdout: str) -> bool:
    """Judge a probe result against its success criterion.

    Criteria: exit_zero · exit_zero_nonempty · contains:<substr> · regex:<pattern>.
    For the kali lane (no exit code available), exit_zero* fall back to
    "produced non-empty output".
    """
    success = (success or "exit_zero").strip()
    out = stdout or ""
    has_output = bool(out.strip())

    if success == "exit_zero":
        return exit_code == 0 if exit_code is not None else has_output
    if success == "exit_zero_nonempty":
        base = (exit_code == 0) if exit_code is not None else True
        return base and has_output
    if success.startswith("contains:"):
        return success[len("contains:"):] in out
    if success.startswith("regex:"):
        try:
            return re.search(success[len("regex:"):], out) is not None
        except re.error:
            return False
    # Unknown criterion → conservative: require non-empty output.
    return has_output


def _kind_for(verb: str) -> str:
    if verb in ("adb", "frida-ps", "frida"):
        return "adb"
    if verb in ("ideviceinfo", "idevice_id"):
        return "ios"
    if verb in ("picocom", "screen", "openocd", "flashrom"):
        return "serial"
    return "host"


def parse_device(verb: str, args: list, stdout: str) -> dict | None:
    """Best-effort extraction of a connected device for known_assets.devices.

    For `adb devices` we read real serials; for other passing probes we record a
    single probe-confirmed marker (dedup-on-serial collapses repeats)."""
    kind = _kind_for(verb)
    if verb == "adb" and "devices" in (args or []):
        for line in (stdout or "").splitlines():
            line = line.strip()
            if "\tdevice" in line or line.endswith(" device"):
                serial = line.split()[0]
                return {"kind": kind, "serial": serial, "transport": "adb"}
        return None
    # Generic: the probe passed, so a device of this kind is present.
    return {"kind": kind, "serial": f"{verb}-confirmed", "transport": verb}


async def run_probe(probe: dict) -> dict:
    """Run a readiness probe and return:
    {ran, ok, exit_code, stdout, stderr, success_criterion, device, error}.

    ``ran`` = the probe executed; ``ok`` = the success criterion was met. A probe
    is a short fixed check; its wall-clock bound is the module-level
    ``_PROBE_TIMEOUT_S``, applied by the underlying host/kali runner.
    """
    verb = (probe or {}).get("verb", "")
    args = list((probe or {}).get("args", []) or [])
    run_on = (probe or {}).get("run_on", "host")
    success = (probe or {}).get("success", "exit_zero")

    valid, reason = probe_verbs.validate(verb, args)
    if not valid:
        return {"ran": False, "ok": False, "exit_code": None, "stdout": "",
                "stderr": "", "success_criterion": success, "device": None,
                "error": f"rejected: {reason}"}

    if run_on == "host":
        res = host_lane.run(verb, args, timeout=_PROBE_TIMEOUT_S)
        exit_code, stdout, stderr = res["exit_code"], res["stdout"], res["stderr"]
        ran, err = res["ok"], res.get("error", "")
    elif run_on == "kali":
        from tools import kali_runner
        binary = probe_verbs.binary_for(verb)
        cmd = shlex.join([binary, *args])
        try:
            stdout = await kali_runner.exec_command(cmd, timeout=_PROBE_TIMEOUT_S)
            stderr, exit_code, ran, err = "", None, True, ""
        # surface any kali transport error as a non-ran probe (don't crash the check)
        except Exception as exc:  # noqa: BLE001
            stdout, stderr, exit_code, ran = "", "", None, False
            err = f"{type(exc).__name__}: {exc}"
    else:
        return {"ran": False, "ok": False, "exit_code": None, "stdout": "",
                "stderr": "", "success_criterion": success, "device": None,
                "error": f"unknown run_on '{run_on}' (use host|kali)"}

    ok = ran and evaluate_success(success, exit_code, stdout)
    device = parse_device(verb, args, stdout) if ok else None
    return {"ran": ran, "ok": ok, "exit_code": exit_code, "stdout": stdout,
            "stderr": stderr, "success_criterion": success, "device": device,
            "error": err}


async def check_gate(gid: str, artifact_store=None) -> dict:
    """Run a setup gate's readiness probe, record the result, and on a pass write
    the connected device into known_assets. Single source of truth shared by the
    MCP ``setup_gate check`` action and the dashboard recheck route.

    ``artifact_store`` is an OPTIONAL callable(result_dict) -> artifact_id, injected
    by the caller so this module stays free of any mcp_server dependency (correct
    layering). Returns {status, gate, result, artifact_id} where status ∈
    ok | failed | skipped | no_gate | no_probe.
    """
    import core.session as _sess
    gate = _sess.setup_gate_by_id(gid)
    if gate is None:
        return {"status": "no_gate", "gate": None, "result": None, "artifact_id": ""}
    if gate.get("election") == "skip":
        return {"status": "skipped", "gate": gate, "result": None, "artifact_id": ""}
    probe = gate.get("readiness_probe") or {}
    if not probe:
        return {"status": "no_probe", "gate": gate, "result": None, "artifact_id": ""}

    res = await run_probe(probe)
    artifact_id = ""
    if artifact_store is not None:
        try:
            artifact_id = artifact_store(res) or ""
        # artifact storage is best-effort evidence; never fail the probe on it
        except Exception:  # noqa: BLE001
            artifact_id = ""
    updated = _sess.record_probe_result(
        gid, res["ok"], artifact_id=artifact_id, stdout_excerpt=res.get("stdout", "")
    )
    if res["ok"] and res.get("device"):
        from datetime import datetime, timezone
        dev = dict(res["device"])
        dev["source"] = f"probe:{gid}"
        dev["obtained_at"] = datetime.now(timezone.utc).isoformat()
        _sess.update_known_assets("devices", [dev])
    return {"status": "ok" if res["ok"] else "failed", "gate": updated,
            "result": res, "artifact_id": artifact_id}
