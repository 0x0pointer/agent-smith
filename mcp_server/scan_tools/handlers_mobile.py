"""Mobile static-analysis handlers: mobsf, mobsfscan."""
from core import cost as cost_tracker
from core import logger as log
from mcp_server._app import _record, _run


async def _handle_mobsf(target, _flags, _options):
    """Static analysis of a built mobile binary (APK / IPA / APPX / source zip)
    via the MobSF container: uploads the bytes, runs the scan, returns the
    MASVS-aligned summary. `target` is a local file path."""
    _record("mobsf")
    import os
    import json as _json
    from mcp_server.scan_engine import wrap
    if not os.path.isfile(target):
        return wrap(
            "mobsf",
            _json.dumps({"error": f"not a file: {target!r}. Provide a path to an "
                         ".apk / .ipa / .appx / source .zip."}),
            {"target": target},
        )
    from tools import mobsf_runner
    log.tool_call("mobsf", {"target": target})
    call_id = cost_tracker.start("mobsf")
    result = await mobsf_runner.analyze(target)
    if result.get("ok"):
        summary = mobsf_runner.summarize(result.get("report", {}))
        summary["hash"] = result.get("hash")
        summary["scan_type"] = result.get("scan_type")
        payload = _json.dumps(summary, default=str)
    else:
        payload = _json.dumps({"error": result.get("error", "mobsf analysis failed")})
    cost_tracker.finish(call_id, payload)
    log.tool_result("mobsf", payload[:500])
    return wrap("mobsf", payload, {"target": target, "scan_type": result.get("scan_type")})


async def _handle_mobsfscan(target, flags, _options):
    """Static analysis of a mobile SOURCE tree (mounts the path; MASVS-tagged)."""
    _record("mobsfscan")
    raw = await _run("mobsfscan", path=target, flags=flags)
    from mcp_server.scan_engine import wrap
    return wrap("mobsfscan", raw, {"path": target})
