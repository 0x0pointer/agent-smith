"""
Host execution lane — run an allow-listed readiness probe on the host.

This is the "third execution lane" the manual-setup design needs: alongside the
ephemeral Docker tools and the persistent Kali/MSF containers, some probes
(`frida-ps -U`, `ideviceinfo`, `flashrom`) must run on the operator's HOST where
the USB device / serial adapter is attached.

The agent-smith MCP server (and the dashboard api_server) already run ON the
host, so we execute in-process — no networked daemon, no listening port, no
bearer token to leak. The security boundary is core.probe_verbs: an allow-listed
verb + structured argv run with ``shell=False``. Every call is appended to an
audit log. (A networked daemon would only be needed if the device lived on a
different host than the MCP server — left as a future drop-in.)
"""
from __future__ import annotations

import shutil
import subprocess
from datetime import datetime, timezone

from core import paths as _paths
from core import probe_verbs

_AUDIT_LOG = _paths.REPO_ROOT / "logs" / "host_lane_audit.log"


def _audit(verb: str, args: list, result: dict) -> None:
    """Append one structured line per host execution. Best-effort; never raises."""
    try:
        _AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).isoformat()
        line = (
            f"{ts}\tverb={verb}\targs={' '.join(args)}\t"
            f"ok={result.get('ok')}\texit={result.get('exit_code')}\t"
            f"err={result.get('error') or ''}\n"
        )
        with _AUDIT_LOG.open("a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        pass


def run(verb: str, args: list, timeout: int = 30) -> dict:
    """Execute an allow-listed probe verb on the host.

    Returns {ok, exit_code, stdout, stderr, timed_out, error}. ``ok`` means the
    process ran to completion (exit code captured) — NOT that the probe's
    success criterion was met; that judgement belongs to core.probe_runner.
    """
    args = list(args or [])
    valid, reason = probe_verbs.validate(verb, args)
    if not valid:
        result = {"ok": False, "exit_code": None, "stdout": "", "stderr": "",
                  "timed_out": False, "error": f"rejected: {reason}"}
        _audit(verb, args, result)
        return result

    binary = probe_verbs.binary_for(verb)
    if not shutil.which(binary):
        result = {"ok": False, "exit_code": None, "stdout": "", "stderr": "",
                  "timed_out": False,
                  "error": f"'{binary}' is not installed on the host — install it to run this probe"}
        _audit(verb, args, result)
        return result

    try:
        proc = subprocess.run(  # noqa: S603 — argv is allow-listed + arg-validated, shell=False
            [binary, *args],
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        result = {
            "ok": True,
            "exit_code": proc.returncode,
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
            "timed_out": False,
            "error": "",
        }
    except subprocess.TimeoutExpired:
        result = {"ok": False, "exit_code": None, "stdout": "", "stderr": "",
                  "timed_out": True, "error": f"probe timed out after {timeout}s"}
    except OSError as exc:
        result = {"ok": False, "exit_code": None, "stdout": "", "stderr": "",
                  "timed_out": False, "error": f"{type(exc).__name__}: {exc}"}
    _audit(verb, args, result)
    return result
