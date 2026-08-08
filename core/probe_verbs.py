"""
Readiness-probe verb allow-list (the security boundary for host execution).

capabilities.yaml ships in skills/, which is a git submodule that can update —
so a probe command is UNTRUSTED INPUT. We never free-form shell it. Instead a
probe declares a ``verb`` (must be in PROBE_VERBS) plus structured ``args``
(each validated against ARG_RE — no spaces, no shell metacharacters). The host
lane then runs ``subprocess.run([binary, *args], shell=False)``. This closes the
"malicious capabilities.yaml = host RCE" vector (PLAN_REVIEW_GAPS G19/G20).

To support a new probe tool, add it here deliberately — that is the review gate.
"""
from __future__ import annotations

import re

# Allowed argument shape: alphanumerics + the punctuation real probe args use
# (flags, paths, host:port, package ids, baud rates, serials). No spaces, no
# shell metacharacters ($ ` ; | & > < ( ) * ? ! \ " ' newline), so even joined
# into a kali() command string the args cannot break out.
ARG_RE = re.compile(r"^[A-Za-z0-9._:/=@,+-]+$")

# Hard cap on argv length — a probe should be a short, fixed check.
MAX_ARGS = 12

# verb -> binary on PATH. Keep this list small and intentional.
PROBE_VERBS: dict[str, str] = {
    "adb":       "adb",        # android: `adb devices`, `adb connect <ip>:5555`, `adb shell getprop`
    "frida-ps":  "frida-ps",   # frida server reachable: `frida-ps -U`
    "frida":     "frida",      # `frida --version`
    "ideviceinfo": "ideviceinfo",  # ios (libimobiledevice): device present over USB
    "idevice_id":  "idevice_id",   # ios: list attached device UDIDs
    "picocom":   "picocom",    # uart: open a serial port / banner grab
    "screen":    "screen",     # uart fallback
    "openocd":   "openocd",    # jtag/swd: scan chain detect
    "flashrom":  "flashrom",   # spi flash: chip id read
    "ip":        "ip",         # network: `ip -br addr`
    "arp-scan":  "arp-scan",   # network: `arp-scan -l`
    "ping":      "ping",       # basic reachability
}


def validate(verb: str, args: list) -> tuple[bool, str]:
    """Return (ok, reason). A probe verb must be allow-listed and every arg
    must be a non-empty string matching ARG_RE. Rejects shell injection."""
    if verb not in PROBE_VERBS:
        return False, f"probe verb '{verb}' not in allow-list ({', '.join(sorted(PROBE_VERBS))})"
    if not isinstance(args, list):
        return False, "probe args must be a list"
    if len(args) > MAX_ARGS:
        return False, f"too many probe args ({len(args)} > {MAX_ARGS})"
    for a in args:
        if not isinstance(a, str) or not a:
            return False, f"probe arg must be a non-empty string: {a!r}"
        if not ARG_RE.match(a):
            return False, f"probe arg {a!r} contains disallowed characters (no spaces/shell metacharacters)"
    return True, "ok"


def binary_for(verb: str) -> str | None:
    """The PATH binary for a verb, or None if not allow-listed."""
    return PROBE_VERBS.get(verb)
