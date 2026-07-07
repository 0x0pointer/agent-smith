"""
Auto-triggered skill gates based on finding / note content.
"""
import re

from ._common import (
    scan_session,
    _AUTH_KEYWORDS,
    _AUTH_WEAKNESS_KEYWORDS,
    _CLOUD_KEYWORDS,
    _CLOUD_METADATA_PREFIX,
    _GATE_BENIGN_MARKERS,
    _INTERNAL_NET_KEYWORDS,
    _K8S_KEYWORDS,
    _RCE_KEYWORDS,
    _RCE_EQUIVALENT_MARKERS,
    _SPECULATION_MARKERS,
)


_CVE_RE = re.compile(r"cve-\d{4}-\d{4,7}", re.IGNORECASE)


def _maybe_trigger_cve_gate(text: str, cve: str, speculative: bool, severity: str) -> str | None:
    """CH-3: a confirmed CVE (cve= field or CVE-id in the text) auto-opens an
    exploitability-validation chain (analyze-cve; +metasploit at high/critical)
    instead of sitting as text. Suppressed for speculative findings."""
    match = _CVE_RE.search(cve or "") or _CVE_RE.search(text)
    if not match or speculative:
        return None
    skills = ["analyze-cve"] + (["metasploit"] if severity in ("critical", "high") else [])
    scan_session.trigger_gate("analyze_cve", f"CVE identified: {match.group(0).upper()}", skills)
    return "analyze_cve"


def _maybe_trigger_rce_gate(text: str, title: str, severity: str, speculative: bool) -> list[str]:
    """RCE-class finding → obligate the FULL post-exploitation escalation, ONLY when
    code execution is actually confirmed (a speculative "appears to support SSTI" /
    reflected ${7*7} is not RCE and imposes nothing).

    Command execution is NOT the finish line — run_2 proved COPY-TO/FROM-PROGRAM code
    exec (output via an error oracle) and stopped there, never getting an interactive
    shell, never escaping the container. So a confirmed RCE now requires:
      • post-exploit   — enumerate + escalate over the exec primitive
      • reverse-shell  — turn one-shot command exec into a real interactive/persistent
                         session (the missing "shell access")
      • container-k8s-security — WHEN the RCE is inside a container (Docker/K8s markers),
                         assess container escape.
    These obligate the ATTEMPT (satisfied by the skill running + documenting the
    outcome — an egress-blocked target that can't yield a shell still satisfies by
    recording why), so they never become an unsatisfiable wall."""
    if not (severity in ("critical", "high")
            and any(kw in text for kw in _RCE_KEYWORDS)
            and not speculative):
        return []
    # An "RCE-equivalent" / "shell is redundant" finding is application-layer takeover,
    # NOT confirmed host code execution. Opening the host-escalation gate on it just lets
    # the same rationalization ("a shell would add nothing") satisfy the gate — the exact
    # rubber-stamp seen on VulnBank. Require a genuine host-exec claim, not an equivalence.
    if any(m in text for m in _RCE_EQUIVALENT_MARKERS):
        return []
    triggered: list[str] = []
    scan_session.trigger_gate(
        "post_exploit_rce", f"RCE confirmed: {title}", ["post-exploit", "reverse-shell"])
    triggered.append("post_exploit_rce")
    # Detect container context from the RCE finding ITSELF (uid=999 in-container,
    # "Docker Container" title, /.dockerenv) — not only from a later note, which is
    # why run_2's DB-container RCE never opened the escape gate.
    if any(kw in text for kw in _K8S_KEYWORDS):
        scan_session.trigger_gate(
            "container_k8s", f"RCE inside a container: {title}", ["container-k8s-security"])
        triggered.append("container_k8s")
    return triggered


def _maybe_trigger_auth_gate(text: str, title: str, severity: str) -> str | None:
    """Auth weakness → credential-audit is mandatory. Require a real weakness
    (high/critical severity OR a weakness keyword), not just an auth-service name."""
    auth_weakness = severity in ("critical", "high") or any(k in text for k in _AUTH_WEAKNESS_KEYWORDS)
    if not (auth_weakness and any(kw in text for kw in _AUTH_KEYWORDS)):
        return None
    current = scan_session.get()
    depth = current.get("depth", "standard") if current else "standard"
    if depth in ("standard", "thorough"):
        scan_session.trigger_gate("credential_audit", f"Auth service detected: {title}", ["credential-audit"])
        return "credential_audit"
    return None


def _auto_trigger_finding_gates(title: str, severity: str, description: str, cve: str = "") -> list[str]:
    """Check finding content and trigger appropriate gates. Returns list of triggered gate IDs.

    Guarded against false triggers: a mitigated / non-exploitable / working-as-
    intended finding triggers nothing, and credential-audit needs a real auth
    WEAKNESS signal — not just the name of an auth service.
    """
    text = f"{title} {description}".lower()

    # Mitigated / not-exploitable findings must not impose a mandatory skill gate.
    if any(marker in text for marker in _GATE_BENIGN_MARKERS):
        return []

    speculative = any(m in text for m in _SPECULATION_MARKERS)
    triggered: list[str] = []
    cve_gate = _maybe_trigger_cve_gate(text, cve, speculative, severity)
    if cve_gate:
        triggered.append(cve_gate)
    triggered.extend(_maybe_trigger_rce_gate(text, title, severity, speculative))  # returns a list
    auth_gate = _maybe_trigger_auth_gate(text, title, severity)
    if auth_gate:
        triggered.append(auth_gate)
    return triggered


def _auto_trigger_note_gates(message: str) -> list[str]:
    """Check note content and trigger environment-specific gates. Returns list of triggered gate IDs."""
    triggered: list[str] = []
    text = message.lower()

    # Container/K8s markers (kubepods, /.dockerenv, SA token) are container-
    # INTERNAL signals — they only appear once we're executing inside a pod, so
    # keep the container-escape gate gated on an existing RCE/access gate.
    rce_gate_exists = any(g["id"] == "post_exploit_rce" for g in (scan_session.get() or {}).get("gates", []))
    if rce_gate_exists and any(kw in text for kw in _K8S_KEYWORDS):
        scan_session.trigger_gate(
            "container_k8s",
            "Container/K8s environment detected",
            ["container-k8s-security"],
        )
        triggered.append("container_k8s")

    # CH-7: cloud-metadata (IMDS) and internal-subnet reachability are routinely
    # reached via SSRF / DNS-rebinding with NO shell, so these gates fire on the
    # indicator regardless of how access was obtained — not only post-RCE.
    if any(kw in text for kw in _CLOUD_KEYWORDS) or _CLOUD_METADATA_PREFIX in text:
        scan_session.trigger_gate(
            "cloud_pivot",
            "Cloud metadata service reachable",
            ["cloud-security"],
        )
        triggered.append("cloud_pivot")

    if any(kw in text for kw in _INTERNAL_NET_KEYWORDS):
        # network-assess maps the topology; but once we ALSO have code execution,
        # internal reachability must be turned into actual MOVEMENT, not just a
        # topology diagram — obligate lateral-movement too. (run_2 proved the app
        # container was 'reachable' but never moved into it.) Both are attempt-gates:
        # satisfied by the skill running, so a genuinely un-pivotable target still
        # closes them by documenting why.
        net_skills = ["network-assess"] + (["lateral-movement"] if rce_gate_exists else [])
        scan_session.trigger_gate(
            "internal_network",
            "Internal network reachable" + (" — with code execution" if rce_gate_exists else ""),
            net_skills,
        )
        triggered.append("internal_network")

    # Auth service indicators in notes (e.g. from nmap service detection)
    if any(kw in text for kw in _AUTH_KEYWORDS):
        current = scan_session.get()
        depth = current.get("depth", "standard") if current else "standard"
        if depth in ("standard", "thorough"):
            scan_session.trigger_gate(
                "credential_audit",
                "Auth service detected in recon",
                ["credential-audit"],
            )
            triggered.append("credential_audit")

    return triggered
