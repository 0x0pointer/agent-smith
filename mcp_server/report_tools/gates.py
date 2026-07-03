"""
Auto-triggered skill gates based on finding / note content.
"""
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
    _SPECULATION_MARKERS,
)


def _auto_trigger_finding_gates(title: str, severity: str, description: str) -> list[str]:
    """Check finding content and trigger appropriate gates. Returns list of triggered gate IDs.

    Guarded against false triggers: a mitigated / non-exploitable / working-as-
    intended finding triggers nothing, and credential-audit needs a real auth
    WEAKNESS signal — not just the name of an auth service.
    """
    triggered: list[str] = []
    text = f"{title} {description}".lower()

    # Mitigated / not-exploitable findings must not impose a mandatory skill gate.
    if any(marker in text for marker in _GATE_BENIGN_MARKERS):
        return triggered

    # RCE-class finding → post-exploit is mandatory — but ONLY when code execution
    # is actually confirmed. A speculative mention ("appears to support SSTI",
    # ${7*7} merely reflected) is not RCE, so it must not impose the post-exploit
    # gate (the false-fire seen on a SQLi-auth-bypass finding that name-dropped SSTI).
    speculative = any(m in text for m in _SPECULATION_MARKERS)
    if (severity in ("critical", "high")
            and any(kw in text for kw in _RCE_KEYWORDS)
            and not speculative):
        scan_session.trigger_gate(
            "post_exploit_rce",
            f"RCE confirmed: {title}",
            ["post-exploit"],
        )
        triggered.append("post_exploit_rce")

    # Auth weakness → credential-audit is mandatory. Require a real weakness
    # (high/critical severity OR a weakness keyword), not just an auth-service name.
    auth_weakness = severity in ("critical", "high") or any(k in text for k in _AUTH_WEAKNESS_KEYWORDS)
    if auth_weakness and any(kw in text for kw in _AUTH_KEYWORDS):
        current = scan_session.get()
        depth = current.get("depth", "standard") if current else "standard"
        if depth in ("standard", "thorough"):
            scan_session.trigger_gate(
                "credential_audit",
                f"Auth service detected: {title}",
                ["credential-audit"],
            )
            triggered.append("credential_audit")

    return triggered


def _auto_trigger_note_gates(message: str) -> list[str]:
    """Check note content and trigger environment-specific gates. Returns list of triggered gate IDs."""
    triggered: list[str] = []
    text = message.lower()

    # Only trigger environment gates if an RCE gate already exists (we have access)
    rce_gate_exists = any(g["id"] == "post_exploit_rce" for g in (scan_session.get() or {}).get("gates", []))

    if rce_gate_exists:
        # K8s/container indicators → container-k8s-security mandatory
        if any(kw in text for kw in _K8S_KEYWORDS):
            scan_session.trigger_gate(
                "container_k8s",
                "Container/K8s environment detected",
                ["container-k8s-security"],
            )
            triggered.append("container_k8s")

        # Cloud metadata indicators → cloud-security mandatory
        if any(kw in text for kw in _CLOUD_KEYWORDS) or _CLOUD_METADATA_PREFIX in text:
            scan_session.trigger_gate(
                "cloud_pivot",
                "Cloud metadata service reachable",
                ["cloud-security"],
            )
            triggered.append("cloud_pivot")

        # Internal network indicators → network-assess mandatory
        if any(kw in text for kw in _INTERNAL_NET_KEYWORDS):
            scan_session.trigger_gate(
                "internal_network",
                "Internal network reachable from compromised host",
                ["network-assess"],
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
