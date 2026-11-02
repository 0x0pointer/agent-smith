"""Re-open a prematurely-dismissed capability gate when a finding CONTRADICTS its dismissal.

Root cause this closes (observed live): a run dismissed ``post_exploit_rce`` as
"no code execution / injection clean" BEFORE the auth-gated SQLi endpoints were reachable, then
confirmed extensive SQLi hours later — with the gate already permanently ``not_applicable``. Nothing
re-opened it, so the agent was never driven to turn the SQLi into RCE/file-read, and the whole
internal-pivot chain (``COPY TO PROGRAM`` / ``pg_read_file`` -> DB pod -> K8s SA token -> internal
hosts) silently dropped.

Fix: when a confirmed server-side-injection / code-exec finding is filed, re-open
``post_exploit_rce`` (once) and rewrite its gate trigger into a concrete, DB-aware escalation
directive the completion blocker surfaces — the PROACTIVE nudge so the agent actually attempts the
escalation instead of relying on the model to think of it. A confirmed SSRF likewise re-opens
``internal_network``. Bounded (``reopen_gate_on_evidence`` re-opens each gate at most once, so an
informed re-dismissal is respected and this can't loop). Fail-soft, NON-BLOCKING.
"""
from __future__ import annotations

# Server-side primitives that CONTRADICT a "no code execution" dismissal — each is escalatable to
# RCE or an arbitrary-file-read oracle.
_CODE_EXEC_MARKERS = (
    "sql injection", "sqli", "command injection", "os command", "cmdi",
    "server-side template", "ssti", "template injection",
    "deserializ",                       # deserialization / deserialisation
    "arbitrary file upload", "unrestricted file upload", "webshell",
    "remote code", "code execution", " rce", "xxe", "xml external entity",
)
_SSRF_MARKERS = ("server-side request forgery", "ssrf")

# Synthesized credential/secret/token primitives (IMPROVEMENT-PLAN 1.5 — feedback-into-coverage):
# disclosing reusable secret material should FEED BACK into exploitation, not dead-end as a note.
# A reused secret is the most common bridge PAST the perimeter — a stolen K8s/cloud service-account
# token or kubeconfig authenticates to the internal/cluster/cloud API, and a cracked password /
# SSH key / API key reaches lateral movement or RCE on another host. So a secret disclosed AFTER a
# premature "no internal network" / "no code execution" dismissal CONTRADICTS it, exactly as a
# direct SSRF/injection does, and re-opens the relevant gate with a concrete reuse directive.
_CRED_PRIMITIVE_MARKERS = (
    "service account token", "service-account token", "serviceaccount token",
    "/var/run/secrets", "kubeconfig", "kube config",
    "jwt secret", "signing key", "signing secret", "private key", "ssh key", "ssh private",
    "aws credential", "aws secret", "aws access key", "cloud credential", "api key", "api token",
    "access token", "bearer token", "session token", "hardcoded credential", "hardcoded password",
    "leaked credential", "exposed secret", "exposed credential", "stolen token",
    "stolen credential", "database credential", "db credential", "secret key",
)


def is_code_exec_primitive(title: str, description: str = "") -> bool:
    """True when a finding describes a server-side primitive escalatable to RCE / file-read."""
    blob = f" {title} {description} ".lower()
    return any(m in blob for m in _CODE_EXEC_MARKERS)


def is_ssrf(title: str, description: str = "") -> bool:
    blob = f" {title} {description} ".lower()
    return any(m in blob for m in _SSRF_MARKERS)


def is_credential_primitive(title: str, description: str = "") -> bool:
    """True when a finding discloses reusable credential/secret/token material — a primitive to
    spray across services + principals and to authenticate against the internal/cluster/cloud API."""
    blob = f" {title} {description} ".lower()
    return any(m in blob for m in _CRED_PRIMITIVE_MARKERS)


def _rce_escalation_trigger(label: str) -> str:
    return (
        f"RE-OPENED by a confirmed injection primitive ({label[:120]}) — this CONTRADICTS the earlier "
        "'no code execution' dismissal. ESCALATE the injection to code-exec / arbitrary file-read NOW: "
        "Postgres superuser -> `COPY ... TO PROGRAM` (RCE) + `pg_read_file()` / `pg_ls_dir()` (file-read "
        "oracle: read env, the K8s service-account token, /proc/net to map the internal network); "
        "MySQL -> `INTO OUTFILE` / `load_file()`; MSSQL -> `xp_cmdshell`. A file-read/RCE here unlocks "
        "the internal-host pivot — drive it with /post-exploit + /reverse-shell."
    )


def _internal_network_trigger(label: str) -> str:
    return (
        f"RE-OPENED by a confirmed SSRF ({label[:120]}) — the server makes attacker-controlled requests, "
        "so the internal/cluster network IS reachable through this primitive, contradicting the earlier "
        "'no internal network' dismissal. Enumerate it via the SSRF: probe 169.254.169.254 (IMDS), the "
        "cluster service CIDRs and loopback services, then run /network-assess + /lateral-movement on "
        "whatever responds."
    )


def _credential_reuse_trigger(label: str) -> str:
    return (
        f"RE-OPENED by disclosed credential/secret material ({label[:120]}) — a reused secret is the most "
        "common bridge past the perimeter, so this CONTRADICTS the earlier dismissal. REUSE IT NOW: a "
        "K8s/cloud service-account token or kubeconfig -> authenticate to the cluster/cloud API (list "
        "secrets/pods, AssumeRole); a cracked password / API key -> SPRAY it across EVERY other known "
        "service + principal (cred x service matrix) and test cross-account / BOLA reach; an SSH/private "
        "key -> attempt a shell. Drive it with /credential-audit + /lateral-movement + /post-exploit."
    )


def _reopen_specs(title: str, description: str, label: str) -> list[tuple[str, str, str]]:
    """The (gate_id, reason, new_trigger) re-open specs a finding's primitives imply. A
    credential/secret primitive feeds BOTH the internal API and lateral/RCE reach, so it emits
    two specs (IMPROVEMENT-PLAN 1.5 feedback-into-coverage)."""
    specs: list[tuple[str, str, str]] = []
    if is_code_exec_primitive(title, description):
        specs.append(("post_exploit_rce",
                      f"confirmed code-exec primitive: {label[:160]}",
                      _rce_escalation_trigger(label)))
    if is_ssrf(title, description):
        specs.append(("internal_network",
                      f"confirmed SSRF contradicts 'no internal network': {label[:160]}",
                      _internal_network_trigger(label)))
    if is_credential_primitive(title, description):
        reason = f"disclosed credential/secret primitive: {label[:160]}"
        trig = _credential_reuse_trigger(label)
        specs.append(("internal_network", reason, trig))
        specs.append(("post_exploit_rce", reason, trig))
    return specs


def reopen_gates_on_finding(title: str, description: str = "", severity: str = "") -> list[str]:
    """Re-open any capability gate a confirmed finding contradicts. Returns the gate ids re-opened
    (``[]`` when nothing applies). Fail-soft, NON-BLOCKING — never raises into the finding path.

    Covers confirmed code-exec / SSRF primitives and (1.5) disclosed credential/secret/token
    material. Each re-open is bounded (``reopen_gate_on_evidence`` fires once per gate) and adds
    no new hard completion gate."""
    reopened: list[str] = []
    try:
        if severity not in ("critical", "high", "medium"):
            return reopened
        import core.session as _sess
        label = (title or "").strip() or "finding"
        for gid, reason, trig in _reopen_specs(title, description, label):
            if gid in reopened:
                continue
            if _sess.reopen_gate_on_evidence(gid, reason=reason, new_trigger=trig) is not None:
                reopened.append(gid)
    except Exception:
        pass
    return reopened
