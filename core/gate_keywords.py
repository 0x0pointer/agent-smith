"""Keyword sets that fire mandatory skill gates from finding titles/notes.

This is the single home for the *gate-firing* vocabulary consumed by
``mcp_server.report_tools`` (RCE→post-exploit, K8s→container, cloud→cloud-security,
internal-net→network-assess, auth-weakness→credential-audit), plus the negative
markers that suppress a gate on benign or merely-speculative findings.

Deliberately SEPARATE from ``core.adjunction.rubric``: that module owns the
severity-scoring vocabulary (high/low-impact terms, terminal-blast-radius terms).
The two share words but answer different questions — "should a skill gate open?"
vs "what severity is this?" — and are tuned independently. Do not merge them.
"""

# Keywords in finding titles/descriptions that indicate RCE — triggers post-exploit gate.
RCE_KEYWORDS = (
    "command injection", "rce", "remote code execution", "code execution",
    "ssti", "server-side template injection", "deserialization",
    "os command", "shell injection", "eval injection",
)

# Keywords indicating a container/K8s execution context — triggers the container-escape
# gate. Includes plain-DOCKER markers (not just K8s): a confirmed RCE inside any
# container warrants an escape assessment, and run_2's postgres-container RCE never
# fired this because it only matched kube/serviceaccount tokens.
K8S_KEYWORDS = (
    "kubernetes", "kubepods", "/.dockerenv", "dockerenv",
    "sa token", "serviceaccount", "k8s", "containerd", "cri-o",
    "docker container", "docker.sock", "docker socket", "container escape",
    "inside a container", "in-container", "container runtime", "/proc/1/",
)

# Keywords in notes that indicate cloud metadata access — triggers cloud gate.
CLOUD_KEYWORDS = (
    "metadata service", "imds", "cloud metadata",
    "iam role", "instance profile", "link-local metadata",
)
# Cloud metadata IPs checked separately to avoid hardcoded-IP linting rules.
CLOUD_METADATA_PREFIX = "169.254."

# Keywords in notes that indicate internal network discovery — triggers network gate.
# Deliberately broad: agents write notes in many styles ("172.18.0.0/24", "host at 10.",
# "docker network", "reachable from DB container", etc.) — all should fire the gate.
INTERNAL_NET_KEYWORDS = (
    # Explicit phrasing
    "internal subnet", "internal network", "non-public subnet",
    "live hosts on 10.", "live hosts on 172.", "live hosts on 192.168.",
    # Natural phrasing agents actually write
    "docker network", "container network", "host at 10.", "host at 172.",
    "hosts at 10.", "hosts at 172.", "hosts at 192.168.",
    "reachable from", "pivot", "10.0.", "10.1.", "10.2.", "10.10.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "192.168.", "subnet /24", "subnet /16",
)

# Keywords that indicate auth services — triggers credential-audit gate.
AUTH_KEYWORDS = (
    "ssh", "ftp", "smb", "rdp", "vnc", "telnet",
    "login form", "basic auth", "admin panel", "management console",
    "mysql", "postgres", "mssql", "mongodb", "redis", "ldap",
)

# Negative markers — a finding that is mitigated / not exploitable / working as
# intended must NOT trigger a mandatory skill gate. The keyword gates were firing
# on benign findings ("login CSRF protection works", "mysql not reachable",
# "SSTI marked not_applicable", "deserialization uses a safe parser").
GATE_BENIGN_MARKERS = (
    "not reachable", "not exploitable", "not vulnerable", "working correctly",
    "properly configured", "correctly configured", "is enforced", "protection works",
    "mitigated", "false positive", "not applicable", "no impact", "safe parser",
    "no user input", "out of scope", "out-of-scope",
)

# "RCE-equivalent" / app-takeover framing — NOT confirmed host code execution. A finding
# that frames itself as *equivalent to* a shell/RCE, or argues a shell is *redundant*, is
# application-layer takeover, not actual command execution on the host. These must NOT open
# the post-exploit / reverse-shell / container-escape gate (which exists to escalate a REAL
# host exec primitive into a shell) — otherwise the gate fires on app-layer takeover and then
# gets "satisfied" by the very "a shell would add nothing" rationalization that framed it,
# exactly as observed on the VulnBank run (post_exploit_rce opened on an app-takeover finding
# with no confirmed host RCE, then a reverse-shell skip closed it). Confirmed host RCE won't
# carry this framing — it reports real command output, uid=, or a written file.
RCE_EQUIVALENT_MARKERS = (
    "rce-equivalent", "rce equivalent", "equivalent to rce", "equivalent to a shell",
    "shell-equivalent", "shell equivalent", "without a shell", "without shell",
    "shell is redundant", "shell would be redundant", "shell would add nothing",
    "shell adds nothing", "reverse shell' step is redundant", "would not expand blast",
    "not a true rce", "not actual code execution", "not host code execution",
    "no actual code execution",
)

# Speculation markers — an UNCONFIRMED finding ("the username appears to support
# SSTI; ${7*7} was reflected") must not impose the mandatory post-exploit gate.
# RCE/post-exploit is expensive and only makes sense once code execution is
# actually confirmed, so a speculative RCE/SSTI keyword fires nothing.
SPECULATION_MARKERS = (
    "appears to", "appear to", "may be", "might be", "possibly", "suspected",
    "potential", "unconfirmed", "not confirmed", "could be", "seems to",
    "may allow", "might allow", "may indicate", "if exploitable",
)

# Stronger auth-weakness signal so credential-audit fires on a real weakness,
# not on the mere mention of an auth service in passing.
AUTH_WEAKNESS_KEYWORDS = (
    "bypass", "weak", "default cred", "default password", "brute", "guessable",
    "credential", "password leak", "token leak", "exposed", "reuse",
    "predictable", "no lockout", "no rate limit", "enumerat",
)
