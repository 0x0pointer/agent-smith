"""Attack-primitive taxonomy for compositional cross-finding chaining.

A finding PROVIDES capabilities (a Postgres SQLi provides ``file_read`` via
``pg_read_server_file``) and can be BLOCKED needing a capability (a PIN-locked
Werkzeug console REQUIRES ``file_read`` to leak the PIN ingredients). Compositional
chaining is the join ``provides(B) ∩ requires(A)`` — this module supplies both sides
so ``core/graph/build`` can emit PROVIDES/REQUIRES edges and ``core/graph/chains``
can match "finding B provides the primitive finding A is blocked on".

Pure data + pure functions, no I/O (mirrors ``core/graph/model.py`` and
``mcp_server/report_tools/findings.py:_infer_injection_type``). PROVIDES markers are
specific; REQUIRES markers are deliberately NARROW and BLOCKER-SHAPED so ordinary
finding prose never manufactures a spurious requirement — a missed tag just means no
auto-chain (fail-open, status-quo). ``code_exec`` is a TERMINAL (the goal of most
chains, not a bridge) so it carries no requires-markers.

Validated against the four exemplar chains (see tests/test_primitives.py):
  SQLi→file_read→Werkzeug-PIN→RCE, SSRF→network_reach→IMDS→cloud, LFI→file_read→config,
  leaked-secret→signing_key→JWT-forge.
"""
from __future__ import annotations

# ── Canonical primitive ids ──────────────────────────────────────────────────
FILE_READ       = "file_read"
CODE_EXEC       = "code_exec"        # terminal (provides-only)
NETWORK_REACH   = "network_reach"    # SSRF / proxy unlocks internal services
CLOUD_CREDS     = "cloud_creds"
SIGNING_KEY     = "signing_key"
CRED            = "cred"
ARBITRARY_WRITE = "arbitrary_write"
SECRET_READ     = "secret_read"

PRIMITIVES: tuple[str, ...] = (
    FILE_READ, CODE_EXEC, NETWORK_REACH, CLOUD_CREDS,
    SIGNING_KEY, CRED, ARBITRARY_WRITE, SECRET_READ,
)

# (primitive, provides_markers, requires_markers), ordered specific-first.
#   provides  = "this finding HANDS YOU the capability"
#   requires  = "this finding is BLOCKED, needing the capability" (blocker-shaped only)
_TAXONOMY: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...] = (
    (FILE_READ,
     ("pg_read_server_file", "pg_read_binary_file", "pg_ls_dir", "load_file(", "lo_import",
      "arbitrary file read", "arbitrary-file-read", "local file inclusion", " lfi",
      "path traversal", "directory traversal", "file disclosure", "read arbitrary file",
      "read any file", "xml external entit", "xxe"),
     ("blocked on file", "need file-read", "need to read /", "cannot read /", "no lfi",
      "no file-read", "requires file read", "requires a file-read", "machine-id",
      "machine_id", "derive the pin", "pin generation", "pin-gated", "pin-locked",
      "pin is un-derivable", "debugger pin", "werkzeug pin")),
    (CODE_EXEC,
     ("remote code execution", "command execution", " rce", "os command exec",
      "copy .. to program", "copy to program", "copy from program", "eval injection",
      "deserialization rce", "web shell", "webshell", "reverse shell obtained"),
     ()),  # terminal — never a bridge REQUIRES
    (NETWORK_REACH,
     ("ssrf", "server-side request forg", "request forgery", "dns rebinding",
      "open redirect to internal", "proxied to internal", "blind ssrf"),
     ("only reachable from", "internal-only", "not externally reachable",
      "reachable only from an adjacent", "need ssrf", "requires internal reach",
      "blocked on internal", "adjacent pod", "internal network only")),
    (CLOUD_CREDS,
     ("imds", "instance metadata", "metadata service", "iam role", "instance profile",
      "sts credentials", "assumerole", "cloud credentials", "169.254.169.254", "169.254.170.2"),
     ("need cloud cred", "blocked on iam", "requires instance role", "requires cloud cred")),
    (SIGNING_KEY,
     ("jwt secret", "jwt_secret", "signing secret", "signing key", "hmac secret",
      "hs256 secret", "private signing key", "token signing key"),
     ("need the signing", "blocked on jwt secret", "cannot forge", "requires signing key",
      "unknown signing secret", "without the signing key", "to forge a token")),
    (CRED,
     ("plaintext password", "cleartext password", "credentials dumped", "password dump",
      "leaked credential", "default credential", "default password", "dumped the users table",
      "user table dump"),
     ("need valid credential", "blocked on auth", "requires login", "no credentials",
      "requires valid credentials")),
    (ARBITRARY_WRITE,
     ("arbitrary file write", "write arbitrary file", "upload to webroot",
      "stored in the webroot", "arbitrary-write", "unrestricted file upload"),
     ("need to write", "blocked on write", "requires file write", "requires arbitrary write")),
    (SECRET_READ,
     ("config disclosure", ".env leak", "environment variables leaked", "secrets leaked",
      "source code disclosure", "source disclosure", "internal secret leak"),
     ("need to read config", "blocked on secret", "requires config access")),
)


def _match(text: str, markers: tuple[str, ...]) -> bool:
    return any(mk in text for mk in markers)


def classify_provides(title: str, description: str = "", cve: str = "") -> set[str]:
    """Primitives this finding PROVIDES to a downstream chain step."""
    text = f"{title} {description} {cve}".lower()
    return {pid for pid, prov, _req in _TAXONOMY if prov and _match(text, prov)}


def classify_requires(title: str, description: str = "") -> set[str]:
    """Primitives this finding is BLOCKED on (narrow, blocker-shaped markers only)."""
    text = f"{title} {description}".lower()
    return {pid for pid, _prov, req in _TAXONOMY if req and _match(text, req)}


def coerce_primitive_list(raw) -> list[str]:
    """Validate an explicit provides/requires list (from report(action='finding')).

    Drop-unknown, NEVER raise — a taxonomy typo must never reject a good finding."""
    if not isinstance(raw, (list, tuple)):
        return []
    seen: list[str] = []
    for x in raw:
        p = str(x).strip().lower()
        if p in PRIMITIVES and p not in seen:
            seen.append(p)
    return seen
