"""
Canonical severity rubric
==========================
Single source of truth for how findings are rated. Replaces the divergent
per-skill mini-rubrics (web-exploit, api-security, business-logic, codebase,
ai-redteam, credential-audit) with ONE standard.

Consumed by:
- adjunction.directive — embedded in the completion-time adjudication pass so the
  senior-reviewer re-rates every finding against this rubric, not its own ad-hoc one.
- adjunction.directive — `validate_severity_vs_impact` flags findings whose asserted
  severity reads inflated relative to their description, as a hint to the reviewer.

This module is pure data + pure functions — no I/O, no LLM, deterministic.
"""
from __future__ import annotations

# Ordered most → least severe. Mirrors the values report() already accepts.
SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")


def severity_rank(severity: str) -> int:
    """Numeric rank (critical=4 … info=0); -1 for unknown. Higher = worse."""
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    return order.get((severity or "").strip().lower(), -1)


# The rubric. Each band lists the kinds of issue that belong there. The
# examples are illustrative anchors, NOT an exhaustive allow-list — the
# reviewer always reasons about real-world exploitability in the target's
# actual context (auth model, data flows, existing mitigations, preconditions).
RUBRIC: dict[str, dict] = {
    "critical": {
        "summary": (
            "Full or near-full compromise with little/no precondition — an "
            "attacker gains code execution, admin access, or bulk sensitive data."
        ),
        "examples": [
            "Unauthenticated RCE / command injection / deserialization to code execution",
            "Authentication bypass granting admin or privileged access without credentials",
            "Cross-tenant data exfiltration at scale, or full database dump",
            "Leaked credentials/secret that directly yields privileged access (confirmed live)",
        ],
    },
    "high": {
        "summary": (
            "Serious impact but gated by a privilege, a precondition, or limited "
            "to a single victim/tenant at a time."
        ),
        "examples": [
            "Authenticated RCE, or RCE requiring low-privilege access",
            "BOLA / IDOR reading another user's or tenant's data",
            "BFLA / vertical privilege escalation (invoke admin function as a normal user)",
            "SQLi / NoSQLi / SSTI / XXE with confirmed (non-blind) data access",
            "Mass assignment that elevates role/privilege (e.g. isAdmin=true)",
            "JWT bypass — alg=none, key confusion, signature not verified",
            "SSRF reaching internal services or cloud metadata (IMDS)",
            "Stored XSS executing in an authenticated/admin context",
            "File upload to a web-executable path with confirmed execution",
        ],
    },
    "medium": {
        "summary": (
            "Real weakness, but exploitation needs inference/OOB, user interaction, "
            "chaining, or yields limited/no direct sensitive data on its own."
        ),
        "examples": [
            "Blind SQLi / SSTI / XXE (OOB or boolean/time inference), or injection without proven data access",
            "Reflected or DOM XSS",
            "SSRF that cannot reach sensitive internal targets",
            "Mass assignment of non-privileged fields",
            "CSRF on a meaningful state-changing action",
            "Sensitive info disclosure that aids attack (stack traces, internal paths, secrets in errors)",
            "Missing rate limiting on auth / financial / resource-costly endpoints",
            "Weak session management or fixation",
            "Open redirect usable in phishing or OAuth token-theft chains",
        ],
    },
    "low": {
        "summary": (
            "Hardening gap or theoretical issue with no demonstrated exploitation "
            "path in this application's context."
        ),
        "examples": [
            "Verbose errors with no sensitive content",
            "Missing security headers (CSP, HSTS, X-Frame-Options)",
            "CORS misconfiguration with NO credential/exploitability path "
            "(e.g. the app authenticates via bearer headers, not cookies)",
            "Deprecated TLS version offered alongside a modern one",
            "Missing cookie flags on non-session cookies; autocomplete on sensitive fields",
        ],
    },
    "info": {
        "summary": "Not a vulnerability — context, identification, or a working control.",
        "examples": [
            "Technology/version identification with no direct exploit",
            "A defensive control behaving as intended",
            "Best-practice / hardening note for the report's context section",
        ],
    },
}


# Advisory keyword signals. These never decide severity — they only let the
# directive FLAG a finding whose asserted severity reads inflated relative to
# its own description, so the reviewer pays extra attention. Conservative on
# purpose: a flag means "double-check", not "wrong".
_HIGH_IMPACT_TERMS = (
    "rce", "remote code execution", "code execution", "command injection",
    "deserialization", "auth bypass", "authentication bypass", "admin access",
    "privilege escalation", "account takeover", "cross-tenant", "data exfiltration",
    "database dump", "idor", "bola", "bfla", "ssti", "ssrf", "sql injection",
    "sqli", "xxe", "arbitrary file", "credential", "secret", "token theft",
    "exfiltrate", "dump", "read other", "another user", "another tenant",
)

_LOW_IMPACT_TERMS = (
    "missing header", "security header", "verbose error", "stack trace only",
    "informational", "best practice", "hardening", "version disclosure",
    "banner", "autocomplete", "deprecated tls", "cookie flag", "no exploit",
    "theoretical", "not exploitable",
)


def rubric_text() -> str:
    """Compact Markdown rendering of the rubric for embedding in a directive."""
    lines = ["SEVERITY RUBRIC (rate every finding against THIS, not an ad-hoc scale):"]
    for sev in SEVERITIES:
        band = RUBRIC[sev]
        lines.append(f"\n{sev.upper()} — {band['summary']}")
        for ex in band["examples"]:
            lines.append(f"  - {ex}")
    return "\n".join(lines)


def validate_severity_vs_impact(severity: str, description: str) -> tuple[bool, str | None]:
    """Advisory check: does the asserted severity look plausible for the text?

    Returns (ok, hint). ok=False only flags an *egregious* mismatch — a
    critical/high finding whose description contains only low-impact language
    and none of the high-impact terms. Never authoritative; the reviewer's
    contextual judgement always wins.
    """
    sev = (severity or "").strip().lower()
    text = (description or "").lower()
    if sev not in ("critical", "high"):
        return True, None
    has_high = any(t in text for t in _HIGH_IMPACT_TERMS)
    has_low = any(t in text for t in _LOW_IMPACT_TERMS)
    if not has_high and has_low:
        return False, (
            f"asserted {sev.upper()} but the description reads like a low-impact / "
            "hardening issue — confirm there is a real exploitation path before keeping it high"
        )
    return True, None
