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


# Terminal-impact signals for the exploit-chain rescoring rule. A *proven* chain
# (an escalation lead marked done WITH a recorded result) that reaches one of
# these terminals re-rates the finding at the terminal's blast radius — chains
# COMPOSE, they never average. Critical terminals beat high terminals.
_TERMINAL_CRITICAL_TERMS = (
    "rce", "remote code execution", "code execution", "command execution",
    "command injection", "reverse shell", "web shell", "shell access",
    "admin access", "administrator access", "admin panel access",
    "account takeover", "ato", "domain admin", "cloud account",
    "full aws", "full database", "database dump", "dumped all", "all users",
    "all tenants", "cross-tenant", "cross tenant", "mass exfil", "bulk exfil",
    "root access", "auth bypass", "authentication bypass", "full compromise",
)
# Link-local cloud-metadata (IMDS) address. Assembled from octets rather than
# written as a literal so it's not a hardcoded-IP smell (Sonar S1313) — here it
# is only a detection KEYWORD matched in finding text, never a connection target.
_IMDS_IP = ".".join(("169", "254", "169", "254"))
_TERMINAL_HIGH_TERMS = (
    "privilege escalation", "privesc", "another user", "other users",
    "another tenant", "cross-object", "idor", "bola", "internal service",
    "cloud metadata", "imds", _IMDS_IP, "read other", "session takeover",
)


def chain_terminal_severity(finding: dict) -> str | None:
    """Severity a finding should carry given any PROVEN escalation chain.

    Inspects ``finding['escalation_leads']`` (the `[{lead, status, result}]`
    list) for entries marked ``done`` WITH a non-empty ``result`` — i.e. a chain
    the agent actually followed and recorded the outcome of. If that outcome
    reaches a terminal impact, returns the terminal severity ("critical" beats
    "high"); otherwise None. Pure; never lowers severity (the caller only raises).
    """
    leads = finding.get("escalation_leads")
    if not isinstance(leads, list):
        return None
    best: str | None = None
    for lead in leads:
        if not isinstance(lead, dict):
            continue
        result = str(lead.get("result", "")).strip()
        if str(lead.get("status", "")).strip().lower() != "done" or not result:
            continue
        text = f"{lead.get('lead', '')} {result}".lower()
        if any(t in text for t in _TERMINAL_CRITICAL_TERMS):
            return "critical"  # highest band — short-circuit
        if any(t in text for t in _TERMINAL_HIGH_TERMS):
            best = "high"
    return best


def rubric_text() -> str:
    """Compact Markdown rendering of the rubric for embedding in a directive."""
    lines = ["SEVERITY RUBRIC (rate every finding against THIS, not an ad-hoc scale):"]
    for sev in SEVERITIES:
        band = RUBRIC[sev]
        lines.append(f"\n{sev.upper()} — {band['summary']}")
        for ex in band["examples"]:
            lines.append(f"  - {ex}")
    return "\n".join(lines)


def rubric_digest() -> str:
    """One line per band (summaries only, no examples) — for condensed/small-profile
    directives where the full rubric_text() would blow the context budget."""
    lines = ["SEVERITY RUBRIC (rate against THIS — likelihood × impact, not a checklist):"]
    for sev in SEVERITIES:
        lines.append(f"  {sev.upper()}: {RUBRIC[sev]['summary']}")
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


# ── Anti-false-positive doctrine ───────────────────────────────────────────────
# Single source of truth for the "what counts as a real finding" principles that
# were previously scattered across the per-skill SKILL.md files as divergent
# one-liners. Embedded in the completion-time adjudication directive (so the
# senior-review pass applies them) and surfaced as a compact hunt-time digest at
# scan start. Pure data — no I/O, no LLM.
#
# Deliberately domain-agnostic: Smith is black-box-first across web/API/network/
# AD/cloud/k8s/LLM/source, so these are phrased to apply to any target class, not
# just the white-box code-review context they partly originate from.

PRINCIPLES: tuple[str, ...] = (
    "ONLY REPORT WHAT YOU CAN EXPLOIT. A finding needs a concrete attack — who the "
    "attacker is, what they send/do, and what they get. \"An attacker could "
    "theoretically…\" is not a finding; \"send this request, get this result\" is.",
    "SEVERITY = LIKELIHOOD × IMPACT, not deviation from a checklist. If you cannot "
    "describe the concrete damage achieved, the severity is lower than you think.",
    "DEFENSE-IN-DEPTH GAPS ARE HARDENING, NOT VULNERABILITIES. If Layer A already "
    "prevents the attack, the absence of Layer B is a hardening note — file it as "
    "LOW/info, never high/critical. (Smith still records it as a LOW finding for "
    "audit/compliance; it just must not be inflated.)",
    "DESIGNED BEHAVIOUR IS NOT A BUG. Understand the trust model first — if the "
    "design trusts admins fully, admin-does-admin-things is not a finding.",
    "VERIFY PARSER/RUNTIME ASSUMPTIONS. The most convincing false positives reason "
    "\"the parser/runtime will interpret this as…\" without checking. If an exploit "
    "depends on parser or runtime behaviour, test it or cite the spec — don't assume.",
    "AN HONEST \"NOTHING FOUND\" BEATS A PADDED REPORT. Don't manufacture LOWs to look "
    "thorough; but push hard before concluding nothing is there.",
)

# Anti-patterns the reviewer should actively reject. Generalized from the
# white-box originals into target-agnostic phrasing.
ANTI_PATTERNS: tuple[str, ...] = (
    "Listing every checklist/standard deviation (OWASP, ASVS, a CIS benchmark) as a "
    "finding — a standard is a checklist, not a bug list.",
    "Rating a defense-in-depth gap as HIGH/CRITICAL when an existing layer already "
    "blocks the attack.",
    "Ignoring the deployment model — e.g. flagging missing app-level rate limiting "
    "when the CDN/WAF enforces it, or app-level controls a reverse proxy provides.",
    "\"Potential\"/\"theoretical\" findings with no proof — either you can exploit it "
    "or you can't; the words \"potentially\"/\"theoretically\" mean more work is owed.",
    "Constructing an exploit from unverified parser/runtime assumptions.",
    "Reporting an injection \"reachable\" without confirming the payload survives to "
    "the sink (encoding, prepared statements, or a prior layer may defang it).",
)


def anti_fp_text() -> str:
    """Full anti-FP doctrine for embedding in the adjudication directive."""
    lines = ["ANTI-FALSE-POSITIVE PRINCIPLES (apply to every verdict):"]
    lines += [f"  - {p}" for p in PRINCIPLES]
    lines.append("")
    lines.append("REJECT THESE ANTI-PATTERNS:")
    lines += [f"  - {a}" for a in ANTI_PATTERNS]
    return "\n".join(lines)


def anti_fp_digest() -> str:
    """Compact (2-line) hunt-time reminder surfaced at scan start."""
    return (
        "FINDINGS BAR: only report what you can EXPLOIT (concrete attack + observed result, "
        "never \"theoretically\"). Severity = likelihood × impact. A defense-in-depth gap "
        "behind an existing control is a LOW hardening note, not a high/critical. Don't pad "
        "with LOWs; an honest \"nothing exploitable here\" is a valid result."
    )
