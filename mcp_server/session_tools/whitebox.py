"""White-box detection + condensed / white-box iteration-gate briefs."""
import os

from core import findings as findings_store
from core import session as scan_session

import mcp_server.session_tools as _st
from ._common import _THOROUGH_MIN_ITERATIONS


def _is_whitebox_scan() -> bool:
    """Return True when the active scan is a white-box code review rather than a live pentest.

    Signals:
    - set_codebase() was called (PENTEST_TARGET_PATH is set to a local directory)
    - semgrep or trufflehog appear in the tools called this session
    - The active or most-recent skill is 'codebase'
    """
    if os.environ.get("PENTEST_TARGET_PATH"):
        return True
    effective = _st._effective_tools()
    if effective & {"semgrep", "trufflehog"}:
        return True
    current = scan_session.get() or {}
    skill_history = current.get("skill_history", [])
    if skill_history:
        last_skill = skill_history[-1].get("skill", "")
        if last_skill == "codebase":
            return True
        if any(s.get("skill") == "codebase" for s in skill_history):
            return True
    return False


def _deepen_brief_condensed(iteration: int, whitebox: bool) -> str:
    """Short deepen brief for medium/small profiles — 3 concrete next actions, no prose.

    The full multi-thousand-char briefs overwhelm a small-context model; under a
    condensed profile the thorough gate also requires fewer passes (_min_iterations),
    so the brief only needs to point at the highest-value next moves.
    """
    data = findings_store._load()
    criticals = [f for f in data.get("findings", []) if f.get("severity") == "critical"]
    mi = _st._min_iterations()
    if whitebox:
        actions = [
            "Trace each injection-class finding source-to-sink and confirm the sanitizer is "
            "actually bypassable; attach the call chain to the finding's evidence.",
            "Read the trust-boundary interfaces between the top components — what attacker-"
            "controlled value crosses, and is it re-validated on arrival?",
            "For each critical, determine what an attacker reaches AFTER exploiting it and "
            "record escalation_leads.",
        ]
    else:
        actions = [
            "Re-test every tested_clean cell with a deeper technique (higher sqlmap level/risk, "
            "filter-bypass XSS, blind/OOB) — these are your likely false negatives.",
            "Test the next pending coverage cells; mark each in_progress before testing.",
            "Chain the criticals to maximum impact: record escalation_leads + a kill-chain via "
            "report(action='chain').",
        ]
    numbered = "\n".join(f"  {i + 1}. {a}" for i, a in enumerate(actions))
    return (
        f"⛔ ITERATION GATE: analysis pass {iteration}/{mi} done — one condensed deepening pass "
        f"required ({len(criticals)} critical finding(s) on record). Do these, then call "
        f"session(action='complete') again:\n{numbered}"
    )


def _deepen_brief_whitebox(analysis_pass: int) -> str:
    """
    Generate a mandatory re-run brief for white-box code-review iteration gates.
    Each pass deepens the analysis rather than re-running live exploitation tools.
    analysis_pass is 1-indexed: 1 = just finished pass 1, need pass 2; 2 = need pass 3.
    """
    if _st._condensed_directives():
        return _deepen_brief_condensed(analysis_pass, whitebox=True)
    data = findings_store._load()
    findings = data.get("findings", [])
    criticals = [f for f in findings if f.get("severity") == "critical"]
    highs = [f for f in findings if f.get("severity") == "high"]
    finding_summary = f"{len(findings)} findings ({len(criticals)} critical, {len(highs)} high)"

    steps: list[str] = []

    if analysis_pass == 1:
        # Pass 2: deeper cross-component tracing and ASVS gap coverage
        intro = (
            f"⛔ WHITEBOX ITERATION GATE: Analysis pass 1/{_THOROUGH_MIN_ITERATIONS} done — "
            f"thorough white-box review requires {_THOROUGH_MIN_ITERATIONS} passes. "
            "Pass 2 must go deeper: cross-component data flow tracing, ASVS gap coverage, "
            "and second-order flaws. Execute ALL steps below before calling complete() again:"
        )
        steps.append(
            "SOURCE-TO-SINK TRACING — for every injection-class finding (SQL injection, "
            "command injection, SSTI, path traversal, deserialization), trace the full data "
            "flow from the HTTP entry point through every function call to the dangerous sink. "
            "Read each intermediate function to verify whether sanitization actually occurs "
            "or is bypassable. Document the complete call chain in the finding's evidence field."
        )
        steps.append(
            "CROSS-COMPONENT ANALYSIS — read the interfaces between the top 5 highest-risk "
            "components (e.g. FHIRdoor → Aidbox, medikit-experiment → K8s API, "
            "Keycloak/Zitadel → Aidbox). For each interface: what data crosses the trust "
            "boundary? What validation is performed on arrival? What can an attacker-controlled "
            "value at the source become at the destination? Log any new findings from this analysis."
        )
        steps.append(
            "ASVS GAP COVERAGE — go through each ASVS 5.0 chapter not yet covered in pass 1 "
            "and explicitly verify each requirement against the code. Minimum chapters to cover "
            "if not already done: V6 (Authentication), V7 (Session Management), V8 (Authorization), "
            "V9 (Self-contained Tokens), V10 (OAuth/OIDC), V11 (Cryptography), V13 (Configuration), "
            "V14 (Data Protection), V16 (Security Logging). For each chapter, read the relevant "
            "source files and log a finding or note confirming whether each requirement is met."
        )
        steps.append(
            "SECOND-ORDER AND STORED FLAWS — identify all places where user-supplied data is "
            "stored (database, cache, files, K8s secrets, FHIR resources) and then later "
            "retrieved and used in a security-sensitive operation. Does the retrieval path "
            "re-validate the data? Can a value stored safely now be used dangerously later "
            "(stored XSS, second-order SQLi, YAML/pickle deserialization of stored blobs)?"
        )
        steps.append(
            "DEPENDENCY AUDIT — run scan(tool='semgrep') again with 'p/security-audit' and "
            "'p/owasp-top-ten' rulesets if not already run. For every high-severity CVE-tagged "
            "dependency found, trace whether the vulnerable code path is actually reachable "
            "from the application's attack surface."
        )
        if criticals:
            unchained = [f for f in criticals if not f.get("escalation_leads")]
            if unchained:
                titles = ", ".join(f["title"][:50] for f in unchained[:3])
                steps.append(
                    f"KILL CHAIN COMPLETION — {len(unchained)} critical finding(s) have no "
                    f"escalation_leads set ({titles}{'...' if len(unchained) > 3 else ''}). "
                    "For each: read the relevant code to determine what an attacker can do AFTER "
                    "exploiting this finding. What data can be exfiltrated? What next component "
                    "can be reached? What is the maximum blast radius? Update each finding with "
                    "escalation_leads pointing to the next step in the kill chain."
                )

    elif analysis_pass == 2:
        # Pass 3: adversarial mindset — chained attacks, edge cases, maximum coverage
        intro = (
            f"⛔ WHITEBOX ITERATION GATE: Analysis pass 2/{_THOROUGH_MIN_ITERATIONS} done — "
            "one final pass required at maximum adversarial depth. "
            "Pass 3 must find what passes 1 and 2 missed by combining findings and "
            "attacking edge cases. Execute ALL steps below before calling complete() again:"
        )
        steps.append(
            "CHAINED EXPLOIT PATHS — take the top 3 pairs of findings and reason through "
            "whether exploiting finding A makes finding B easier or newly exploitable. "
            "Example patterns: committed secret → auth bypass → RBAC escalation → bulk data read; "
            "CORS bypass + weak session token → cross-site PHI exfiltration; "
            "IMDS access → managed identity → ACR write → supply chain → all pods compromised. "
            "For each viable chain: read the relevant code to confirm the path is real, "
            "then log a new finding (or update existing ones) with the full chain evidence."
        )
        steps.append(
            "BUSINESS LOGIC EDGE CASES — for every FHIR operation and access-control decision "
            "in the codebase, ask: what happens at the boundary? Can a null/empty/zero value "
            "bypass a check? Can a list with zero items pass an 'all items must satisfy X' check? "
            "Can a race condition between two concurrent requests produce an inconsistent state? "
            "Read the relevant policy evaluation code and test edge cases analytically."
        )
        steps.append(
            "CONFIGURATION VS CODE MISMATCHES — compare what the infrastructure configuration "
            "(K8s manifests, ArgoCD values, Terraform) declares vs. what the application code "
            "actually expects. Look for: environment variables the code reads but the manifest "
            "doesn't set (falls back to insecure default); secrets the code expects to be "
            "present but may be absent in some environments; TLS settings the code assumes "
            "but the infra doesn't enforce."
        )
        steps.append(
            "REMAINING ASVS VERIFICATION — go through any ASVS chapters still unverified "
            "from passes 1 and 2. For each unmet requirement, either confirm it is met by "
            "reading the code or log it as a finding. Produce a final ASVS coverage note "
            "using report(action='note') summarising which chapters are covered, which are "
            "partially covered, and which are absent."
        )
        steps.append(
            "END-TO-END POC SCRIPTS — for each critical finding that has only an HTTP template "
            "PoC, write a self-contained Python or shell script that executes the full exploit "
            "from scratch (no manual steps). Save each with http(action='save_poc') and link "
            "it to the finding_id. The script must include: credential/token acquisition, "
            "the exploit request, and verification of impact."
        )

    else:
        intro = (
            f"⛔ WHITEBOX ITERATION GATE: Pass {analysis_pass}/{_THOROUGH_MIN_ITERATIONS} — "
            "quality gates still blocking. Re-run all code review activities at maximum depth."
        )
        steps.append(
            "Re-read every component not yet fully analyzed, deepen every finding with "
            "additional code evidence, and ensure all high/critical findings have complete "
            "source-to-sink call chains documented in their evidence field."
        )

    steps.append(
        f"Current state: {finding_summary}. "
        "After completing ALL steps above, call session(action='complete') again."
    )
    numbered = "\n".join(f"  {i + 1}. {step}" for i, step in enumerate(steps))
    return f"{intro}\n{numbered}"
