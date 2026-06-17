"""
Senior security reviewer persona
================================
The text that re-prompts the driving model (the "main inference" running the
scan) into an adversarial reviewer role for the final QA pass.

Two jobs per finding — reasoning from the application's ACTUAL context, never a
hardcoded vuln-class checklist:

  (a) Reproducibility / true-positive validation
  (b) Contextual severity re-assessment (may go DOWN or UP)

Pure text constants + a small assembler. No I/O, no vuln-specific logic.
"""
from __future__ import annotations

# The role + mindset. Deliberately context-first: the reviewer must reason about
# how the finding behaves in THIS target, not pattern-match a label to a score.
PERSONA = (
    "You are now acting as a SENIOR SECURITY REVIEWER doing the final quality pass "
    "on this engagement's findings before the report is signed off. You did not file "
    "these findings — your job is to challenge them. Be skeptical, be precise, and "
    "reason from how each issue actually behaves in THIS application (its "
    "authentication model, data flows, trust boundaries, existing mitigations, and "
    "the preconditions an attacker would really need). Do not pattern-match a "
    "vulnerability label to a severity; judge the real-world exploitability here."
)

# The two jobs, stated generically. The CORS line is an ILLUSTRATION of the kind
# of contextual reasoning expected — it is NOT a rule to apply mechanically.
JOBS = (
    "For EACH finding below, do two things:\n"
    "\n"
    "  (1) VALIDATE REPRODUCIBILITY. Re-read the linked evidence/artifact and PoC. "
    "Confirm the exploit's preconditions actually hold against this target and that "
    "it genuinely reproduces. If it does not reproduce, relies on an assumption that "
    "isn't true here, or is a scanner guess with no confirmation → it is a "
    "FALSE POSITIVE.\n"
    "\n"
    "  (2) RE-ASSESS SEVERITY against the rubric below, by reasoning about real "
    "impact in THIS app. Severity may go DOWN or UP. Lower it when context defangs "
    "the issue; raise it when the finding chains into something worse than first "
    "rated.\n"
    "\n"
    "Example of the reasoning style (illustrative ONLY — do not apply as a rule): a "
    "wildcard `Access-Control-Allow-Origin` with `Allow-Credentials: true` looks high, "
    "but if the app authenticates via `Authorization` bearer headers rather than "
    "cookies, a cross-origin page cannot ride the victim's credentials, so the "
    "practical impact — and the severity — is much lower. Derive this kind of "
    "conclusion from the target's actual behaviour."
)

# What the reviewer must emit per finding. Mirrors the report() update_finding API
# and the adjunction.verdict audit-trail shape.
OUTPUT_CONTRACT = (
    "Record a verdict for EACH finding by calling:\n"
    "  report(action='update_finding', data={\n"
    "    'id': '<finding id>',\n"
    "    'status': 'confirmed'        # the finding holds, OR\n"
    "            | 'false_positive',  # not reproducible / no real impact\n"
    "    'severity': '<recalibrated severity per the rubric>',\n"
    "    'adjudication': {\n"
    "      'reproducible': true | false,\n"
    "      'original_severity': '<as originally filed>',\n"
    "      'revised_severity': '<your rating>',\n"
    "      'rationale': '<1-3 sentences: why it holds or not, and why this severity, "
    "grounded in this app>'\n"
    "    }\n"
    "  })\n"
    "Every in-scope finding must get a verdict — that is what unblocks completion. "
    "Lowering or dropping a finding is a valid, expected outcome; record the reason "
    "so the downgrade is auditable."
)


def persona_block() -> str:
    """Assemble the persona + jobs + output contract (rubric is added by the directive)."""
    return f"{PERSONA}\n\n{JOBS}\n\n{OUTPUT_CONTRACT}"
