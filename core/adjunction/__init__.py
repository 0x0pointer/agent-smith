"""
adjunction — final-QA finding adjudication
==========================================
A senior-reviewer pass, run as the LAST step before a scan completes, that
re-prompts the driving model (the same "main inference" running the scan — no
separate LLM, no API keys, identical across Claude Code / opencode / Codex) to:

  (1) validate each finding's reproducibility / true-positive status, and
  (2) re-assess its severity against one canonical rubric, reasoning from the
      target's actual context (severity may go down or up).

It rides the existing completion-blocker channel: the gate returns a directive
string, the model records verdicts via report(action='update_finding', ...),
and completion stays blocked until every high/critical finding carries a verdict.

Always on. The only finding-schema addition is the `adjudication` audit-trail
object (see adjunction.verdict).
"""
from __future__ import annotations

from core.adjunction.gate import (
    ADJUDICATION_SEVERITIES,
    adjudication_blockers,
    pending_findings,
)
from core.adjunction.rubric import (
    ANTI_PATTERNS,
    PRINCIPLES,
    RUBRIC,
    SEVERITIES,
    anti_fp_digest,
    anti_fp_text,
    chain_terminal_severity,
    rubric_digest,
    rubric_text,
    severity_rank,
    validate_severity_vs_impact,
)
from core.adjunction.verdict import coerce_adjudication, is_adjudicated

__all__ = [
    "ADJUDICATION_SEVERITIES",
    "adjudication_blockers",
    "pending_findings",
    "is_adjudicated",
    "coerce_adjudication",
    "ANTI_PATTERNS",
    "PRINCIPLES",
    "RUBRIC",
    "SEVERITIES",
    "anti_fp_digest",
    "anti_fp_text",
    "chain_terminal_severity",
    "rubric_digest",
    "rubric_text",
    "severity_rank",
    "validate_severity_vs_impact",
]
