"""
Tests for mcp_server.scan_engine.budget — actionable truncation hint.

The user observed Smith (Qwen3.6-35B-A3B-FP8) looping 8+ times trying
variations of the same `python3 -c '...'` command because each kali
response hit the 5000-char budget and Smith kept treating the output
as "truncated, must retry differently" rather than "fetch the artifact".

Before this change there were up to three separate cryptic warnings —
"Truncated N fact(s) — artifact=X", "Evidence truncated — artifact=X",
"Envelope exceeded 5000 char budget — content truncated" (no artifact
hint at all in the third).

After: ONE consolidated warning that spells out the exact next MCP
tool call with the artifact_id substituted into the options dict.
Smaller models that don't reliably synthesise tool calls from short
hints can match-and-execute the literal example instead.
"""
import pytest

from mcp_server.scan_engine.budget import (
    enforce_budget,
    _retrieve_artifact_hint,
    ToolBudget,
)
from mcp_server.scan_engine.envelope import Envelope


# ---------------------------------------------------------------------------
# _retrieve_artifact_hint — message content
# ---------------------------------------------------------------------------

class TestRetrieveArtifactHint:

    def test_contains_explicit_session_artifact_call(self):
        """The whole point: the literal `session(action='artifact', ...)`
        call must appear verbatim with the artifact_id substituted, so
        smaller models can match-and-execute it without inferring the
        pattern from background documentation."""
        hint = _retrieve_artifact_hint("art_abc123", envelope_oversize=True)
        assert "session(action='artifact'" in hint
        assert "'id': 'art_abc123'" in hint or "id: 'art_abc123'" in hint
        assert "mode: 'full'" in hint

    def test_offers_grep_as_cheaper_alternative(self):
        """Progressive disclosure: when Smith only needs a specific row
        (e.g. one CVE in a 200-CVE nuclei dump), grep is far cheaper
        than full. The hint must surface it as an option."""
        hint = _retrieve_artifact_hint("art_xyz", dropped_facts=10)
        assert "mode: 'grep'" in hint
        assert "pattern" in hint

    def test_includes_strong_dont_retry_instruction(self):
        """The model loop happens because Smith reads "truncated" and
        decides to retry with variations. The hint must explicitly tell
        Smith NOT to do that."""
        hint = _retrieve_artifact_hint("art_1", envelope_oversize=True)
        assert "DO NOT" in hint
        assert "re-run" in hint.lower() or "rerun" in hint.lower()

    def test_summarises_what_was_dropped(self):
        """The reason string lets Smith decide whether the truncation
        matters for its current goal (e.g. 'envelope oversize' on a
        scan summary may not need the full artifact, but 'evidence
        keys dropped' definitely does)."""
        hint = _retrieve_artifact_hint(
            "art_1",
            dropped_facts=5,
            dropped_evidence_keys=2,
            envelope_oversize=True,
        )
        assert "5 fact" in hint
        assert "2 evidence key" in hint
        assert "envelope exceeded" in hint.lower()

    def test_default_reason_when_nothing_flagged(self):
        """Defensive: the helper shouldn't crash if called with no
        truncation reasons (it just produces a generic message)."""
        hint = _retrieve_artifact_hint("art_x")
        assert "art_x" in hint
        assert "TRUNCATED" in hint


# ---------------------------------------------------------------------------
# enforce_budget — emits exactly ONE consolidated warning, not 3
# ---------------------------------------------------------------------------

class TestEnforceBudgetWarnings:

    def _budget(self, **overrides):
        b = ToolBudget(max_chars=200, max_facts=2, max_evidence_chars=80)
        for k, v in overrides.items():
            setattr(b, k, v)
        return b

    def test_no_warning_when_under_budget(self):
        """Negative case: a small envelope produces zero warnings.
        This pins down that we don't false-positive on the consolidated
        warning emission gate.

        Budget is bumped well above the indent=2 JSON-serialized minimum
        (~250 chars even for an empty envelope) so the test isolates the
        "under budget" path."""
        env = Envelope(summary="ok", facts=["a"], evidence={"k": "v"})
        result = enforce_budget(env, self._budget(max_chars=2000), "art_1")
        assert result.warnings == []

    def test_dropped_facts_produces_single_warning(self):
        """Previously this emitted "Truncated N fact(s) — artifact=X"
        with no actionable call. Now: one consolidated hint with the
        full session(action='artifact', ...) example."""
        env = Envelope(
            summary="x",
            facts=["a", "b", "c", "d", "e"],  # max_facts=2 → drop 3
        )
        result = enforce_budget(env, self._budget(), "art_facts")
        # Exactly one warning (the consolidated hint), not the old 3-of-3
        assert len(result.warnings) == 1
        assert "art_facts" in result.warnings[0]
        assert "session(action='artifact'" in result.warnings[0]

    def test_dropped_evidence_keys_produces_single_warning(self):
        """Same shape for the evidence-truncation path."""
        env = Envelope(
            summary="x",
            evidence={f"k{i}": "x" * 50 for i in range(10)},  # well over 80
        )
        result = enforce_budget(env, self._budget(), "art_ev")
        assert len(result.warnings) == 1
        assert "art_ev" in result.warnings[0]
        assert "evidence key" in result.warnings[0]

    def test_envelope_oversize_produces_warning_with_artifact_id(self):
        """The bug case: the OLD line 142 warning had no artifact_id at
        all. Now the consolidated warning always carries it so Smith
        can always retrieve the full output."""
        # Force envelope-oversize without facts/evidence drops
        env = Envelope(
            summary="x" * 500,  # well over max_chars=200
            facts=["short"],
            evidence={"k": "v"},
        )
        result = enforce_budget(env, self._budget(), "art_oversize")
        assert len(result.warnings) >= 1
        joined = " ".join(result.warnings)
        assert "art_oversize" in joined
        assert "session(action='artifact'" in joined

    def test_multiple_truncation_reasons_still_single_warning(self):
        """The whole consolidation point: even when facts AND evidence
        AND envelope all overflow simultaneously, Smith gets ONE
        warning with all the reasons + the actionable call. Three
        separate warnings made it easy to skim past."""
        env = Envelope(
            summary="x" * 100,
            facts=["a"] * 10,                                    # max_facts=2
            evidence={f"k{i}": "x" * 50 for i in range(10)},     # max_evidence_chars=80
        )
        result = enforce_budget(env, self._budget(max_chars=150), "art_all")
        assert len(result.warnings) == 1
        w = result.warnings[0]
        assert "fact" in w
        assert "evidence key" in w
        assert "session(action='artifact'" in w
