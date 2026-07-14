"""Minimal smith-event event-store primitives (training-data-plan.md §3, §3.1-§3.6, §8, §13).

Deliberately dependency-light (stdlib only) so the acceptance suite runs anywhere. The store folds
an append-only event log into materialized state (Replay/Correction), the Redactor gives consistent
engagement-scoped HMAC placeholders (Redaction), resolve_span reconstructs exactly what the model
saw (Span integrity), and render_sft_example builds a leakage-safe training example with lineage
(Temporal leakage / Lineage).
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import pathlib


def digest(obj) -> str:
    """Canonical §13 serialization: sorted keys, no whitespace, UTF-8. Matches build_derived.py."""
    b = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(b).hexdigest()


def load_jsonl(path) -> list[dict]:
    return [json.loads(x) for x in pathlib.Path(path).read_text().splitlines() if x.strip()]


class Redactor:
    """Engagement-scoped HMAC placeholders (§8). ``placeholder_id = HMAC(key, type\\x00value)``; the
    display label ``<TYPE_n>`` is assigned in first-seen order and is stable per value. The HMAC key
    lives OUTSIDE the corpus and no reverse map is stored — the same value yields the same label
    within an engagement, and a DIFFERENT engagement_key yields different labels (no cross-linking)."""

    def __init__(self, engagement_key: bytes):
        self.key = engagement_key
        self._label: dict[str, str] = {}   # hmac_hex -> label
        self._counts: dict[str, int] = {}  # entity_type -> n

    def placeholder_id(self, entity_type: str, normalized_value: str) -> str:
        return hmac.new(self.key, f"{entity_type}\x00{normalized_value}".encode(), hashlib.sha256).hexdigest()

    def label(self, entity_type: str, normalized_value: str) -> str:
        h = self.placeholder_id(entity_type, normalized_value)
        if h not in self._label:
            self._counts[entity_type] = self._counts.get(entity_type, 0) + 1
            self._label[h] = f"<{entity_type.upper()}_{self._counts[entity_type]}>"
        return self._label[h]


def resolve_span(artifact_bytes: bytes, visible_spans: dict) -> str:
    """Reconstruct exactly what the model saw from coordinate-system-tagged spans (§3.5)."""
    cs = visible_spans["coordinate_system"]
    if cs != "utf8_byte_offset":
        raise ValueError(f"unsupported coordinate_system {cs!r}")
    out = b"".join(artifact_bytes[s["start"]:s["end_exclusive"]] for s in visible_spans["spans"])
    return out.decode("utf-8")


def dpo_exportable(pref_record: dict) -> bool:
    """Preference-quality gate (§7): P0 (mined from unrelated historical states) is never usable
    for preference training; P1-P3 are."""
    return pref_record.get("level") in ("P1", "P2", "P3")


class Store:
    def __init__(self, events: list[dict]):
        self.events = sorted(events, key=lambda e: e["sequence"])
        self.by_id = {e["event_id"]: e for e in self.events}

    def causal_parents(self, ev: dict) -> list[str]:
        return list(ev.get("caused_by", [])) + list(ev.get("depends_on", []))

    def superseded_ids(self, at_sequence: int | None = None) -> set[str]:
        out: set[str] = set()
        for e in self.events:
            if at_sequence is not None and e["sequence"] > at_sequence:
                continue
            if e.get("event_type") == "adjudication":
                out.update(e.get("supersedes", []))
        return out

    def fold(self, at_sequence: int | None = None, apply_corrections: bool = True) -> dict:
        """Materialize {observed_state, belief_state} by folding state_ops in sequence order,
        SKIPPING contributions from superseded events (Correction: derived state changes, history
        untouched). dict values merge per key; scalars replace. apply_corrections=False ignores
        supersessions — used to show the fold DIFFERS with vs without the correction."""
        superseded = self.superseded_ids(at_sequence) if apply_corrections else set()
        state = {"observed": {}, "belief": {}}
        for e in self.events:
            if at_sequence is not None and e["sequence"] > at_sequence:
                continue
            if e["event_id"] in superseded:
                continue
            for op in e.get("state_ops", []):
                layer = state[op["layer"]]
                key, val = op["key"], op["value"]
                if isinstance(val, dict) and isinstance(layer.get(key), dict):
                    layer[key].update(val)
                elif isinstance(val, dict):
                    layer[key] = dict(val)
                else:
                    layer[key] = val
        return {"observed_state": state["observed"], "belief_state": state["belief"]}

    def snapshot(self, at_sequence: int | None = None) -> dict:
        folded = self.fold(at_sequence)
        return {**folded, "state_hash": digest(folded)}

    def decisions(self) -> list[dict]:
        return [e for e in self.events if e.get("event_type") == "decision"]

    def render_sft_example(self, decision_ev: dict) -> dict:
        """Build a leakage-safe SFT example (§3.3): includes ONLY evidence the model actually saw,
        and attaches lineage back to events/artifacts/engagement/policy (§13 Lineage)."""
        d = decision_ev["decision"]
        visible = [r for r in d.get("supporting_observations", [])
                   if r.get("visible_at_decision") and not r.get("discovered_after_decision")
                   and not r.get("hidden_ground_truth")]
        rt = d.get("runtime_versions", {})
        example = {
            "messages": [
                {"role": "system", "content": "You are a penetration-testing agent."},
                {"role": "user", "content": {"goal": d["goal"], "visible_evidence": [r["artifact_ref"] for r in visible]}},
                {"role": "assistant", "content": {"tool": d["chosen_tool"], "operation": d["operation"], "params": copy.deepcopy(d.get("params", {}))}},
            ],
            "lineage": {
                "engagement_id": decision_ev["engagement_id"],
                "decision_event_id": decision_ev["event_id"],
                "evidence_artifacts": [r["artifact_ref"] for r in visible],
                "policy_version": rt.get("policy_version"),
                "context_manifest_id": d.get("context_manifest_id"),
                "teacher_origin": d.get("provenance", {}).get("teacher_origin"),
            },
        }
        return example
