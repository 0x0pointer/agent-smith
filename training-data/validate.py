#!/usr/bin/env python3
"""Validate the lab-engagement-001 fixture against the smith-event schemas and run the §15.1
acceptance checks that need no external infra (training-data-plan.md).

Schema conformance   every event + standalone doc validates against its schema
Evidence derivation  recompute dimensions + V-level from primitives (§5)
DAG ordering         no causal parent holds a >= sequence than its child (§3.1)
Trust boundary       untrusted content is never rendered with instruction authority (§3)
Correction edge      adjudication.supersedes is a correction edge, never a causal (caused_by) edge (§3.1)
State-layer isolation nothing writes the latent layer; latent refs stay evaluator-only (§3.2)
Teacher gate         only teacher_origin=open_weight records are exportable (§12)
Context replay       rendered_prompt_hash recomputes from the manifest components (§3.6)
Snapshot integrity   state_hash recomputes from {observed_state, belief_state} (§3, Replay anchor)
Release reprod.      canonical_manifest_digest recomputes deterministically, twice == stored (§13)

Run:  .venv/bin/python training-data/build_derived.py   # once, to bake derived digests
      .venv/bin/python training-data/validate.py
Exit 0 = all pass, 1 = any failure.
"""
import hashlib
import json
import pathlib
import sys

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = pathlib.Path(__file__).parent
SCHEMAS = ROOT / "schemas"
FX = ROOT / "fixtures" / "lab-engagement-001"

RESOURCES = [(json.loads(f.read_text())["$id"], Resource.from_contents(json.loads(f.read_text())))
             for f in sorted(SCHEMAS.glob("*.json"))]
REGISTRY = Registry().with_resources(RESOURCES)
SCHEMA_BY_ID = {sid: res.contents for sid, res in RESOURCES}

EVENT_SCHEMA = {
    "observation": "observation-event.schema.json",
    "decision": "decision-event.schema.json",
    "action": "action-event.schema.json",
    "result": "result-event.schema.json",
    "adjudication": "adjudication-event.schema.json",
}


def digest(obj) -> str:
    """Canonical §13 serialization: sorted keys, no whitespace, UTF-8. Matches build_derived.py."""
    b = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(b).hexdigest()


def derive_level(p, theta=0.8):
    repro = p["success_count"] / max(p["attempt_count"], 1)
    indep = min(p["independent_method_count"], 3)
    directness = 2 if p["is_deterministic"] else (1 if p["success_count"] > 0 else 0)
    impact = 1 if p.get("impact_observed") else 0
    human = p.get("human_review_count", 0) > 0
    if human and repro >= theta and indep >= 2:
        return "V5"
    if indep >= 2 and repro >= theta:
        return "V4"
    if directness == 2 and p["success_count"] >= 1:
        return "V3"
    if repro >= theta and impact >= 1:
        return "V2"
    if p["independent_method_count"] >= 1 or p["success_count"] >= 1:
        return "V1"
    return "V0"


def exportable(decision_ev):
    """Teacher gate (§12): a record is exportable only if its proposing model is open-weight."""
    return decision_ev.get("decision", {}).get("provenance", {}).get("teacher_origin") == "open_weight"


def check(validator_schema_id, doc, errors, label):
    v = Draft202012Validator(SCHEMA_BY_ID[validator_schema_id], registry=REGISTRY)
    for e in v.iter_errors(doc):
        errors.append(f"[SCHEMA] {label}: {e.message} @ /{'/'.join(map(str, e.path))}")


def main():
    errors = []
    events = [json.loads(x) for x in (FX / "events.jsonl").read_text().splitlines() if x.strip()]
    manifests = [json.loads(x) for x in (FX / "context-manifests.jsonl").read_text().splitlines() if x.strip()]
    snapshot = json.loads((FX / "expected-snapshots" / "snapshot-seq5.json").read_text())
    release = json.loads((FX / "expected-exports" / "release-smith-dataset-0.1.0.json").read_text())

    # 1. Schema conformance
    for i, ev in enumerate(events, 1):
        sid = EVENT_SCHEMA.get(ev.get("event_type"))
        if sid:
            check(sid, ev, errors, f"event {i} ({ev['event_type']})")
    for m in manifests:
        check("context-manifest.schema.json", m, errors, f"manifest {m['context_manifest_id']}")
    check("state-snapshot.schema.json", snapshot, errors, "snapshot-seq5")
    check("release-manifest.schema.json", release, errors, "release-0.1.0")
    print(f"  schema conformance: {len(events)} events + {len(manifests)} manifests + snapshot + release")

    # 2. Evidence derivation (§5)
    for ev in events:
        evd = ev.get("result", {}).get("evidence")
        if evd:
            want, got = derive_level(evd["primitives"]), evd.get("level")
            (errors.append(f"[DERIVATION] stored {got} != recomputed {want}") if want != got
             else print(f"  evidence derivation: level {got} reproduces from primitives"))

    # 3. DAG ordering (§3.1)
    seq = {ev["event_id"]: ev["sequence"] for ev in events}
    for ev in events:
        for parent in ev.get("caused_by", []) + ev.get("depends_on", []):
            if parent in seq and seq[parent] >= ev["sequence"]:
                errors.append(f"[DAG] parent {parent} seq {seq[parent]} >= child seq {ev['sequence']}")
    print("  DAG ordering: causal parents precede children")

    # 4. Trust boundary (§3)
    for ev in events:
        t = ev.get("observation", {}).get("trust")
        if t and t.get("trust") == "untrusted" and (t.get("rendering") != "data" or t.get("instruction_authority")):
            errors.append("[TRUST] untrusted content not confined to data")
    print("  trust boundary: untrusted content confined to data")

    # 5. Correction edge (§3.1): supersedes never appears in caused_by; target exists
    for ev in events:
        if ev.get("event_type") == "adjudication":
            sup = ev.get("supersedes", [])
            if not sup:
                errors.append("[CORRECTION] adjudication with no supersedes target")
            if set(sup) & set(ev.get("caused_by", [])):
                errors.append("[CORRECTION] supersedes leaked into caused_by (correction became causal)")
            for tid in sup:
                if tid not in seq:
                    errors.append(f"[CORRECTION] supersedes target {tid} not in graph")
    print("  correction edge: supersedes is a correction edge, not causal")

    # 6. State-layer isolation (§3.2)
    for ev in events:
        if ev.get("observation", {}).get("updates_state_layer") == "latent":
            errors.append("[STATE-LAYER] an observation wrote the latent layer (must be observed/belief)")
    if snapshot["latent_ground_truth_ref"] is not None:
        errors.append("[STATE-LAYER] non-oracle snapshot has a non-null latent_ground_truth_ref")
    print("  state-layer isolation: nothing writes latent; latent stays evaluator-only")

    # 7. Teacher gate (§12) — positive (fixture) + negative (synthetic proprietary)
    for ev in events:
        if ev.get("event_type") == "decision" and not exportable(ev):
            errors.append("[TEACHER-GATE] a non-open_weight decision is marked exportable")
    proprietary = {"decision": {"provenance": {"teacher_origin": "proprietary"}}}
    if exportable(proprietary):
        errors.append("[TEACHER-GATE] exporter would accept a proprietary-teacher record")
    print("  teacher gate: only open_weight records exportable (proprietary rejected)")

    # 8. Context replay (§3.6)
    for m in manifests:
        want = digest(sorted(m["components"], key=lambda c: c["ordinal"]))
        if want != m["rendered_prompt_hash"]:
            errors.append(f"[CONTEXT-REPLAY] {m['context_manifest_id']}: rendered_prompt_hash mismatch (run build_derived.py)")
        else:
            print(f"  context replay: {m['context_manifest_id']} reconstructs + hash-verifies")
    # decision.context_manifest_id resolves
    mids = {m["context_manifest_id"] for m in manifests}
    for ev in events:
        cid = ev.get("decision", {}).get("context_manifest_id")
        if cid and cid not in mids:
            errors.append(f"[CONTEXT-REPLAY] decision references missing manifest {cid}")

    # 9. Snapshot integrity / Replay anchor (§3)
    want = digest({"observed_state": snapshot["observed_state"], "belief_state": snapshot["belief_state"]})
    if want != snapshot["state_hash"]:
        errors.append("[SNAPSHOT] state_hash mismatch (run build_derived.py)")
    else:
        print("  snapshot integrity: state_hash reproduces from state layers")

    # 10. Release reproducibility (§13) — deterministic twice, and == stored
    body = {k: v for k, v in release.items() if k != "canonical_manifest_digest"}
    d1, d2 = digest(body), digest(body)
    if d1 != d2:
        errors.append("[RELEASE] canonical digest is non-deterministic")
    elif d1 != release["canonical_manifest_digest"]:
        errors.append("[RELEASE] canonical_manifest_digest mismatch (run build_derived.py)")
    else:
        print("  release reproducibility: canonical digest deterministic + matches stored")

    if errors:
        print("\nFAIL:")
        for e in errors:
            print("  " + e)
        sys.exit(1)
    print(f"\nPASS: {len(events)} events + 3 docs valid against smith-event/1.0 + 10 acceptance checks")


if __name__ == "__main__":
    main()
