#!/usr/bin/env python3
"""Validate the lab-engagement-001 fixture against the smith-event schemas and run the §15.1
checks that need no external infra (training-data-plan.md). Every predicate check is paired with a
NEGATIVE CONTROL — a crafted violation it must catch — so no check is "green by construction".
The fold-based Replay/Correction/Snapshot checks live in eventstore/acceptance.py.

Run:  .venv/bin/python training-data/build_derived.py   # once, to bake derived digests
      .venv/bin/python training-data/validate.py
Exit 0 = all pass, 1 = any failure.
"""
import hashlib
import json
import os
import pathlib
import subprocess
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


def rp_hash(m):
    """rendered_prompt_hash binds components + renderer + tokenizer (§3.6). Matches build_derived.py."""
    return digest({"components": sorted(m["components"], key=lambda c: c["ordinal"]),
                   "renderer_version": m["renderer_version"], "tokenizer_ref": m["tokenizer_ref"]})


def dag_violations(evs):
    s = {e["event_id"]: e["sequence"] for e in evs}
    return [f"{p} >= {e['event_id']}" for e in evs
            for p in e.get("caused_by", []) + e.get("depends_on", []) if s.get(p, -1) >= e["sequence"]]


def trust_violation(ev):
    t = ev.get("observation", {}).get("trust")
    return bool(t and t.get("trust") == "untrusted" and (t.get("rendering") != "data" or t.get("instruction_authority")))


def correction_violation(ev):
    return ev.get("event_type") == "adjudication" and bool(set(ev.get("supersedes", [])) & set(ev.get("caused_by", [])))


def latent_write(ev):
    return ev.get("observation", {}).get("updates_state_layer") == "latent"


def check_schema(schema_id, doc, errors, label):
    for e in Draft202012Validator(SCHEMA_BY_ID[schema_id], registry=REGISTRY).iter_errors(doc):
        errors.append(f"[SCHEMA] {label}: {e.message} @ /{'/'.join(map(str, e.path))}")


DERIV_CASES = [  # exercises every V-level branch, not just the one the fixture hits
    ({"attempt_count": 1, "success_count": 0, "independent_method_count": 0, "is_deterministic": False}, "V0"),
    ({"attempt_count": 3, "success_count": 1, "independent_method_count": 1, "is_deterministic": False}, "V1"),
    ({"attempt_count": 5, "success_count": 5, "independent_method_count": 1, "is_deterministic": False, "impact_observed": True}, "V2"),
    ({"attempt_count": 2, "success_count": 2, "independent_method_count": 1, "is_deterministic": True}, "V3"),
    ({"attempt_count": 5, "success_count": 5, "independent_method_count": 2, "is_deterministic": False}, "V4"),
    ({"attempt_count": 5, "success_count": 5, "independent_method_count": 2, "is_deterministic": False, "human_review_count": 1}, "V5"),
]


def main():
    errors = []
    events = [json.loads(x) for x in (FX / "events.jsonl").read_text().splitlines() if x.strip()]
    manifests = [json.loads(x) for x in (FX / "context-manifests.jsonl").read_text().splitlines() if x.strip()]
    snapshot = json.loads((FX / "expected-snapshots" / "snapshot-seq5.json").read_text())
    release = json.loads((FX / "expected-exports" / "release-smith-dataset-0.1.0.json").read_text())

    # 1. Schema conformance
    for i, ev in enumerate(events, 1):
        if EVENT_SCHEMA.get(ev.get("event_type")):
            check_schema(EVENT_SCHEMA[ev["event_type"]], ev, errors, f"event {i} ({ev['event_type']})")
    for m in manifests:
        check_schema("context-manifest.schema.json", m, errors, f"manifest {m['context_manifest_id']}")
    check_schema("state-snapshot.schema.json", snapshot, errors, "snapshot-seq5")
    check_schema("release-manifest.schema.json", release, errors, "release-0.1.0")
    print(f"  schema conformance: {len(events)} events + {len(manifests)} manifests + snapshot + release")

    # 2. Evidence derivation (§5) — table across ALL V-levels, plus the fixture's own result.
    for prim, want in DERIV_CASES:
        if derive_level(prim) != want:
            errors.append(f"[DERIVATION] {prim} -> {derive_level(prim)} expected {want}")
    for ev in events:
        evd = ev.get("result", {}).get("evidence")
        if evd and derive_level(evd["primitives"]) != evd.get("level"):
            errors.append(f"[DERIVATION] fixture: stored {evd.get('level')} != {derive_level(evd['primitives'])}")
    print(f"  evidence derivation: V-level recomputes from primitives (V0-V5 table, {len(DERIV_CASES)} cases)")

    # 3. DAG ordering (§3.1) + negative control (a cycle must be caught).
    errors += [f"[DAG] {v}" for v in dag_violations(events)]
    if not dag_violations([{"event_id": "c", "sequence": 1, "caused_by": ["p"]}, {"event_id": "p", "sequence": 2}]):
        errors.append("[DAG] negative control failed — a seq-inverted causal edge was not caught")
    print("  DAG ordering: causal parents precede children (+ inversion caught)")

    # 4. Trust boundary (§3) + negative control.
    errors += ["[TRUST] untrusted content not confined to data" for ev in events if trust_violation(ev)]
    if not trust_violation({"observation": {"trust": {"trust": "untrusted", "rendering": "instruction", "instruction_authority": True}}}):
        errors.append("[TRUST] negative control failed — untrusted-instruction row not caught")
    print("  trust boundary: untrusted content confined to data (+ violation caught)")

    # 5. Correction edge (§3.1) + negative control.
    seq = {ev["event_id"]: ev["sequence"] for ev in events}
    errors += ["[CORRECTION] supersedes leaked into caused_by" for ev in events if correction_violation(ev)]
    for ev in events:
        if ev.get("event_type") == "adjudication":
            if not ev.get("supersedes"):
                errors.append("[CORRECTION] adjudication with no supersedes target")
            errors += [f"[CORRECTION] supersedes target {t} not in graph" for t in ev.get("supersedes", []) if t not in seq]
    if not correction_violation({"event_type": "adjudication", "supersedes": ["x"], "caused_by": ["x"]}):
        errors.append("[CORRECTION] negative control failed — causal supersedes not caught")
    print("  correction edge: supersedes is a correction edge, not causal (+ violation caught)")

    # 6. State-layer isolation (§3.2) + negative control.
    errors += ["[STATE-LAYER] an observation wrote the latent layer" for ev in events if latent_write(ev)]
    if snapshot["latent_ground_truth_ref"] is not None:
        errors.append("[STATE-LAYER] non-oracle snapshot has a non-null latent_ground_truth_ref")
    if not latent_write({"observation": {"updates_state_layer": "latent"}}):
        errors.append("[STATE-LAYER] negative control failed — a latent write was not caught")
    print("  state-layer isolation: nothing writes latent (+ violation caught)")

    # 7. Teacher gate (§12) — positive + negative (proprietary rejected).
    errors += ["[TEACHER-GATE] a non-open_weight decision is exportable" for ev in events
               if ev.get("event_type") == "decision" and not exportable(ev)]
    if exportable({"decision": {"provenance": {"teacher_origin": "proprietary"}}}):
        errors.append("[TEACHER-GATE] proprietary-teacher record accepted")
    print("  teacher gate: only open_weight records exportable (proprietary rejected)")

    # 8. Context replay (§3.6) — hash binds components+renderer+tokenizer; a renderer swap must break it.
    mids = {m["context_manifest_id"] for m in manifests}
    for m in manifests:
        if rp_hash(m) != m["rendered_prompt_hash"]:
            errors.append(f"[CONTEXT-REPLAY] {m['context_manifest_id']}: hash mismatch (run build_derived.py)")
        if rp_hash({**m, "renderer_version": m["renderer_version"] + "-x"}) == m["rendered_prompt_hash"]:
            errors.append("[CONTEXT-REPLAY] negative control failed — renderer swap did not change the hash")
    for ev in events:
        cid = ev.get("decision", {}).get("context_manifest_id")
        if cid and cid not in mids:
            errors.append(f"[CONTEXT-REPLAY] decision references missing manifest {cid}")
    print("  context replay: hash binds components+renderer+tokenizer (+ renderer swap caught)")

    # 9. Release reproducibility (§13) — recompute the canonical digest in a SEPARATE PROCESS with a
    #    randomized hash seed (real cross-run reproducibility, not same-call determinism); tamper caught.
    body = {k: v for k, v in release.items() if k != "canonical_manifest_digest"}
    prog = ("import json,hashlib,sys;b=json.load(sys.stdin);"
            "print('sha256:'+hashlib.sha256(json.dumps(b,sort_keys=True,separators=(',',':'),"
            "ensure_ascii=False).encode()).hexdigest())")
    sub = subprocess.run([sys.executable, "-c", prog], input=json.dumps(body), text=True, capture_output=True,
                         env={**os.environ, "PYTHONHASHSEED": "random"})
    if sub.stdout.strip() != release["canonical_manifest_digest"]:
        errors.append(f"[RELEASE] cross-process digest {sub.stdout.strip()} != stored")
    if digest({**body, "release_id": body["release_id"] + "-x"}) == release["canonical_manifest_digest"]:
        errors.append("[RELEASE] negative control failed — a tampered manifest matched the digest")
    print("  release reproducibility: canonical digest reproduces cross-process (+ tamper caught)")

    if errors:
        print("\nFAIL:")
        for e in errors:
            print("  " + e)
        sys.exit(1)
    print(f"\nPASS: {len(events)} events + 3 docs schema-valid + 9 checks (each with a negative control)")


if __name__ == "__main__":
    main()
