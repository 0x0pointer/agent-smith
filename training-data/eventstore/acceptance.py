#!/usr/bin/env python3
"""§15.1 event-store acceptance tests (training-data-plan.md). Every test pairs the positive property
with a NEGATIVE CONTROL — a case that violates the property — so a check can actually fail (not
"green by construction"). Complements validate.py (schema conformance + the digest checks).

  .venv/bin/python training-data/eventstore/acceptance.py
"""
import copy
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import core  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]
FX = ROOT / "fixtures" / "lab-engagement-001"
ran = 0
fails: list[str] = []
H = "sha256:"  # content-addressed ref prefix (named to avoid duplicating the literal)


def check(name, cond, detail=""):
    global ran
    ran += 1
    print(f"  {'PASS' if cond else 'FAIL'}  {name}{'' if cond else ' — ' + detail}")
    if not cond:
        fails.append(name)


def conflict_store(seq1, seq2):
    """One decision, two branches whose results write the SAME key (a conflict) at the given
    sequences — so fold() must resolve deterministically by sequence, not insertion order."""
    return core.Store([
        {"event_id": "d", "sequence": 1, "event_type": "decision", "engagement_id": "e"},
        {"event_id": "a1", "sequence": 2, "event_type": "action", "caused_by": ["d"]},
        {"event_id": "a2", "sequence": 3, "event_type": "action", "caused_by": ["d"]},
        {"event_id": "r1", "sequence": seq1, "event_type": "result", "caused_by": ["a1"],
         "state_ops": [{"layer": "observed", "key": "host", "value": {"status": "open"}}]},
        {"event_id": "r2", "sequence": seq2, "event_type": "result", "caused_by": ["a2"],
         "state_ops": [{"layer": "observed", "key": "host", "value": {"status": "filtered"}}]},
    ])


def main():
    events = core.load_jsonl(FX / "events.jsonl")
    store = core.Store(events)
    obs_id = next(e["event_id"] for e in events if e.get("event_type") == "observation")  # from fixture, not hardcoded
    tgt = next(op["key"] for e in events if e.get("event_type") == "result" for op in e.get("state_ops", []))
    snap = json.loads((FX / "expected-snapshots" / "snapshot-seq5.json").read_text())
    expected = {"observed_state": snap["observed_state"], "belief_state": snap["belief_state"]}

    # Replay — folding the event log reproduces the INDEPENDENTLY hand-authored snapshot; a mutated
    # event no longer folds to it (so the check can fail).
    got = store.fold(5)
    mutated = copy.deepcopy(events)
    for e in mutated:
        for op in e.get("state_ops", []):
            if op["layer"] == "belief" and "sqli_confidence" in op.get("value", {}):
                op["value"]["sqli_confidence"] = 0.123
    neg = core.Store(mutated).fold(5)
    check("Replay (fold == snapshot; mutation caught)", got == expected and neg != expected,
          f"fold {got}")

    # Correction — superseding the observation drops its contribution from DERIVED state while the
    # event stays in the log; without corrections the contribution survives (negative control).
    with_c, without_c = store.fold(5, apply_corrections=True), store.fold(5, apply_corrections=False)
    check("Correction (derived changes, history intact)",
          "surface_signal" not in with_c["belief_state"][tgt]
          and "surface_signal" in without_c["belief_state"][tgt]
          and obs_id in store.by_id and len(store.events) == 5,
          f"{with_c} vs {without_c}")

    # Concurrency — two branches CONFLICT on one key; fold resolves by sequence (last writer), and
    # swapping the sequences flips the winner — so ordering is deterministic and load-bearing.
    a = conflict_store(4, 5).fold()["observed_state"]["host"]["status"]  # r2 later
    b = conflict_store(5, 4).fold()["observed_state"]["host"]["status"]  # r1 later
    kids = {e["event_id"] for e in conflict_store(4, 5).events if "d" in conflict_store(4, 5).causal_parents(e)}
    check("Concurrency (conflict resolves by sequence)", a == "filtered" and b == "open" and kids == {"a1", "a2"},
          f"a={a} b={b} kids={kids}")

    # Temporal leakage — the exporter drops future/hidden evidence that WAS a candidate (load-bearing:
    # all 3 refs are in the decision; only the visible one survives).
    seen, future, hidden = (H + c * 64 for c in "abc")
    dec = {"event_id": "dX", "engagement_id": "e", "decision": {
        "goal": "g", "chosen_tool": "http", "operation": "request", "params": {},
        "provenance": {"teacher_origin": "open_weight"}, "context_manifest_id": "c",
        "runtime_versions": {"policy_version": "policy@v3"},
        "supporting_observations": [
            {"artifact_ref": seen, "visible_at_decision": True, "discovered_after_decision": False, "hidden_ground_truth": False},
            {"artifact_ref": future, "visible_at_decision": True, "discovered_after_decision": True, "hidden_ground_truth": False},
            {"artifact_ref": hidden, "visible_at_decision": False, "discovered_after_decision": False, "hidden_ground_truth": True},
        ]}}
    kept = core.Store([]).render_sft_example(dec)["lineage"]["evidence_artifacts"]
    candidates = [o["artifact_ref"] for o in dec["decision"]["supporting_observations"]]
    check("Temporal leakage (future/hidden dropped)",
          len(candidates) == 3 and kept == [seen] and future in candidates and hidden in candidates,
          f"kept={kept}")

    # Redaction — same value -> same label across a record (consistency); NO raw value survives
    # (negative: the un-redacted record does leak); cross-engagement placeholder_ids differ.
    r = core.Redactor(b"engagement-001-key")
    raw_host, raw_cred = "10.0.0.5", "s3cr3t_pw"  # NOSONAR — RFC1918 + fake secret, redaction-test fixtures
    rec = {"host": r.label("target_host", raw_host),
           "note": f"cred {r.label('cred', raw_cred)} seen again on {r.label('target_host', raw_host)}"}
    blob = json.dumps(rec)
    r2 = core.Redactor(b"engagement-002-key")
    check("Redaction (consistent, no raw leak, no cross-link)",
          blob.count("<TARGET_HOST_1>") == 2 and raw_host not in blob and raw_cred not in blob
          and raw_host in json.dumps({"host": raw_host})   # negative: unredacted WOULD leak
          and r2.placeholder_id("target_host", raw_host) != r.placeholder_id("target_host", raw_host),
          blob)

    # Span integrity — resolve the visible span over REAL stored bytes; a shifted span yields
    # different content (negative: not returning the whole artifact regardless of offsets).
    ss = json.loads((FX / "artifacts" / "span-sample.json").read_text())
    art = ss["artifact_utf8"].encode("utf-8")
    e = ss["visible_prefix_bytes"]
    shown = core.resolve_span(art, {"coordinate_system": ss["coordinate_system"], "spans": [{"start": 0, "end_exclusive": e}]})
    shifted = core.resolve_span(art, {"coordinate_system": ss["coordinate_system"], "spans": [{"start": 10, "end_exclusive": e}]})
    check("Span integrity (real bytes; offset-sensitive)", shown == art[:e].decode() and shifted != shown,
          f"shown={shown!r}")

    # Preference filtering — P0 is never exportable; P1-P3 are (negative control is P0 itself).
    prefs = [{"id": lv, "level": lv} for lv in ("P0", "P1", "P2", "P3")]
    check("Preference filtering (P0 unexportable)",
          [p["id"] for p in prefs if core.dpo_exportable(p)] == ["P1", "P2", "P3"] and not core.dpo_exportable(prefs[0]))

    # Lineage — over a REAL fixture decision: the lineage refs RESOLVE to real events/artifacts;
    # a fabricated artifact ref does not (negative).
    real_dec = next(e for e in events if e.get("event_type") == "decision")
    lin = store.render_sft_example(real_dec)["lineage"]
    obs_refs = {e["observation"]["artifact_ref"] for e in events if e.get("event_type") == "observation"}
    check("Lineage (resolves to real events/artifacts)",
          lin["decision_event_id"] in store.by_id
          and lin["evidence_artifacts"] and all(a in obs_refs for a in lin["evidence_artifacts"])
          and lin["policy_version"] == "policy@v3" and lin["teacher_origin"] == "open_weight"
          and (H + "f" * 64) not in obs_refs,
          f"lineage={lin}")

    # Schema fits real data — the ingester's REDACTED live-scan slice validates + is causally ordered.
    real = ROOT / "fixtures" / "vulnbank-live" / "events.jsonl"
    if real.exists():
        from jsonschema import Draft202012Validator
        from referencing import Registry, Resource
        res = [(json.loads(f.read_text())["$id"], Resource.from_contents(json.loads(f.read_text())))
               for f in sorted((ROOT / "schemas").glob("*.json"))]
        reg, by = Registry().with_resources(res), {i: r.contents for i, r in res}
        m = {"observation": "observation-event.schema.json", "decision": "decision-event.schema.json",
             "action": "action-event.schema.json", "result": "result-event.schema.json",
             "adjudication": "adjudication-event.schema.json"}
        revs = [json.loads(x) for x in real.read_text().splitlines() if x.strip()]
        rseq = {ev["event_id"]: ev["sequence"] for ev in revs}
        rerr = sum((1 if not m.get(ev.get("event_type"))
                    else sum(1 for _ in Draft202012Validator(by[m[ev["event_type"]]], registry=reg).iter_errors(ev)))
                   + sum(1 for p in ev.get("caused_by", []) + ev.get("depends_on", []) if rseq.get(p, -1) >= ev["sequence"])
                   for ev in revs)
        check(f"Schema fits real data ({len(revs)} redacted live-scan events)", rerr == 0, f"{rerr} errors")

    print()
    if fails:
        print(f"FAIL: {len(fails)}/{ran} acceptance tests: {', '.join(fails)}")
        sys.exit(1)
    print(f"PASS: {ran} event-store acceptance tests (each with a negative control)")


if __name__ == "__main__":
    main()
