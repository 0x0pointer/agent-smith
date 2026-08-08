#!/usr/bin/env python3
"""Freeze acceptance: validate a REAL emitted event stream (+ harvested decisions) against the
smith-event schemas and the §15.1 invariants (training-data-plan.md). The schema is frozen once a
real scan's stream passes this — not just the hand-authored fixture (validate.py) or the event-store
logic tests (acceptance.py).

Checks: schema conformance · unique+monotonic sequence · causal DAG (parents exist, lower sequence) ·
result↔action linkage · harvested-decision `explains` resolves and is NOT causal · secret-leak scan ·
event-type census.

  python training-data/eventstore/validate_stream.py --events logs/smith-events/<id>.jsonl
  python training-data/eventstore/validate_stream.py --latest
Exit 0 = pass, 1 = any error.
"""
import argparse
import collections
import json
import pathlib
import re
import sys

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

SCHEMAS = pathlib.Path(__file__).resolve().parents[1] / "schemas"
_RES = [(json.loads(f.read_text())["$id"], Resource.from_contents(json.loads(f.read_text())))
        for f in sorted(SCHEMAS.glob("*.json"))]
_REG = Registry().with_resources(_RES)
_BY = {i: r.contents for i, r in _RES}
EVENT_SCHEMA = {
    "observation": "observation-event.schema.json", "decision": "decision-event.schema.json",
    "action": "action-event.schema.json", "result": "result-event.schema.json",
    "adjudication": "adjudication-event.schema.json", "finding": "finding-event.schema.json",
    "coverage_transition": "coverage-transition-event.schema.json",
}
LEAK_PATTERNS = [
    (r"eyJ[A-Za-z0-9_-]{20,}", "JWT"),
    (r"Bearer\s+[A-Za-z0-9._~+/-]{20,}", "bearer token"),
    (r"AKIA[0-9A-Z]{16}", "AWS key"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private key"),
]


def _load(path):
    return [json.loads(x) for x in path.read_text().splitlines() if x.strip()]


def _schema_conformance(events, errors):
    for i, e in enumerate(events, 1):
        sid = EVENT_SCHEMA.get(e.get("event_type"))
        if not sid:
            errors.append(f"line {i}: unknown event_type {e.get('event_type')!r}")
            continue
        for err in Draft202012Validator(_BY[sid], registry=_REG).iter_errors(e):
            errors.append(f"line {i} ({e['event_type']}): {err.message} @ /{'/'.join(map(str, err.path))}")


def _sequence_and_dag(events, errors):
    by_id, seqs = {}, []
    for e in events:
        by_id[e["event_id"]] = e
        seqs.append(e["sequence"])
    if len(set(seqs)) != len(seqs):
        errors.append(f"sequence not unique ({len(seqs) - len(set(seqs))} dups)")
    if seqs != sorted(seqs):
        errors.append("sequence not monotonic in file order")
    for e in events:
        for parent in e.get("caused_by", []) + e.get("depends_on", []):
            if parent not in by_id:
                errors.append(f"{e['event_type']} {e['event_id'][:10]}: causal parent {parent[:10]} missing")
            elif by_id[parent]["sequence"] >= e["sequence"]:
                errors.append(f"{e['event_type']} seq {e['sequence']}: parent seq {by_id[parent]['sequence']} not lower")


def _result_linkage(events, errors):
    kinds = {e["event_id"]: e["event_type"] for e in events}
    for e in events:
        if e["event_type"] == "result":
            cb = e.get("caused_by") or []
            if len(cb) != 1 or kinds.get(cb[0]) != "action":
                errors.append(f"result seq {e['sequence']}: caused_by must be exactly one action")


def _harvested_decisions(events, decisions, errors):
    action_ids = {e["event_id"] for e in events if e["event_type"] == "action"}
    for d in decisions:
        exp = d.get("explains") or []
        if not exp or any(a not in action_ids for a in exp):
            errors.append(f"harvested decision {d['event_id'][:10]}: explains does not resolve to a real action")
        if set(exp) & set(d.get("caused_by", [])):
            errors.append(f"harvested decision {d['event_id'][:10]}: explains leaked into caused_by (must stay non-causal)")
        for err in Draft202012Validator(_BY["decision-event.schema.json"], registry=_REG).iter_errors(d):
            errors.append(f"harvested decision {d['event_id'][:10]}: {err.message}")


def _leak_scan(raw_text, errors):
    for pat, label in LEAK_PATTERNS:
        if re.search(pat, raw_text):
            errors.append(f"LEAK: {label} pattern present in the stream")


def _artifact_completeness(events, events_path, errors):
    """Every referenced artifact (result.artifact_id, finding.proof_artifact_id) must be durably
    retained in the engagement bundle logs/smith-events/<id>/ — else the training data points at
    observation content that was wiped. Returns how many resolve. No refs -> nothing to check."""
    refs = {r for e in events for r in
            (e.get("result", {}).get("artifact_id"), e.get("finding", {}).get("proof_artifact_id")) if r}
    if not refs:
        return 0
    bundle = events_path.parent / events_path.stem  # logs/smith-events/<id>/
    if not bundle.is_dir():
        errors.append(f"[BUNDLE] {len(refs)} artifacts referenced but no durable bundle at {bundle.name}/ — "
                      "observation content was not retained")
        return 0
    missing = sorted(r for r in refs if not (bundle / f"{r}.txt").exists())
    if missing:
        errors.append(f"[BUNDLE] {len(missing)}/{len(refs)} referenced artifacts missing from {bundle.name}/ "
                      f"(e.g. {missing[0]})")
    return len(refs) - len(missing)


def validate_stream(events_path, decisions_path=None):
    errors = []
    events = _load(events_path)
    decisions = _load(decisions_path) if decisions_path and decisions_path.exists() else []
    if not events:
        return {"ok": False, "errors": ["empty event stream"], "census": {}}
    _schema_conformance(events, errors)
    _sequence_and_dag(events, errors)
    _result_linkage(events, errors)
    _harvested_decisions(events, decisions, errors)
    _leak_scan(events_path.read_text() + ("\n" + decisions_path.read_text() if decisions else ""), errors)
    retained = _artifact_completeness(events, events_path, errors)
    census = collections.Counter(e["event_type"] for e in events)
    census["artifacts_retained"] = retained
    census["harvested_decision"] = len(decisions)
    return {"ok": not errors, "errors": errors, "census": dict(census), "events": len(events)}


def main():
    ap = argparse.ArgumentParser(description="Freeze-acceptance validator for a real smith-event stream.")
    ap.add_argument("--events")
    ap.add_argument("--decisions")
    ap.add_argument("--latest", action="store_true")
    a = ap.parse_args()
    if a.latest and not a.events:
        d = pathlib.Path(__file__).resolve().parents[2] / "logs" / "smith-events"
        streams = [f for f in d.glob("*.jsonl") if "decisions" not in f.name]
        a.events = str(max(streams, key=lambda f: f.stat().st_mtime)) if streams else ""
    if not a.events:
        ap.error("need --events (or --latest)")
    ev = pathlib.Path(a.events)
    dec = pathlib.Path(a.decisions) if a.decisions else ev.with_suffix(".decisions.jsonl")
    res = validate_stream(ev, dec)
    print(f"census: {res['census']}")
    if res["ok"]:
        print(f"PASS: {res['events']} events + {res['census'].get('harvested_decision', 0)} harvested decisions — "
              "schema + sequence + DAG + linkage + no-leak")
        sys.exit(0)
    print(f"FAIL ({len(res['errors'])}):")
    for e in res["errors"][:40]:
        print("  " + e)
    sys.exit(1)


if __name__ == "__main__":
    main()
