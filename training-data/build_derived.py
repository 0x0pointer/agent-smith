#!/usr/bin/env python3
"""Bake the DERIVED digests into the fixtures (they must be computed, not hand-authored):
  - context manifest  rendered_prompt_hash   = digest(components ordered by ordinal)  §3.6
  - state snapshot     state_hash             = digest({observed_state, belief_state})  §3
  - release manifest   canonical_manifest_digest = digest(manifest minus that field)   §13

Canonical serialization (§13): JSON with sorted keys, no whitespace, UTF-8. validate.py recomputes
these independently and asserts equality — proving the digests reproduce from content.

Run once after editing fixture content:  .venv/bin/python training-data/build_derived.py
"""
import hashlib
import json
import pathlib

FX = pathlib.Path(__file__).parent / "fixtures" / "lab-engagement-001"


def digest(obj) -> str:
    b = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(b).hexdigest()


def bake_context():
    p = FX / "context-manifests.jsonl"
    out = []
    for line in p.read_text().splitlines():
        if not line.strip():
            continue
        m = json.loads(line)
        # Bind renderer + tokenizer into the hash so a renderer/tokenizer SWAP invalidates it
        # (a components-only hash would make a renderer change invisible — §3.6).
        m["rendered_prompt_hash"] = digest({
            "components": sorted(m["components"], key=lambda c: c["ordinal"]),
            "renderer_version": m["renderer_version"],
            "tokenizer_ref": m["tokenizer_ref"],
        })
        out.append(json.dumps(m, ensure_ascii=False))
    p.write_text("\n".join(out) + "\n")


def bake_snapshot():
    p = FX / "expected-snapshots" / "snapshot-seq5.json"
    s = json.loads(p.read_text())
    s["state_hash"] = digest({"observed_state": s["observed_state"], "belief_state": s["belief_state"]})
    p.write_text(json.dumps(s, indent=2, ensure_ascii=False) + "\n")


def bake_release():
    p = FX / "expected-exports" / "release-smith-dataset-0.1.0.json"
    r = json.loads(p.read_text())
    r["canonical_manifest_digest"] = digest({k: v for k, v in r.items() if k != "canonical_manifest_digest"})
    p.write_text(json.dumps(r, indent=2, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    bake_context()
    bake_snapshot()
    bake_release()
    print("baked derived digests: rendered_prompt_hash, state_hash, canonical_manifest_digest")
