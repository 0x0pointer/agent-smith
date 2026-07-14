# smith-event schema spike (`schemas/` + `fixtures/`)

The implementation package the round-3 critic asked for instead of another prose revision:
JSON Schemas + a validating fixture derived from **`training-data-plan.md` (v1.2)**.
Goal — surface schema defects on real data before freezing `smith-event/1.0`.

```
schemas/     JSON Schema (draft 2020-12), $id = bare filename, relative $refs
fixtures/lab-engagement-001/
  events.jsonl              one decision cycle: observation -> decision -> action -> result
  expected-snapshots/       (pending) state-snapshot hashes for the Replay test
  expected-exports/         (pending) SFT/DPO renderings for the leakage/preference tests
validate.py  validates the fixture + runs the infra-free §15.1 acceptance checks
```

Run:
```bash
.venv/bin/python training-data/validate.py
```

## Schemas → plan sections

| Schema | Status | Plan § |
|---|---|---|
| `common.schema.json` | ✅ | §3, §3.1–3.6, §4, §5 — shared `$defs` (envelope pieces, trust label, capture_mode, provenance+`teacher_origin`, evidence primitives, visible spans, stage hashes) |
| `event-envelope.schema.json` | ✅ | §3.1 — ordering authority; causal DAG = `caused_by`/`depends_on`; `supersedes` is a correction edge |
| `observation-event.schema.json` | ✅ | §3, §3.2 — trust label; writes observed/belief, never latent |
| `decision-event.schema.json` | ✅ | §3, §3.3, §3.6 — captured_field reasoning; `teacher_origin`; `context_manifest_id` |
| `action-event.schema.json` | ✅ | §3.4, §7 — `exact_action_hash` + `semantic_action_family` + behavior fields; `safety_class` |
| `result-event.schema.json` | ✅ | §3.5, §4, §5 — visible spans; 3-layer outcome; evidence primitives |
| `adjudication-event.schema.json` | ⬜ next | §3.1, §4, §5 — retraction/supersession + adjudicated labels |
| `state-snapshot.schema.json` | ⬜ next | §3, §3.2 — latent/observed/belief layers for Replay |
| `context-manifest.schema.json` | ⬜ next | §3.6 — components[{type,ref,ordinal}] + rendered_prompt_hash |
| `release-manifest.schema.json` | ⬜ next | §13 — canonical digests + random_seed |

## Acceptance tests (§15.1) — coverage so far

`validate.py` runs the four that need no external infra:
**Schema conformance**, **Evidence derivation** (recompute V-level from primitives — the §5 rule lives in `derive_level()`), **DAG ordering** (parent.sequence < child.sequence), **Trust boundary** (untrusted → data only).

Pending (need the remaining schemas / an event-store / exporter): Replay, Retraction, Concurrency,
Temporal leakage, Redaction, Span integrity, Context replay, Preference filtering (P0 unexportable),
Release reproducibility, Lineage, Correction, State-layer isolation, Teacher gate.

## Conventions
- Draft 2020-12. Each schema's `$id` is its **bare filename**; `$ref`s are relative (`common.schema.json#/$defs/...`) so the set validates locally with no network.
- Event schemas are `allOf: [ {$ref envelope}, {own} ]` with `event_type` pinned by `const`.
- IDs: `event_id` = ULID (sort key, not causality); `sequence` = the authoritative per-engagement order.
