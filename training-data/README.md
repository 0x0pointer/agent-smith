# smith-event schema spike + minimal event-store

The implementation package the round-3 critic asked for instead of another prose revision: JSON
Schemas + a minimal event-store + validating fixtures derived from **`training-data-plan.md` (v1.2)**.
Goal — surface schema/semantic defects on real data before freezing `smith-event/1.0`.

```
schemas/                    9 JSON Schemas (draft 2020-12), $id = bare filename, relative $refs
eventstore/
  core.py                   digest · Redactor (HMAC placeholders) · Store (fold/snapshot) · resolve_span · render_sft_example
  acceptance.py             9 event-store §15.1 tests, each with a NEGATIVE control
  ingest_agent_smith.py     live agent-smith scan -> redacted smith-event fixture
build_derived.py            bakes the derived digests (rendered_prompt_hash, state_hash, canonical_manifest_digest)
validate.py                 schema conformance + 9 infra-free §15.1 checks, each with a negative control
fixtures/
  lab-engagement-001/       hand-authored: events.jsonl (obs->decision->action->result->adjudication),
                            context-manifests.jsonl, expected-snapshots/, expected-exports/, artifacts/
  vulnbank-live/            66 REDACTED events ingested from a real VulnBank scan (schema-valid, zero raw identifiers)
```

Run (order matters — bake first):
```bash
.venv/bin/python training-data/build_derived.py
.venv/bin/python training-data/validate.py                 # schema + 9 checks
.venv/bin/python training-data/eventstore/acceptance.py    # 9 event-store tests
.venv/bin/python training-data/eventstore/ingest_agent_smith.py --validate   # re-ingest + validate
```

## Schemas → plan sections
All 9 present and consumed by the fixtures/tests: `common` (§3–§5 shared `$defs`), `event-envelope`
(§3.1 ordering authority; causal DAG = `caused_by`/`depends_on`; `supersedes` = correction edge),
`observation` (§3, §3.2 trust label; writes observed/belief, never latent), `decision` (§3, §3.3,
§3.6 captured_field reasoning, `teacher_origin`, `context_manifest_id`), `action` (§3.4, §7
`exact_action_hash` + `semantic_action_family` + behavior; `safety_class`), `result` (§3.5, §4, §5
visible spans, 3-layer outcome, evidence primitives), `adjudication` (§3.1, §4 `reproducible ⇒
artifact_id`), `state-snapshot` (§3.2 latent/observed/belief + `state_hash`), `context-manifest`
(§3.6), `release-manifest` (§13 canonical digests + `random_seed`).

## §15.1 acceptance coverage

Every predicate check is paired with a **negative control** (a crafted violation it must catch), so
no check is "green by construction". 18 checks total across the two runners:

**`validate.py` (9)** — Schema conformance · Evidence derivation (V0–V5 table, recomputed from
primitives) · DAG ordering (+ inversion caught) · Trust boundary (+ untrusted-instruction caught) ·
Correction edge (+ causal-supersedes caught) · State-layer isolation (+ latent-write caught) ·
Teacher gate (+ proprietary rejected) · Context replay (hash binds components+renderer+tokenizer, +
renderer-swap caught) · Release reproducibility (recomputed cross-process w/ randomized hash seed, +
tamper caught).

**`eventstore/acceptance.py` (9)** — Replay (fold the log == independently hand-authored snapshot, +
mutation caught) · Correction (superseded contribution drops from derived state, history intact) ·
Concurrency (two branches CONFLICT on one key; fold resolves by sequence; swapping order flips the
winner) · Temporal leakage (future/hidden evidence was a candidate and is dropped) · Redaction (same
value → same label, no raw value survives, cross-engagement placeholder_ids differ) · Span integrity
(resolve over real stored bytes; offset-sensitive) · Preference filtering (P0 unexportable) · Lineage
(refs resolve to real events/artifacts; a fabricated ref does not) · **Schema fits real data** (the
66-event redacted `vulnbank-live/` fixture validates + is causally ordered).

Still needing external infra (out of scope for the spike): full multi-branch **Concurrency** against a
real executor, export-time **Redaction** across a whole engagement, and **Span integrity** against
live (non-fixture) artifact stores.

## Conventions
- Draft 2020-12. Each schema's `$id` is its **bare filename**; `$ref`s are relative (`common.schema.json#/$defs/...`) so the set validates locally with no network.
- Event schemas are `allOf: [ {$ref envelope}, {own} ]` with `event_type` pinned by `const`.
- IDs: `event_id` = ULID (sort key, not causality); `sequence` = the authoritative per-engagement order.
- Derived digests are **baked** by `build_derived.py` and independently **recomputed** by the checks; `core.digest` / `build_derived` / `validate` use identical canonical JSON (sorted keys, no whitespace, UTF-8).
