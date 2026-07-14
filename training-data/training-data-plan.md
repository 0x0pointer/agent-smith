# Training-Data Pipeline for Pentest Model Distillation — Plan (v1.2, schema-spike-ready draft)

> **Status:** DRAFT v1.2 — architecture approved; the schema contract is **spike-ready but NOT
> frozen.** v1.2 resolves the round-3 implementation-level corrections: **latent / observed /
> belief** state layers (§3.2); **per-field capture-mode provenance** so no reasoning field is
> reconstructed post-hoc (§3); **distributed event-ordering authority** + supersedes-is-a-correction-
> edge (§3.1); a **context-assembly manifest** per model invocation (§3.6); **exact + semantic-family**
> action identifiers, no over-dedup (§3.4); **coordinate-system-tagged** visible spans + per-stage
> hashes (§3.5); evidence **primitives** that derive the dimensions **and computed V-levels** (§5); the
> Plane-A **raw-vs-redacted contradiction** resolved into a transient-acquisition **mode** + **HMAC-keyed
> placeholders** (§8); **canonical-serialization** release digests (§13); and a **schema-freeze
> acceptance-test suite** (§15.1). Next artifact = a compact `schemas/` + `fixtures/` package validated
> on ~20–50 decisions from one authorized lab scan — **not** another prose revision.
> New in v1.1 (§3.1–3.5): event-sourcing invariants + correction semantics; environment-vs-belief
> state (upgraded to the three-layer split in v1.2, §3.2); temporal visibility / anti-future-leakage; label-uncertainty + multi-parent credit;
> counterfactual quality levels P0–P3; evidence dimensions (V0–V5 derived); dataset release identity;
> action fingerprinting; result-truncation spans; confidence-calibration eval. Claude-track wording
> corrected (isolation is a *contamination* control, **not** a resolution of the ToS question).
> **v0→v1 headline changes:** canonical unit is now a **pentest event graph** (not "one trajectory
> per scan"); **vector-valued reward computed at export** (not a single outcome tag);
> **same-state counterfactual** preference data; **prompt-injection/trust labeling** as a
> first-class concern; **multi-layer evaluation with hidden targets** (agent-smith is one layer,
> not the sole judge); **two-plane redaction**; **evidence hierarchy V0–V5**; teacher/student
> choices are gated, not locked. Change log in §16.
>
> **Goal:** turn the artifacts / logs / findings / coverage / chains agent-smith already produces —
> plus a little extra instrumentation — into a **model-agnostic pentest dataset** that teaches good
> *decisions*, and distill it into small models that run as Smith on the DGX Spark.

---

## 0. TL;DR

- **Dataset is the durable asset; adapters are cheap, re-derivable outputs.** Keep model-agnostic
  DATA separate from model-specific export templates.
- **Canonical unit = an append-only event graph** (observations, hypotheses, decisions, actions,
  results, state transitions, evidence, findings, coverage/chain transitions, interventions). SFT
  windows, preference pairs, classifiers, and evaluators are **derived views**, not the source.
- **Teach decisions, not transcript imitation.** The biggest risk is training a stylistic mimic
  that overfits agent-smith's bookkeeping. Guard with process supervision + independent evaluation.
- **Build the evaluation suite BEFORE the first adapter.** agent-smith is *one* eval layer; add
  hidden synthetic targets + general-capability + safety layers to avoid Goodhart circularity.
- **Reward is vector-valued and computed at export time** from stored facts — never baked into the
  data — so "what good pentesting means" can change without rebuilding the corpus.
- **Provenance is per-decision** (model vs human vs QA vs deterministic), and every field carries a
  **trust/origin label** because the corpus contains attacker-controlled content.

---

## 1. Why agent-smith fits
It already insists on artifact-backed findings, source-linked evidence, exploit-chain transitions,
coverage state, and sandboxed execution — the raw ingredients for **process supervision** and
verifiable outcomes, which is the hard part of agent training data. It is also its own operational
harness. Caveat (see §11): being the harness does **not** make it a sufficient benchmark.

## 2. Desired output & reusability (unchanged from v0)
Three layers, kept strictly separate: **(1) the dataset** (model-agnostic, versioned, the asset) →
**(2) QLoRA/LoRA adapter(s)** (bound to one base, disposable, re-derived from the dataset) →
**(3) served student** (base + adapter running as Smith). Reusability comes from a
tokenizer/template-neutral canonical schema + **exporters** that render into any target format, plus
immutable versioned releases with data cards. New model = new exporter, same data.

---

## 3. Canonical unit: the pentest **event graph** ⭐ (v1 correction)
A scan is too large and causally ambiguous to be a linear transcript (thousands of calls, branches,
retries, human steering, findings discovered long after their enabling observation, duplicate
observations, unrelated vuln classes). **Model it as an append-only event graph per engagement:**

```
Engagement → environment snapshot, target entities
           → observations, hypotheses, decisions, tool actions, tool results
           → state transitions, evidence objects, findings
           → coverage transitions, chain transitions, interventions, adjudications
```

Everything else — SFT conversations, local decision windows, preference sets, planning examples,
tool-call examples, classifiers, world-model transitions, evaluator sets — is a **derived view** over
this graph. Materialize periodic **state snapshots** so exporters don't replay every event.

### The decision event (the atom of supervision)
Per decision, store a **structured decision record** (not free-text CoT — more faithful, reusable
across model families):
```
goal, hypothesis, supporting_observations[artifact_refs], target_ref, technique(CWE/MITRE),
alternatives_considered[], expected_signals[], chosen_tool+operation+params, confidence,
stop_condition
```
Optionally attach a **short** 40–80-token explanation. Keep the tool call, params, and result
**verbatim** (the high-value, verifiable tokens). Never persist the raw scratchpad.

**Every reasoning field carries a `capture_mode` (v1.2) — never fabricate a rationale after the
fact.** `alternatives_considered`, `expected_signals`, `confidence`, `stop_condition` are only
supervision-grade if the model produced them **before** action selection; reconstructing them later
with another model recreates the exact post-hoc-rationale failure the structured record exists to
avoid. Tag each as `{value, capture_mode, actor}` where `capture_mode ∈ {pre_decision_generated,
operator_supplied, policy_derived, post_hoc_adjudicated, not_captured}`. Post-hoc values are usable
for *analysis*, never presented as the acting model's reasoning; a missing field is `not_captured`,
not invented.

### Per-decision provenance (v1 correction — not coarse `teacher=claude`)
```
proposal_source, selection_source, decision_source, execution_source, outcome_adjudicator,
teacher_origin  // license class of the proposing model: open_weight | proprietary — gates §12
```
Human-overridden actions (`model proposal → human reject → human-selected alternative → result`)
are **high-value preference candidates — but only after outcome verification** (v1.2). A human
override is not automatically the better action; promote it to a *preferred* label once its result
is confirmed, not on authority alone.

### Trust / origin labeling (v1 — critical, was missing)
Every content field carries `{origin, trust, rendering, instruction_authority}`. Origins: system /
operator / skill / model / mcp_server / scanner / target / external_api / human_adjudicator.
**Untrusted (target-controlled) content is always exported as observation DATA, never as
instructions** — otherwise we train the student to obey prompt-injection. Retain sanitization
transforms + injection-detector results + truncation status.

### Runtime version refs (v1 — tool schemas can't just be "kept out")
Each event references immutable versions so exporters can reconstruct what was actually available:
`agent_smith_commit, skill_commit, tool_registry_version, policy_version, container_digests{}, model{provider,id,checkpoint_digest,adapter_digest}`.

### Artifacts by reference (v1 — don't duplicate scanner noise)
Staged by reference (names + a per-stage hash in §8/§3.5): **`source_original`** (`sha256`) →
**`sanitized_evidence`** → **`normalized_observation`** (status, type, indicators) →
**`training_rendering`** (one line). Store the pointer + transformation lineage; never inline full
nmap/ffuf/nuclei/HTTP transcripts into every record.

---

### 3.1 Event-sourcing envelope & graph invariants (v1.1; ordering authority v1.2)
**Append-only event sourcing — events are immutable; never mutate an incorrect event, add an
`adjudication` / `retraction` / `supersession` event.** The **execution-causality graph is a DAG over
`caused_by`/`depends_on` edges only.** Envelope on every event:
```
event_id, engagement_id, event_type, sequence, occurred_at, recorded_at,
caused_by[], depends_on[], supersedes[], correlation_id (e.g. decision_id), schema_version
```
**Ordering authority (v1.2) — Smith emits events from many clocks (MCP server, containers,
orchestrator, dashboard, OOB callbacks), so wall-clock is NOT authoritative:**
- `event_id` = UUIDv7/ULID — a practical sort key, **not** authoritative causality.
- `sequence` = monotonic per-engagement, allocated by **one** event-store authority.
- `occurred_at` = source-reported time; `recorded_at` = event-store receipt time (both retained).
- `caused_by`/`depends_on` = the **authoritative** causal structure. **No causal parent may hold a
  greater committed `sequence` than its child.** Late-arriving events get a later `sequence` but keep
  their original `occurred_at`. A **DAG check runs before release materialization.**
- **`supersedes` is a CORRECTION edge, not a causal edge** — it never enters the execution-causality
  DAG; a superseded observation stays in the graph and the correction points back at it out-of-band.

Invariants: **concurrent branches** = multiple children off one parent; **one action may have
multiple results** (each its own event `caused_by` the action); **retries** link to the original via
`caused_by`/`correlation_id`; **duplicate observations** identified by content hash.

### 3.2 State layers: latent / observed / belief (v1.1 §; three-layer split v1.2)
"Environment state = objective ground truth" only holds in an **instrumented lab**; in a real
black-box assessment most environment state is **latent**. Keep **three state layers** (distinct
from the §8 data *planes*), never conflated — and never promote a scanner's "vulnerability present"
into truth just because it was reported:
- **Latent ground truth** — objective reality (the vuln really is present, the cred really is valid,
  the host really is patched). **Populated only when a lab/oracle exposes it**; `latent_ground_truth_ref`
  is `null` on targets without an oracle. Evaluator-only, never visible to the acting model — this is
  exactly the layer the §3.3 `hidden_ground_truth` flag marks.
- **Observed environment state** — facts backed by **direct observation or deterministic
  instrumentation** (a 200 returning the row, a live OOB callback, a sandbox that reproduced the
  exploit) — `observed_state_ref`. **Promotion rule:** a single scanner signal (V0/V1, §5) stays in
  **belief**; a claim becomes **observed** only at evidence level **≥ V2** (reproducible differential);
  nothing is ever written to **latent** by the acting pipeline (oracle-only). "Vulnerability present"
  therefore lives in belief or observed, **never** in latent truth.
- **Belief state** — Smith's interpretation / hypotheses / uncertainty (likely-SQLi, cred confidence
  0.7, cell untested) — `belief_state_before_ref` / `belief_state_after_ref` + `belief_delta`.
```
belief_delta: { hypothesis, prior_confidence, posterior_confidence }
```
A wrong hypothesis updates **belief**; a confirmed observation updates **observed**; **neither
rewrites latent truth.** Essential for partial observability, counterfactuals, world-model training,
calibration, delayed credit, and comparing two agents that read the same evidence differently.

### 3.3 Temporal visibility — anti-future-leakage (v1.1 — essential)
A graph makes future events trivially reachable, so it makes leakage trivially easy. Every evidence
reference at a decision records what the model **actually saw**:
```
visible_at_decision, entered_context, context_position, available_but_not_shown, discovered_after_decision
```
Plus a `hidden_ground_truth` flag for evaluator-only facts (the §3.2 latent layer). Exporters MUST reconstruct the decision
context from these — never let graph-available-but-unseen or discovered-later evidence into a
training example. Evidence is only *part* of the input; the full assembled context is captured by the
**context-assembly manifest** (§3.6).

### 3.4 Action fingerprint & dedup (v1.1; two-identifier model v1.2)
String-level dedup misses semantically equal actions (curl vs requests vs Burp vs scanner probe);
over-aggressive semantic dedup **destroys behaviorally-distinct** ones (a repeated race probe or a
timing sample *is* the point, not a duplicate). Keep **two** identifiers:
- **`exact_action_hash`** — dedup exact repeats aggressively (delete).
- **`semantic_action_family`** = `{target_entity, operation_class, param_mutation, payload_family,
  auth_context, expected_oracle}` — treat family duplicates as a **sampling / weighting** problem,
  never automatic deletion.
Record the behavior-distinguishing fields so the family can't collapse distinct actions: `transport,
method, encoding, execution_cardinality, timing_model, concurrency, session_state, tool_semver,
side_effect_class`.

### 3.5 Result truncation & visible spans (v1.1; coordinate system v1.2)
"Keep results verbatim" applies to the evidence plane (§8). The **training record** stores exactly
which fragments the model saw — but a bare `{start,end}` offset points at the **wrong content** once
any normalizer runs (Unicode normalization, ANSI strip, decompression, redaction, line-ending
conversion, JSON parse, HTML extraction). Anchor every span to a **named artifact variant + explicit
coordinate system**:
```
artifact_ref, artifact_variant (e.g. sanitized_utf8_v2), coordinate_system (e.g. utf8_byte_offset),
visible_spans[{start, end_exclusive}], truncation_strategy, original_bytes, visible_bytes
```
Retain a **separate hash per transformation stage** — `source_original` · `sanitized_evidence` ·
`normalized_observation` · `training_rendering` (§8) — so a span always resolves against the exact
bytes it was measured on.

### 3.6 Context-assembly manifest (v1.2 — the full model input, not just evidence)
§3.3 records which *evidence* the model saw, but a decision also depends on the system policy, active
skill text, tool schemas, prior summaries, **context-compaction output**, operator / QA messages,
scratch memory, budget, and prior tool failures. Capture the **assembled input per model invocation**
so a bad decision can be attributed to the model vs. the exporter vs. truncation vs. missing evidence:
```
context_manifest_id,
components[ { type, ref, ordinal } ]   // system_policy, skill, tool_schema, observation,
                                       // compaction_summary, operator_msg, qa_advisory, budget, …
rendered_prompt_hash, renderer_version, tokenizer_ref
```
The canonical graph stays **model-agnostic**; this manifest records what a *particular* invocation
actually received, and (with §3.5 variants) lets the exact context be **reconstructed and
hash-verified** (acceptance test "Context replay", §15.1).

---

## 4. Outcome, utility, credit, and reward (v1 — replaces "one outcome tag")
A single `advanced/dead_end/refused/inconclusive` tag is **not a reliable reward** (a "dead end" can
be a great action — rules out a hypothesis, closes a cell clean, establishes a precondition; a
"finding" can be a bad action — 200 calls for 3, duplicate work, out of scope, fragile result).
Store **three layers**, and **do not let the acting model self-label** (noisy + self-serving —
compute most asynchronously from state transitions, adjudicate the rest):

- **A. Observed result** — `execution_status, result_class, new_artifacts[], state_changes[]`.
- **B. Adjudicated utility** — `information_gain, coverage_gain, finding_gain, chain_gain,
  duplication_penalty, scope_compliant, cost{seconds,tokens,tool_calls}`.
- **C. Credit assignment** — findings usually have **multiple contributors**, so credit is a list,
  not a single parent (and weights need not sum to 1 unless the method supports it):
  `contributors[{event_id, role, weight}]` (e.g. surface_discovery 0.2 / param_identification 0.3 /
  exploit_confirmation 0.5).

**Utility & credit are uncertain LABELS, not objective facts** (v1.1). `information_gain`,
`contribution`, even `duplicate` are estimates — store each as
`{value, confidence, source/adjudicator, method, timestamp, basis[], competing_assessments?}`, same
"facts-first, policy-later" discipline as the reward. Compute most asynchronously from state
transitions; adjudicate the rest; never let the acting model self-score.

**Reward is a versioned policy over a vector**, computed at export/train time — never baked in:
```
R = { evidence_quality, finding_novelty, coverage_gain, chain_progress, information_gain,
      scope_compliance, reproducibility, safety, execution_cost, duplicate_work, false_positive_risk }
R_v1 = 4·confirmed_finding + 2·chain_transition + 1·coverage_gain + 0.5·info_gain
       − 2·duplicate − 3·unsupported_claim − 10·scope_violation − cost_penalty
```
Store constituent facts; compute R at export. Changing "good pentesting" must not require rebuilding.

## 5. Evidence — store PRIMITIVES, derive dimensions, derive the level (v1.1; primitives v1.2)
A single ordinal hides real differences (a target-specific deterministic exploit vs. two weak
scanners agreeing vs. a human confirming an unreproducible race vs. a reproduced differential with
no demonstrated impact). **Store measurable primitives**, compute the **dimensions** from them, then
derive the level — each a *versioned view* (facts-first; minimizes adjudicator inconsistency):
```
primitives: attempt_count, success_count, independent_method_count, control_present, control_passed,
            impact_observed, human_review_count, environment_reset_success, is_deterministic
```
**Dimensions** are computed from the primitives (no free adjudicator judgement); each carries
`{value, scale_version, basis}` where `basis` = the primitive names+values that produced `value`.
Under `scale_version = evidence-scales/1.0`:
```
reproducibility     = success_count / max(attempt_count,1)          # 0..1
independence        = min(independent_method_count, 3)              # 0..3
directness          = 2 if is_deterministic else (1 if success_count>0 else 0)
impact_demonstration= 1 if impact_observed else 0
control_comparison  = 0 if !control_present else (1 if !control_passed else 2)   # none/failed/passed
human_adjudication  = human_review_count > 0
environment_stability = environment_reset_success                  # bool
```
**The level is COMPUTED from the dimensions** (not glued on as prose); `θ_repro = 0.8`:
```
level = V5 if human_adjudication and reproducibility>=θ and independence>=2
        V4 if independence>=2 and reproducibility>=θ
        V3 if directness==2 and success_count>=1
        V2 if reproducibility>=θ and impact_demonstration>=1
        V1 if independent_method_count>=1 or success_count>=1
        else V0
```
Shorthand: `V0` assertion · `V1` heuristic signal · `V2` reproducible differential · `V3`
deterministic exploit · `V4` independent 2nd-method · `V5` human-adjudicated + reproduced. Bumping
`scale_version`/`θ` re-derives every level from history without touching stored primitives. Use in
filtering, reward, sampling weight, eval, and data-card stats.

## 6. Derived training views
SFT **local decision windows** + short successful sub-trajectories (not whole scans first);
outcome-conditioned SFT (error→diagnosis→correction, hypothesis→test→evidence, obs→state-update,
finding→evidence-package, coverage-gap→next-action); **same-state counterfactual preference sets**
(see §7); tool-call/classifier/world-model views. Full-scan conversations are a *late* derived view.

## 7. Preference data — same-state counterfactuals (v1 correction)
Do **not** pair "good action from state 34" vs "bad action from state 82." Compare candidates
**under the same (or cloned) state**. But perfect cloning (DB state, lockout counters, sessions,
caches, queued jobs, external callbacks, seeds, race conditions, side effects) is the hardest infra
problem here — so **define preference quality levels and don't block on P3:**

| Level | Method | Reliability |
|---|---|---|
| **P3** | candidates executed against deterministic cloned states | strongest |
| **P2** | executed against separately-reset equivalent states | good |
| **P1** | judged from the **same frozen observation** by an adjudicator | weaker |
| **P0** | mined from unrelated historical states | **not usable** for preference training |

Tag every candidate action with a **safety class** — `read_only / reversible / state_mutating /
destructive / externally_observable` — and **only auto-execute safe + reproducible** candidates.
**Classify refusals**: scope / DRAIN-gate / policy / safety refusals are *desirable*;
malformed-tool / accidental are not. Never teach "all refusals bad."

---

## 8. Pipeline: two data planes + privacy (v1 — strengthened; contradiction resolved v1.2)
"Immutable raw artifacts" **and** "redact at ingest" can't both hold — once redacted, the stored
object is no longer the original. Resolve by naming the stages and choosing an **acquisition mode**
(called *mode*, not "model", to avoid collision with the ML models of §9–§10):
- **Stage objects:** `source_original` → `sanitized_evidence` → `normalized_observation` →
  `training_rendering` (each with its own hash, §3.5). "Verbatim" means **source-verbatim** in the
  evidence plane and **transformation-verbatim (post-redaction)** in the training plane — so
  credentials embedded in a command never cross into Plane B.
- **Plane A — evidence vault (default = acquisition Mode A, transient, for client engagements):**
  tool output → encrypted **transient** buffer → redaction → **immutable `sanitized_evidence`
  vault** → **destroy the transient raw buffer.** Nothing un-redacted is ever persisted. Encrypted,
  engagement-isolated, access-limited to the redaction pipeline + a data-steward, short NDA
  retention, **not reachable by training jobs.** *(Mode B — an immutable encrypted `source_original`
  vault + a redacted derivative — only for labs / explicit forensic retention with written consent.)*
- **Plane B — training event store:** pseudonymized/normalized, typed placeholders, provenance
  references only, longer-lived where legally justified.

**Typed-placeholder pseudonymization** (consistent per-entity: `<TARGET_HOST_1>`, `<CRED_1>`,
`<JWT_1>`, `<API_KEY_1>`…) preserves attack-chain structure; keep the vuln **shape** verbatim
(payload, param, injection type, oracle, status). Consistency **without** a stored re-identification
map uses an **engagement-scoped keyed identifier (v1.2):** `placeholder_id =
HMAC(engagement_key, entity_type ‖ normalized_value)` → display label. The **HMAC key lives outside
the dataset, is engagement-scoped, is unavailable to training jobs, is destroyable at retention end,
and is never reused across clients** — so the same host/user can't be linked across engagements and
**no re-identification map is kept in the corpus.** Note (EDPB): **pseudonymized data can still be
personal data** — only genuine anonymization exits data-protection scope. Handle **indirect
identifiers** (unique paths, stack traces, cert subjects, schema names, cloud IDs, error strings,
source snippets, timestamps/topology) — regex alone is insufficient.

**Privacy testing per release:** secret scanners, NER, entropy + known-canary detection,
cross-record linkage, nearest-neighbor memorization, membership-inference, **extraction prompts
against the trained adapter**, sampled manual review.

**Include failed scans — labeled** (error→correction pairs, `tested_clean` genuine negatives,
whole-scan failure-cause tags); curate out pure timeout/infra noise.

---

## 9. Training ladder (v1 — reordered)
0. **Baseline (no training)** — evaluate several base models inside agent-smith.
1. **Behavior-cloning SFT** — high-quality **local decision windows** + short successful
   sub-trajectories (NOT whole scans).
2. **Outcome-conditioned SFT** — error-recovery, hypothesis→evidence, obs→state, finding→evidence.
3. **Counterfactual preference optimization** — same-state candidates (§7).
4. **Student rejection sampling** — generate candidates against cloned lab states; keep
   verifier-approved.
5. **Short-horizon RLVR** — 1–5-action tasks (confirm SQLi, prove one chain transition, find an SSRF
   oracle).
6. **Long-horizon RL** — only once reward + state-reset infra is robust (sparse reward, partial
   observability, expensive actions, hard state reproduction).

---

## 10. Student selection (v1 — don't lock)
Do **not** fix Qwen3-14B up front. Run a **base-model bake-off** on 100–300 frozen decision points
(next-action selection, tool-schema validity, command correctness, evidence interpretation, scope
compliance, tool-error recovery, context compression) across ≥ a dense 8B, a dense 14B, a dense
30–32B, a code-specialized model, and possibly an efficient MoE. Pick on **base competence +
trainability**, not family. **Qwen3 dense (Apache-2.0, native tool-calling, 128K ctx) is a strong
default candidate**, but earn it.

**DGX Spark = 128 GB unified / 273 GB/s** — treat the "~22 GB / ~44 GB QLoRA" figures as *static
weights, not usable training configs*. **Phase 0 must benchmark** `model × seq_len × batch × method`
for peak memory, tokens/s, step time, checkpoint time, and post-train inference throughput. Expect
the Spark to shine at adapter training + single-session eval and to be **bandwidth-limited for
long-context / high-throughput 32B**. Adapters **hot-swap** (vLLM multi-LoRA, route by
`set_skill`/phase); they do **not** reliably **compose** — one generalist first, specialists as
controlled experiments, never merge weights.

---

## 11. Evaluation — multi-layer, agent-smith is ONE layer (v1 — anti-circularity)
Same system generating data + labels + verifier + training + judging = strong Goodhart risk (student
learns to satisfy bookkeeping: close easy cells, overproduce artifacts, farm known targets, game
severity/chain labels). Required layers:
1. **Deterministic harness** — valid tool calls, schema compliance, latency, completion, duplicate
   rate, budget adherence.
2. **Operational** — confirmed findings, evidence quality, coverage, chain depth, false positives,
   **calls per confirmed finding**.
3. **Hidden synthetic targets** — never in training: renamed routes, altered HTML/errors, reordered
   params, different frameworks, equivalent-vuln-different-oracle, decoys, patched variants,
   reordered chains.
4. **External expert adjudication** — blind review by experienced pentesters on sampled runs.
5. **General agent capability** — function calling, long-horizon planning, tool-error recovery,
   context mgmt, code gen, instruction following (BFCL supplementary only).
6. **Safety/scope** — does the fine-tune *increase* out-of-scope behavior, credential misuse,
   unauthorized lateral movement, destructive/persistence commands, unsafe exploit execution?
7. **Confidence calibration** — the decision record's `confidence` is only useful if calibrated:
   per-bucket accuracy, expected calibration error, confidence-change-after-evidence, overconfidence
   on false findings, underconfidence on confirmed exploits. **Do not train on teacher `confidence`
   until it's shown to correlate with correctness.**

**Train/test split by equivalence class** (target family, codebase, lab image hash, vuln template,
route graph, env seed, engagement, teacher, client, toolchain version) **+ temporal holdout**. Rule:
*no eval target shares source, image ancestry, generated seed, exploit template, or engagement
provenance with training data.*

---

## 12. Teacher provenance — hard-isolated tracks (v1.1 — a CONTAMINATION control, not a ToS resolution)
The critic argues for the strict rule (no Claude outputs as training targets absent written/legal
clearance); the operator wants to use Claude. The boundary below **prevents Track-A material from
entering distributable artifacts — it does NOT resolve the underlying provider-terms question. Track
A remains an explicitly accepted legal/contractual risk until written permission or legal clearance
exists.** With that understood:

- **Track B — open-weight teacher = the DEFAULT for anything that could ship:** DeepSeek-V3/R1 (MIT)
  or Qwen3-32B (Apache-2.0); Llama-3.1+ secondary (attribution). This is the ToS-clean, distributable
  corpus. Use it from day one for any adapter/dataset that might leave the box or touch client data.
- **Claude is fine for the non-training uses the critic endorses** — ETL testing, schema-completeness
  inspection, *private* evaluation, non-training analytics, finding missing instrumentation.
- **Track A — a strictly-personal, HARD-ISOLATED Claude training track** *if the operator accepts the
  risk*: a **physically separate store**, and the distributable exporter **hard-refuses any record
  whose `teacher_origin` isn't `open_weight`.** `teacher_origin` is a first-class per-decision
  provenance field (§3) = the license class (`open_weight` | `proprietary`) of the model named in that
  record's `proposal_source` / §3 `model{provider,id}` ref — **set at capture, never inferred at
  export.** The gate is enforced in code, not a promise — the real answer to the critic's "gray tracks
  leak" concern.
- **Legal review before any distribution.** Output ownership does **not** override the contractual
  use-restriction. If it will ever be shared/commercial/client-derived → Track B only.

⚠️ Honest note: this is the operator's risk decision for the personal track; the strict default
(open-weight everywhere) is lower-regret and I'd bias toward it for anything non-trivial.

---

## 13. Governance: consent, storage, licensing (v1 — reworked around model lineage)
**Consent must reflect that models can't cleanly "unlearn":** deleting an engagement's records does
not remove learned influence; distributed adapters can't be recalled. So:
- **Opt-in decided at contracting**, not opt-out-30-days-after. No training use before engagement
  close + redaction approval + a cooling-off window.
- **Three separate permission boxes**, each a different risk profile:
  `[ ] internal research/eval  ·  [ ] internal production model improvement  ·  [ ] external
  distribution of derived artifacts.` Client-derived data/adapters stay **internal** unless the
  external box is explicitly ticked.
- **Deletion = future-release exclusion + retrain-from-clean-parent**, with dataset lineage, model
  lineage, deletion manifests, retrain triggers, checkpoint revocation, backup expiry. Do **not**
  promise recall of already-delivered/published models.
- Drop the v0 "perpetual + retroactive purge" wording (contradictory) and the "irreversible
  redaction" guarantee (unprovable for unique code/topology).

**Storage:** Plane A = encrypted object store, **not git**, per-engagement isolation. Under the §8
**Mode-A default (client engagements) the at-rest store holds only the immutable `sanitized_evidence`**
(the un-redacted buffer is transient and destroyed); a raw `source_original` quarantine with NDA
retention/auto-purge exists **only under Mode B** (labs / consented forensic retention). Plane B
curated = private versioned registry (DVC/LakeFS/private HF/git-LFS)
with per-record provenance → opt-out purges executable, least-privilege + MFA. **Provider owns
curated dataset + adapters as trade secret; never open-source the dataset.** Managed host? verify its
DPA forbids training *their* models on your data.

**AGPL-3.0 bill of materials (confirmed: repo + skills submodule are AGPL-3.0):** analyze whether the
ETL/exporters link AGPL components, whether any network-served component triggers AGPL's network
clause, and whether tool-schema/skill text is copied verbatim into the dataset (could carry the
license). Track per-source rights: code license (AGPL) · skill license (AGPL) · teacher-model license
· student-model license · target/lab license · third-party scanner output · dataset record rights.
The **dataset** is likely a separate work from the AGPL code, but the exporters and any copied
skill/prompt text need explicit review — get counsel sign-off.

**Dataset release identity (v1.1; canonical serialization v1.2).** Hashing conceptual components is
not enough — the same logical manifest serializes differently unless the encoding is pinned. Define
**canonical JSON** (stable record sort, UTF-8, normalized timestamps) plus a full build lock: exporter
**dependency lockfile / image digest**, query engine + version + params, schema-migration versions,
source-object hashes, and the **random sampling seed**. A release carries explicit digests:
```
release_id, canonical_manifest_digest, source_snapshot_digest, selection_manifest_digest,
split_manifest_digest, exporter_image_digest, random_seed
```
It preserves the **exact selection query/manifest** that chose every record, so any record traces to
the releases (and models) that consumed it. The real bar: **can a fresh machine rebuild a
byte-identical release** from the referenced snapshot + container images? (acceptance test §15.1).

**Day-one governance fields (v1.1) — cheap now, painful to retrofit.** Even for a private prototype,
capture from the first event: record-level provenance, model lineage, allowed-use classification,
source-license metadata, deletion lineage, and lab/personal/client separation. Leaving these
mostly-empty during prototyping is fine; adding them after millions of events is not.

---

## 14. Roadmap (v1)
- **Phase 0A — Legal & provenance gate:** classify allowed teacher sources; consent model; define
  personal/lab/client datasets; license/AGPL BOM; ban unapproved provider-output training; define
  deletion + retrain policy.
- **Phase 0B — Event instrumentation:** structured decision record; per-decision + human provenance;
  state before/after; expected signal; alternatives; stop condition; runtime/tool/container versions;
  intervention events; trust/origin labels; evidence level. (No long free-text rationales.)
- **Phase 1 — Event store + privacy plane:** evidence vault; training event store; redactor;
  injection sanitizer; artifact normalizer; lineage graph; data-quality dashboard; release manifest.
- **Phase 2 — Frozen evaluation suite (BEFORE any training):** hidden lab targets; patched controls;
  target variants; frozen decision set; expert rubric; safety suite; base-model bake-off.
- **Phase 3 — First dataset release:** local-decision SFT, tool-use SFT, obs→state, error-recovery,
  evidence-adjudication. Exclude ambiguous attribution, target-controlled instruction-like content,
  unapproved-teacher outputs, low-verification findings, infra noise.
- **Phase 4 — First QLoRA baseline** on the bake-off winner.
- **Phase 5 — Counterfactual data generation** (cloneable decision environments).
- **Phase 6 — Rejection sampling + short-horizon RLVR** — only after reward-gaming + verifier
  robustness tests pass.

## 15. Go / No-Go gates (must all pass before training)
| Gate | Requirement |
|---|---|
| Legal | every record has an allowed-use classification |
| Provenance | actor/model/human origin available per decision |
| Privacy | no critical leak in automated + sampled manual tests |
| Poisoning | target-controlled content marked + sandboxed |
| Reproducibility | tool/skill/policy/target/container versions captured |
| Evaluation | hidden frozen benchmark exists **before** training |
| Attribution | state deltas + delayed credit reconstructable |
| Data quality | ≥80–90% of sampled records judged usable |
| Baseline | untuned candidates compared |
| Deletion | a record traces to every dataset + model release that consumed it |

### 15.1 Schema-freeze acceptance tests (v1.2 — pass on one fixture engagement before freezing `smith-event/1.0`)
The schema stays **spike-ready, not frozen**, until a small fixture engagement (~20–50 decisions from
one authorized lab scan) passes **all** of these — these reveal more schema defects than another prose pass:

| Test | Required result |
|---|---|
| Replay | Replaying committed events reproduces the same state-snapshot hashes |
| Retraction | Retracting an observation changes derived state **without mutating history** |
| Concurrency | Two independent branches execute and later converge |
| Temporal leakage | No post-decision or unseen evidence appears in exported SFT examples |
| Trust boundary | Target content is never rendered with instruction authority |
| Redaction | Consistent placeholders survive across a full attack chain |
| Span integrity | Every visible span resolves to the exact content shown to the model |
| Context replay | The model-invocation context reconstructs and hash-verifies (§3.6) |
| Preference filtering | P0 records are impossible to export to DPO training |
| Release reproducibility | Rebuilding twice produces the same release digest (§13) |
| Lineage | Every example maps back to events, artifacts, engagement, and allowed-use policy |
| Correction | Late adjudications + supersessions do not invalidate the event DAG |
| Evidence derivation | Recomputing dimensions + V-level from stored primitives reproduces the stored `{value, scale_version}` and level for every evidence object; bumping `scale_version`/`θ` re-derives prior levels from history (§5) |
| State-layer isolation | A scanner "vuln present" signal is written to observed/belief, never to latent; `latent_ground_truth_ref` is null on non-oracle targets and absent from every exported (non-evaluator) example (§3.2) |
| Teacher gate | No record with `teacher_origin != open_weight` can reach a distributable export (§12) |

**Next artifact = the implementation package, not another revision:** `schemas/` (event-envelope,
decision, observation, action, result, adjudication, state-snapshot, context-manifest, release-
manifest) + `fixtures/lab-engagement-001/` (events.jsonl, expected-snapshots/, expected-exports/),
populated from ~20–50 decisions of one authorized lab scan.

## 16. Change log (v0 → v1, from the critical review)
Keep: dataset-first, canonical/export separation, provenance, artifact-backed labels, staged ladder,
operational eval, QLoRA default, private registry, raw-outside-git. **Change:** event graph (not
trajectory-per-scan) · structured decision record (not prose rationale) · three-layer
outcome + vector reward computed at export · same-state counterfactual preferences + refusal
classification · agent-smith = one eval layer + hidden targets · equivalence-class + temporal splits
· two-plane redaction + privacy testing · **prompt-injection/trust labeling (new)** · tool/skill/
container version refs · artifacts-by-reference · per-decision + human provenance · evidence
hierarchy V0–V5 (new) · teacher = open-weight default + hard-isolated Claude personal track · student
= bake-off (don't lock Qwen3-14B) + DGX benchmark-not-estimate · LoRA hot-swap-not-compose · consent
reworked around model lineage + 3 permission boxes · **AGPL-3.0 BOM (new)** · eval-suite-before-first-adapter.

**v1 → v1.1 (schema contract, round-2 review):** event-sourcing invariants + immutable-with-
correction semantics (§3.1) · **environment-state vs belief-state** (§3.2) · **temporal visibility /
anti-future-leakage** (§3.3) · action fingerprint + semantic dedup (§3.4) · result-truncation visible
spans (§3.5) · label-uncertainty + multi-parent credit (§4) · evidence stored as **dimensions**,
V0–V5 derived (§5) · **counterfactual quality levels P0–P3** + action safety class (§7) · confidence
calibration as an eval layer (§11) · Claude track reworded to **contamination-control-not-ToS-
resolution** (§12) · dataset release digest + day-one governance fields (§13). Still open before
freezing: pick the belief-state representation, the normalizer/fingerprint spec, and the cloning
approach per target class.

**v1.1 → v1.2 (round-3 implementation review):** state split into **latent / observed / belief**
(§3.2) · per-field **`capture_mode`** provenance, no post-hoc fabrication + human-override-only-after-
verification (§3) · **distributed event-ordering authority** + supersedes = correction-not-causal
edge (§3.1) · **context-assembly manifest** per invocation (§3.6) · **`exact_action_hash` +
`semantic_action_family`**, no over-dedup (§3.4) · visible spans get **`artifact_variant` +
`coordinate_system` + `end_exclusive` + per-stage hashes** (§3.5) · evidence **primitives** derive the
dimensions (§5) · Plane-A **raw-vs-redacted contradiction resolved** (transient acquisition, named
stage objects) + **HMAC-keyed engagement-scoped placeholders** (§8) · release digests get **canonical
serialization + byte-identical rebuild** test (§13) · **schema-freeze acceptance-test suite** (§15.1).
Schema is **spike-ready, not frozen**; next artifact = `schemas/` + `fixtures/` on one lab scan.
