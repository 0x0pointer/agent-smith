# Every scan builds training data

agent-smith produces more than a report. **Every pentest is also captured as a structured,
redacted dataset of how the engagement was actually conducted** — the reasoning, the tool
calls, the results, and the findings — which you can later distill into a small local model
that runs *as Smith*.

It's a **byproduct**: it happens automatically, in the background, and **never changes how a
scan runs**.

---

## What gets captured

As the agent works, the MCP server records a schema-versioned **event stream** per engagement
at `logs/smith-events/<engagement_id>.jsonl`:

| Event | What it records |
|---|---|
| **decision** | the reasoning behind the next move — goal, chosen tool, and *why* |
| **action** | the exact tool call, with its parameters |
| **result** | what came back, plus a reference to the raw artifact the model actually saw |
| **finding** / **coverage** | confirmed vulnerabilities and coverage-matrix transitions |

Each bundle is **self-contained**: the raw artifacts referenced by the stream are retained
next to it, so the data still points at real observations even after the scan's scratch files
are cleared.

---

## Safe by design

- **Passive.** Capture is read-only and **never feeds back into the agent's decisions** — it
  cannot change what a scan does or finds.
- **Redacted.** Every stream is leak-scanned; JWTs, bearer tokens, API keys, and private keys
  never enter the data.
- **Opt-out.** Disable it entirely with `SMITH_EVENTS_DISABLED=1`.

---

## Why it compounds

- **More pentests → more data.** Each engagement adds another bundle to `logs/smith-events/`.
- **Diversity beats volume.** The more varied your targets — frameworks, vuln classes, app
  shapes — the more general and capable the model you can train from them.
- **Data → a distilled model.** Pool the streams into a behaviour-cloning dataset and
  fine-tune a small open-weight base with **QLoRA** into a **LoRA adapter** that runs Smith's
  decision policy locally — disposable, re-derivable from the data, and hot-swappable.

**So the longer and more widely you use agent-smith, the better the local Smith you can
eventually train from your own engagements.**

---

## The pipeline

The [`training-data/`](../training-data/) directory holds the end-to-end pipeline that turns the
raw streams into a trainable dataset and a model:

1. **`smith-event` schemas** — the frozen, versioned event contract (decisions, actions,
   results, findings, coverage transitions).
2. **Event store + validator** — append-only storage with a freeze-acceptance validator
   (schema · sequence · causal DAG · result linkage · no-leak · artifact completeness).
3. **Passive decision harvester** — reconstructs the *reasoning → action* link from the
   transcript **after** the scan, as a non-causal reference edge (it never influences the run).
4. **SFT exporter** — renders a leakage-safe behaviour-cloning dataset (observation → reasoning
   → tool call) with a reproducible **data card** (counts, tool distribution, dataset digest).
5. **DGX Spark QLoRA harness** — fine-tunes a small open-weight base (e.g. a 7B model) into a
   LoRA adapter, sized for the Spark's unified memory.

> **Evaluation matters as much as data.** The pipeline's design pairs the dataset with a
> multi-layer eval suite — offline next-action accuracy plus **live agentic runs on hidden
> targets**, split strictly by target family — so a distilled model is measured on scans it
> never trained on, not on memorization.

For the full design — state layers, label uncertainty, counterfactual preference data,
teacher-provenance isolation, and the training ladder — see
[`training-data/training-data-plan.md`](../training-data/training-data-plan.md).
