# Skills for the Fabro pipeline

Skills in the Agent Skills layout (one folder per skill with a `SKILL.md`),
copied unchanged from their upstream repositories. A stage that uses one is
told in its prompt to read the `SKILL.md` here, and how the skill applies to
this pipeline: where the two disagree, the prompt wins. Fabro 0.254.0 did not
offer these to agents through its own `use_skill` tool when we tried it, which
is why the prompts name the files. Agents cannot change this folder: the
verify step rejects any change under `.fabro/`.

| Skill | Stage that follows it | Upstream |
|---|---|---|
| `spec-driven-development` | Write spec (standard changes) | addyosmani/agent-skills |
| `planning-and-task-breakdown` | Write spec (standard changes) | addyosmani/agent-skills |
| `test-driven-development` | Implement | obra/superpowers |
| `incremental-implementation` | Implement (first pass, standard changes) | addyosmani/agent-skills |
| `verification-before-completion` | Implement, every fix stage, both `fix-ci` stages | obra/superpowers |
| `code-review-and-quality` | Review (standard reviewer) | addyosmani/agent-skills |
| `differential-review` | Security review | trailofbits/skills |

Each stage gets only the skills for its own job. Loading every skill into
every stage costs tokens on each turn and makes the instructions contradict
each other.

## differential-review

Security-focused review of a code change: risk triage per file, git history
of removed code, test coverage, blast radius, attacker modelling. The
security reviewer of the `issue-to-pr` workflow follows it.

- Source: https://github.com/trailofbits/skills/tree/main/plugins/differential-review
- Copied from commit `149d7b21f4067765b82e67029730b42d228ef4b4` (plugin version 1.1.4), the folder
  `plugins/differential-review/skills/differential-review/`, unchanged.
- Author: Omar Inuwa, Trail of Bits.
- License: Creative Commons Attribution-ShareAlike 4.0 International,
  https://creativecommons.org/licenses/by-sa/4.0/. This applies to the
  `differential-review/` folder only. Changes to those files must be marked
  as changes and shared under the same license.

The skill mentions two things that are not installed here, the
`audit-context-building` skill and the `adversarial-modeler` agent. The
security reviewer's prompt in `workflows/issue-to-pr/workflow.fabro` tells it
to do that part by hand, and how to apply the skill to this pipeline.

## Skills from addyosmani/agent-skills

`spec-driven-development`, `planning-and-task-breakdown`,
`incremental-implementation` and `code-review-and-quality`.

- Source: https://github.com/addyosmani/agent-skills/tree/main/skills
- Copied from commit `e997ac5b9a74eab332d5e9793bb38a38c8cfdd74`, each folder
  under `skills/` unchanged, including its `references/`.
- Author: Addy Osmani. License: MIT; the upstream `LICENSE` file is in each
  folder.

These skills were written for an interactive session: they ask the user
questions, save specs and plans into the repository, and commit after each
step. None of that fits a run without a person in it, so the stage prompts in
`workflows/issue-to-pr/workflow.fabro` say which parts apply: the spec keeps
this pipeline's ten sections and goes to `/tmp/fabro/spec.md`, the task
breakdown goes into the spec's Code map, questions become assumptions, and
agents do not commit. The reviewer may try the skill's mutation check only in
a copy of the repository under `/tmp`.

## Skills from obra/superpowers

`test-driven-development` (with `writing-good-tests.md`) and
`verification-before-completion`.

- Source: https://github.com/obra/superpowers/tree/main/skills
- Copied from commit `22f0b463e7a5e579904dd6211a520321035526f7`, each folder
  under `skills/` unchanged.
- Author: Jesse Vincent. License: MIT; the upstream `LICENSE` file is in each
  folder.

The stage prompts limit the rule "delete code written before its test" to
code written in the same step, so a fix pass does not throw away the existing
implementation, and exempt changes without Python code when the spec says
`Tests required: no`.

## Not included

From the list these skills were chosen from, two are not here:

- `speckit-analyze` (github/spec-kit) is a command for spec-kit's own files
  (`spec.md`, `plan.md`, `tasks.md`, a constitution, extension hooks), not a
  skill that can be followed without them. The `Save spec` step already checks
  that a spec has the parts later steps rely on.
- `static-analysis` (trailofbits/skills) drives Semgrep and CodeQL. Neither is
  installed in the sandbox images, so the skill would have nothing to run.
  Adding it means adding the scanners to every image first.

## Updating a skill

Copy the folder again from a newer commit and change the commit above. Read
the diff first: these files are instructions to an agent that holds a GitHub
token. Then run `scripts/sync-pipeline` so every repository gets the same copy.
