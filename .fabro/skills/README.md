# Skills for the Fabro pipeline

Skills in the Agent Skills layout (one folder per skill with a `SKILL.md`).
A stage that uses one is told in its prompt to read the `SKILL.md` here.
Fabro 0.254.0 did not offer these to agents through its own `use_skill`
tool when we tried it, which is why the prompt names the file. Agents cannot
change this folder: the verify step rejects any change under `.fabro/`.

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

To update: copy the folder again from a newer commit and change the commit
above. Read the diff first; these files are instructions to a reviewer.
