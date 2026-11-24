# Fabro pipeline

This folder configures [Fabro](https://docs.fabro.sh) for this repository. It
is the same pipeline as in `0x0pointer/Construct`; see `.fabro/README.md`
there for the full description, the guardrails and the server setup.

| Workflow | What it does |
|---|---|
| `workflows/issue-to-pr/` | Builds an issue a maintainer labelled `fabro-approved`: spec, human approval of the spec, code, checks, independent review, draft pull request. |
| `workflows/fix-ci/` | Repairs a Fabro pull request whose CI checks failed, on the same branch. At most three rounds per pull request. |

Both are started by their Fabro automation (on a schedule, or with the Run
button in the web UI). A run picks the oldest approved issue, or the oldest
Fabro pull request with failed checks, and does nothing when there is none.

## What is specific to this repository

`workflow.fabro` is identical in every repository that uses the pipeline.
Everything repository-specific is in the two `workflow.toml` files (keep them
in step with each other) and in `docker/Dockerfile`:

- how to install, lint and test (`install_command`, `lint_command`, `test_command`);
- which paths a run may never change (`protected_prefixes`, `protected_files`);
- who may release an issue (`maintainers`).

`skills/` is a git submodule of `0x0pointer/skills`. Runs here may not change
it or its pointer; skill changes are made in the skills repository and arrive
through the bump-skills pull request.

## Sandbox image

Runs execute in a Docker image built on the machine that hosts Fabro:

```bash
docker build -f .fabro/docker/Dockerfile -t agent-smith-fabro:latest .
```

Rebuild it when the dependencies change.

No secrets belong in any file under `.fabro/`.
