Implemented the fix-pass items only:

- Replaced `docs/plan-5.1-local-kb-retrieval.md` with a short obsolete/historical note so it no longer contains actionable KB/docs instructions.
- Restored executable mode on:
  - `installers/install.sh`
  - `installers/install_codex.sh`
  - `installers/install_opencode.sh`
- Tightened the legacy-KB negative recall test so it now fails if legacy KB file content or `kb:` source labels leak into recall output.
- Extended the installer regression test to assert the installer entry points remain executable.

Test coverage for each todo item:
- Obsolete docs instructions removed:
  - Covered indirectly by full suite; content fix was manual/document-only.
- Installer executable-bit regression:
  - `tests/test_installers_no_kb_bootstrap.py::test_installers_do_not_invoke_build_kb_or_accept_kb_flags`
- Weak legacy-KB negative test:
  - `tests/test_recall.py::test_recall_ignores_legacy_kb_dirs`

What I ran:
- `poetry run pytest -q tests/test_recall.py tests/test_installers_no_kb_bootstrap.py -q`
- `poetry run pytest -q`

Observed passing in this session:
- Targeted tests passed
- Full suite passed: `2724 passed, 22 skipped`

Noticed, not touched:
- Existing warning noise remains in the suite (FastAPI/starlette deprecations and a few runtime warnings), but no test failures.

STATUS: DONE