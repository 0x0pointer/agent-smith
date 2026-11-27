Fixed the failed check.

- **SonarCloud Code Analysis / Quality Gate**
  - **Cause:** the PR accidentally included 110 generated runtime files under `runs/*/control_plane_start.json`. They are one-line JSON snapshots with repeated content, which drove `new_duplicated_lines_density` over the 3% threshold. The root cause was that the new per-run workdir path was added, but `runs/` was not added to `.gitignore`.
  - **Change:** added `runs/` to `.gitignore`, removed the tracked generated `runs/*/control_plane_start.json` files from the PR, and added a regression test in `tests/test_paths.py` that asserts `.gitignore` covers generated run workdirs.

Verification I ran after the fix:
- Regression test red/green:
  - `poetry run pytest tests/test_paths.py -q` → failed before the `.gitignore` fix
  - `poetry run pytest tests/test_paths.py -q` → passed with the fix
  - temporarily removed the ignore rule, reran `poetry run pytest tests/test_paths.py -q` → failed again
  - restored the ignore rule, reran `poetry run pytest tests/test_paths.py -q` → passed
- Full suite:
  - `poetry run pytest -q` → **2814 passed, 22 skipped**

I could not run SonarCloud itself in this sandbox, but the duplicated generated files that caused the quality gate failure have been removed and guarded against reintroduction.