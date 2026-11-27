Fixed the reported CI failure locally on this branch.

- **Failed check: SonarCloud Code Analysis**
  - **Cause:** the PR introduced several long multi-branch functions for run-scoped control-plane behavior, repeated string literals in triage routes, and a couple of test-code smells (`data=` for raw text, reversed assert operands). Those triggered the 11 Sonar issues and likely contributed to the duplication metric.
  - **What I changed:**
    - Split complex logic into small helpers in:
      - `core/api_server/__init__.py`
      - `core/api_server/routes/session_log_routes.py`
      - `core/api_server/routes/findings_routes.py`
      - `core/api_server/routes/triage_routes.py`
      - `core/findings.py`
      - `core/session/lifecycle.py`
      - `core/session/persistence.py`
    - Replaced duplicated triage literals with constants in `core/api_server/routes/triage_routes.py`.
    - Fixed Sonar test smells:
      - `tests/test_container_isolation.py`: swapped assert operands so actual comes first.
      - `tests/test_control_plane.py`: used `content=` instead of `data=` for raw JSON text.
    - Reduced repeated setup in `tests/test_control_plane.py` with small local helpers, which also helps the duplicated-lines signal.
  - **Verification:**
    - Targeted coverage of changed areas:
      - `poetry run pytest -q tests/test_control_plane.py tests/test_container_isolation.py tests/test_dashboard_auth.py tests/test_runs_routes.py tests/test_session_log_api.py tests/test_triage_postscan.py tests/test_session_new_helpers.py tests/test_session_reconcile.py tests/test_findings.py tests/test_api_server.py`
      - Result: **210 passed**
    - Full required suite:
      - `poetry run pytest -q`
      - Result: **2813 passed, 22 skipped**

I could not run SonarCloud itself in this sandbox, so I can’t claim the remote quality gate result directly, but the code changes address each reported Sonar issue and the full test suite passes after the final edit.