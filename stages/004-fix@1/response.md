Fixed the reported CI failures on this branch.

- **CodeQL**
  - **Cause:** `control_plane.orchestrator` embedded user-supplied run options directly into the spawned worker’s command-line prompt, and `/api/runs` routes returned raw `RuntimeError` text to clients.
  - **Change:** wrote run start options to a per-run JSON file (`control_plane_start.json`) inside the run workdir and changed the worker prompt to reference that file instead of inlining target/scope data in argv. Also changed `core/api_server/routes/runs_routes.py` to mask runtime failures behind a generic `503 {"error": "service unavailable"}` response.
  - **Regression coverage:** added tests for the bootstrap-file flow and for masked runtime errors on create/mint-token/stop routes.

- **test**
  - **Cause:** the new container isolation test assumed the Docker executable string would always be exactly `"docker"`, but production intentionally resolves an absolute path such as `/usr/bin/docker` on some hosts/CI runners.
  - **Change:** made the test assert against `runner.docker_executable()` and explicitly simulate the absolute-path case.

Verification run after the final edit:
- `poetry run pytest tests/test_control_plane.py tests/test_runs_routes.py tests/test_container_isolation.py -q` → **37 passed**
- `poetry run pytest -q` → **2813 passed, 22 skipped**